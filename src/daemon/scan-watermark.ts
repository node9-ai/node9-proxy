// src/daemon/scan-watermark.ts
//
// Forward-only watermark scanner for ~/.claude/projects/*.jsonl.
//
// Strategy: never read a JSONL line that existed before we started watching.
// The watermark is a per-file byte offset persisted in
// ~/.node9/scan-watermark.json. On the daemon's first ever run we walk the
// projects directory, record the current size of every file, and scan
// nothing. From that moment forward we scan only the bytes APPENDED to
// known files (one line at a time via streaming readline), or whole new
// files that didn't exist at watermark time.
//
// Privacy invariant — see ScanFinding type in @node9/policy-engine: each
// finding contains pattern names + counts + line indices, never raw text.
// The summary the daemon pushes up is one step further sanitised.

import fs from 'fs';
import os from 'os';
import path from 'path';
import readline from 'readline';
import { scanArgs } from '../dlp.js';
import {
  detectPii,
  extractCanonicalFindings,
  toScanFinding,
  LONG_OUTPUT_THRESHOLD_BYTES as ENGINE_LONG_OUTPUT_THRESHOLD_BYTES,
  CANONICAL_EXTRACTOR_VERSION,
  type ScanFinding,
  type ToolCallEntry,
  type ExtractContext,
} from '@node9/policy-engine';

const PROJECTS_DIR = () => path.join(os.homedir(), '.claude', 'projects');
const WATERMARK_FILE = () => path.join(os.homedir(), '.node9', 'scan-watermark.json');

/** Hard cap on a single JSONL line. Lines longer than this are truncated
 *  and skipped — pathological values from huge tool outputs shouldn't
 *  blow up the readline parser or memory.  */
const MAX_LINE_BYTES = 2 * 1024 * 1024; // 2MB

/**
 * Per-file state. `scannedTo` is the byte offset of the next byte we
 * haven't processed yet. On first sight of a file we either record
 * `scannedTo: 0` (new file) or `scannedTo: currentSize` (existed before
 * watermark — we treat the historical content as already-handled).
 */
interface WatermarkEntry {
  scannedTo: number;
}

/**
 * Bumped when the watermark file's SHAPE changes (new fields, layout
 * changes). Daemons reading a newer schema than they understand refuse
 * to write back so a downgrade can't corrupt the file.
 */
export const WATERMARK_SCHEMA_VERSION = 2;

export interface Watermark {
  schemaVersion: number;
  /**
   * Identity of the canonical detector pipeline that produced verdicts
   * against the byte offsets in `files`. When this falls behind the
   * engine's CANONICAL_EXTRACTOR_VERSION, the daemon resets all offsets
   * to 0 on next start so the new pipeline gets a fresh look at history.
   */
  extractorVersion: string;
  /**
   * One-shot flag, set when the daemon resets offsets in response to an
   * extractor upgrade. Tells the next /scan/report POST to use
   * sessionTotals (overwrite) instead of sessionDeltas (increment),
   * avoiding double-counting on top of any prior `node9 scan
   * --upload-history` baseline. Cleared after the first successful POST.
   */
  pendingResetUploadAs?: 'totals';
  createdAt: string;
  files: Record<string, WatermarkEntry>;
}

/**
 * Result of `loadWatermark`. The state discriminator drives migration:
 *
 *   fresh             — file missing or unparseable. Seed a new one.
 *   current           — schema + extractor versions match. Run as today.
 *   extractor-stale   — schema OK but extractor version drifted. Reset
 *                       all per-file scannedTo to 0, set
 *                       pendingResetUploadAs:'totals', persist new
 *                       extractorVersion. Preserves createdAt so we
 *                       don't backfill pre-install history.
 *   schema-future     — file was written by a newer daemon. Don't touch.
 *                       Don't write back. Skip the tick.
 */
export type WatermarkState =
  | { status: 'fresh'; wm: Watermark }
  | { status: 'current'; wm: Watermark }
  | { status: 'extractor-stale'; wm: Watermark }
  | { status: 'schema-future'; wm: Watermark };

/**
 * Build a default-state watermark (no files known yet). createdAt
 * is set to now; the daemon's first tick will record current file
 * sizes for files that already exist (forward-only — no historical
 * backfill on fresh installs).
 */
function freshWatermark(): Watermark {
  return {
    schemaVersion: WATERMARK_SCHEMA_VERSION,
    extractorVersion: CANONICAL_EXTRACTOR_VERSION,
    createdAt: new Date().toISOString(),
    files: {},
  };
}

/**
 * Read the watermark and classify it. Resets offsets in-memory for the
 * `extractor-stale` branch but does NOT save here — the caller owns the
 * write. Splitting load/save keeps the schema-future refusal honest:
 * we never persist anything for that case.
 */
export function loadWatermark(): WatermarkState {
  let raw: string;
  try {
    raw = fs.readFileSync(WATERMARK_FILE(), 'utf-8');
  } catch {
    return { status: 'fresh', wm: freshWatermark() };
  }

  let parsed: Partial<Watermark>;
  try {
    parsed = JSON.parse(raw) as Partial<Watermark>;
  } catch {
    return { status: 'fresh', wm: freshWatermark() };
  }

  if (typeof parsed.createdAt !== 'string' || !parsed.files || typeof parsed.files !== 'object') {
    return { status: 'fresh', wm: freshWatermark() };
  }

  const fileSchemaVersion = typeof parsed.schemaVersion === 'number' ? parsed.schemaVersion : 1;
  if (fileSchemaVersion > WATERMARK_SCHEMA_VERSION) {
    // Newer daemon wrote this file; current daemon doesn't understand
    // its shape. Refuse to alter it.
    const wm: Watermark = {
      schemaVersion: fileSchemaVersion,
      extractorVersion:
        typeof parsed.extractorVersion === 'string'
          ? parsed.extractorVersion
          : CANONICAL_EXTRACTOR_VERSION,
      createdAt: parsed.createdAt,
      files: parsed.files as Record<string, WatermarkEntry>,
    };
    return { status: 'schema-future', wm };
  }

  const fileExtractorVersion =
    typeof parsed.extractorVersion === 'string' ? parsed.extractorVersion : '';
  if (fileExtractorVersion !== CANONICAL_EXTRACTOR_VERSION) {
    // Detector pipeline changed since this file was written. Reset
    // every file's offset so the new pipeline re-scans history;
    // preserve createdAt so files older than the original install
    // still skip backfill (we don't want to silently turn an upgrade
    // into a months-deep historical re-scan beyond what was already
    // tracked). Mark the next POST as overwrite-class so it doesn't
    // double-count on top of any prior --upload-history.
    const filesIn = parsed.files as Record<string, WatermarkEntry>;
    const filesOut: Record<string, WatermarkEntry> = {};
    for (const [k, v] of Object.entries(filesIn)) {
      filesOut[k] = { scannedTo: 0 };
      void v; // discard old offset
    }
    const wm: Watermark = {
      schemaVersion: WATERMARK_SCHEMA_VERSION,
      extractorVersion: CANONICAL_EXTRACTOR_VERSION,
      pendingResetUploadAs: 'totals',
      createdAt: parsed.createdAt,
      files: filesOut,
    };
    return { status: 'extractor-stale', wm };
  }

  // Schema OK + extractor matches → current. Pass through, including
  // a possibly-set pendingResetUploadAs from a crash between reset and
  // first successful POST (we want to honor the flag still).
  const wm: Watermark = {
    schemaVersion: WATERMARK_SCHEMA_VERSION,
    extractorVersion: CANONICAL_EXTRACTOR_VERSION,
    ...(parsed.pendingResetUploadAs === 'totals' && { pendingResetUploadAs: 'totals' }),
    createdAt: parsed.createdAt,
    files: parsed.files as Record<string, WatermarkEntry>,
  };
  return { status: 'current', wm };
}

/**
 * Atomic save: write to a sibling tempfile, then rename. Rename is
 * atomic on POSIX within the same dir, which prevents a half-written
 * watermark from corrupting the daemon's view of "what's been scanned".
 *
 * Refuses to write if the on-disk file is from a newer schema (daemon
 * downgrade scenario). Caller's loadWatermark would have returned
 * `schema-future` in that case; this is a defensive double-check.
 */
export function saveWatermark(wm: Watermark): void {
  if (wm.schemaVersion > WATERMARK_SCHEMA_VERSION) return;
  const target = WATERMARK_FILE();
  const dir = path.dirname(target);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = target + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(wm, null, 2) + '\n', 'utf-8');
  fs.renameSync(tmp, target);
}

/**
 * Walk ~/.claude/projects/ and return all JSONL paths. Returns [] if the
 * directory doesn't exist (Gemini-only / no Claude Code user — fine,
 * just nothing to scan).
 */
function listJsonlFiles(): string[] {
  const root = PROJECTS_DIR();
  if (!fs.existsSync(root)) return [];
  const out: string[] = [];
  // Claude Code's structure is ~/.claude/projects/<projectHash>/<jsonl-files>.
  // We walk one level deep — that's the documented layout, and recursing
  // wider risks pulling in unrelated files.
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const projectDir = path.join(root, entry.name);
    let inner: fs.Dirent[];
    try {
      inner = fs.readdirSync(projectDir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const file of inner) {
      if (file.isFile() && file.name.endsWith('.jsonl')) {
        out.push(path.join(projectDir, file.name));
      }
    }
  }
  return out;
}

/** Safe filesize lookup. Returns 0 if the file vanished between listing and stat. */
function fileSize(p: string): number {
  try {
    return fs.statSync(p).size;
  } catch {
    return 0;
  }
}

/**
 * Stream-read bytes [fromByte, currentSize) from `filePath`, parsing each
 * JSONL line. Calls `onLine` for each parseable JSON object. Lines longer
 * than MAX_LINE_BYTES are skipped.
 *
 * Returns the new `scannedTo` value (always equals the file size at the
 * moment we finished). If we crashed mid-read, the caller can re-run and
 * pick up from the previous `scannedTo` — there's no destructive update.
 */
export async function scanDelta(
  filePath: string,
  fromByte: number,
  onLine: (lineObj: unknown, lineIndex: number) => void
): Promise<number> {
  const size = fileSize(filePath);
  if (size <= fromByte) return fromByte;

  const stream = fs.createReadStream(filePath, {
    start: fromByte,
    end: size - 1,
    highWaterMark: 64 * 1024,
  });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  let lineIndex = 0;
  for await (const raw of rl) {
    lineIndex++;
    if (raw.length > MAX_LINE_BYTES) continue;
    if (raw.length === 0) continue;
    try {
      const obj: unknown = JSON.parse(raw);
      onLine(obj, lineIndex);
    } catch {
      // Skip unparseable lines — could be partial writes mid-flush.
      // The next tick will re-attempt from `size` so we don't lose them.
    }
  }
  return size;
}

/**
 * Run the existing DLP scanner over a Claude Code JSONL line. The line
 * shape varies (user message, assistant response, tool call, tool result)
 * but each carries content somewhere. We scan known content fields.
 *
 * Producing finding *objects* with pattern names is the whole point — we
 * never propagate the raw matched text past this function. The host
 * (caller) accumulates findings; the engine summarises them.
 */
// Exported so the backfill path (scan-upload-history.ts) can re-use the
// exact same per-line extraction logic. Live ticks call this internally;
// backfill calls it directly across all bytes of the file.
export function extractFindingsFromLine(
  line: unknown,
  sessionId: string,
  lineIndex: number
): ScanFinding[] {
  if (!line || typeof line !== 'object') return [];
  const findings: ScanFinding[] = [];

  // Walk known content shapes. Claude Code messages have either
  // `message.content` (user/assistant) or `toolUseResult` (tool result).
  const obj = line as Record<string, unknown>;
  const candidates: unknown[] = [];

  if (obj.message && typeof obj.message === 'object') {
    const msg = obj.message as Record<string, unknown>;
    if (typeof msg.content === 'string') candidates.push(msg.content);
    else if (Array.isArray(msg.content)) candidates.push(msg.content);
  }
  if (typeof obj.toolUseResult === 'string') candidates.push(obj.toolUseResult);
  if (obj.input && typeof obj.input === 'object') candidates.push(obj.input);

  for (const candidate of candidates) {
    // scanArgs walks an object's values for credential patterns. A
    // top-level string isn't its happy path, so wrap it under a synthetic
    // key. The same pattern detection runs either way; the wrapper only
    // gives the scanner a value to walk.
    const wrapped = typeof candidate === 'string' ? { content: candidate } : candidate;
    const hit = scanArgs(wrapped);
    if (hit) {
      findings.push({
        type: 'dlp',
        patternName: hit.patternName,
        sessionId,
        lineIndex,
      });
    }

    // ── PII patterns ────────────────────────────────────────────────
    // Run on string-shaped candidates only. Skip if the candidate is
    // already a tool input/result object — those go through scanArgs
    // above. PII regexes are tight enough to keep FP rate low (each
    // requires structural delimiters: @ for email, dashes for SSN, etc.).
    if (typeof candidate === 'string' && candidate.length > 0) {
      const piiHits = detectPii(candidate);
      for (const patternName of piiHits) {
        findings.push({
          type: 'pii',
          patternName,
          sessionId,
          lineIndex,
        });
      }
    }
  }

  // ── Per-tool-call detection — delegate to the canonical extractor ──
  // Assistant messages on Claude Code carry an array of content blocks;
  // tool invocations are { type: 'tool_use', name: 'Bash', input: { command } }.
  // For each tool_use we build a ToolCallEntry and feed it to the engine's
  // canonical extractor — same detection pipeline the CLI scan uses, so
  // hook + scan + watermark all agree on identical input.
  //
  // tool_result blocks aren't tool calls but they carry the size signal
  // for long-output-redacted; we encode that as outputBytes on a synthetic
  // ToolCallEntry whose name attribution is still useful.
  const ctx: ExtractContext = {
    sessionId,
    lineIndex,
    project: '',
    agent: 'claude',
    rules: [],
    toolInspection: { bash: 'command', execute_bash: 'command' },
    dlpEnabled: false, // line-level DLP runs above already
  };
  const message = (line as Record<string, unknown>).message;
  if (message && typeof message === 'object') {
    const content = (message as Record<string, unknown>).content;
    if (Array.isArray(content)) {
      for (const block of content) {
        if (!block || typeof block !== 'object') continue;
        const b = block as Record<string, unknown>;

        if (b.type === 'tool_result') {
          const c = b.content;
          const len =
            typeof c === 'string' ? c.length : Array.isArray(c) ? JSON.stringify(c).length : 0;
          if (len > LONG_OUTPUT_THRESHOLD_BYTES) {
            findings.push({
              type: 'long-output-redacted',
              sessionId,
              lineIndex,
            });
          }
          continue;
        }

        if (b.type !== 'tool_use') continue;
        const toolName = typeof b.name === 'string' ? b.name : '';
        const input = (b.input as Record<string, unknown>) ?? {};
        const call: ToolCallEntry = {
          toolName,
          args: input,
          timestamp: typeof obj.timestamp === 'string' ? (obj.timestamp as string) : '',
        };
        const canonical = extractCanonicalFindings(call, ctx);
        for (const cf of canonical) {
          const sf = toScanFinding(cf);
          if (sf) findings.push(sf);
        }
      }
    }
  }
  return findings;
}

// LONG_OUTPUT_THRESHOLD_BYTES, DESTRUCTIVE_OP_RE, PRIVILEGE_ESCALATION_RE,
// SENSITIVE_PATH_RE, FILE_TOOLS, detectPii — all live in @node9/policy-engine
// now. The daemon imports the canonical extractor and a few raw helpers
// for the line-level DLP/PII walk over non-tool-call content.
const LONG_OUTPUT_THRESHOLD_BYTES = ENGINE_LONG_OUTPUT_THRESHOLD_BYTES;

// detectPii + PII regexes now live in @node9/policy-engine (scan/pii.ts)
// so the canonical extractor and the daemon's line-level walk share one
// source of truth.

/**
 * Read-only forensic scan for live SSE broadcast.
 *
 * Independent of the persistent watermark used by the SaaS-sync path:
 * `offsets` is an in-memory Map maintained by the caller, reset on
 * daemon restart. On first sight of a file, the offset is initialized
 * to its current EOF — historical content does not flood the live
 * channel (the dashboard's mount-time scan covers that). On subsequent
 * ticks, only newly-appended lines are extracted.
 *
 * The persistent watermark file (`~/.node9/scan-watermark.json`) is
 * NOT touched. The hourly SaaS sync calls `tickScanWatcher` which
 * advances the persistent watermark and POSTs findings independently.
 */
export async function tickForensicBroadcast(offsets: Map<string, number>): Promise<ScanFinding[]> {
  const out: ScanFinding[] = [];
  const files = listJsonlFiles();
  for (const file of files) {
    const size = fileSize(file);
    const offset = offsets.get(file);
    if (offset === undefined) {
      // First time we see this file — start at EOF so historical lines
      // don't flood the local broadcast.
      offsets.set(file, size);
      continue;
    }
    if (size <= offset) continue;

    const sessionId = path.basename(file, '.jsonl');
    const newOffset = await scanDelta(file, offset, (obj, lineIndex) => {
      out.push(...extractFindingsFromLine(obj, sessionId, lineIndex));
    });
    offsets.set(file, newOffset);
  }
  return out;
}

/**
 * Result of one tick — what was scanned and what was found. Caller pushes
 * the findings through `summarizeScan` and ships the summary to the SaaS.
 */
export interface ScanTickResult {
  findings: ScanFinding[];
  totalToolCalls: number;
  /** Per-session tool-call counts in this delta. Lets the BE attribute
   *  "47 calls in this session" on the Sessions tab without reparsing. */
  toolCallsBySession: Record<string, number>;
  filesScanned: number;
  filesNew: number;
  filesSkipped: number;
  /**
   * How the per-session payload should be written on the SaaS BE.
   *   'deltas' (default) — sessionDeltas, atomic increments, normal flow.
   *   'totals'           — sessionTotals, full overwrite. Set on the first
   *                        tick after an extractor-stale reset so
   *                        re-scanned bytes don't double-count on top of a
   *                        prior `--upload-history` baseline.
   * Caller (sync.ts) reads this to choose the wire field, then calls
   * `markUploadComplete()` on success to clear the flag for the next tick.
   */
  uploadAs: 'deltas' | 'totals';
  /**
   * True when this tick ran with no work because the watermark file is
   * from a newer daemon schema (downgrade safety). sync.ts should skip
   * the network round-trip in that case.
   */
  schemaFuture: boolean;
}

/**
 * Clear the `pendingResetUploadAs` flag from the persisted watermark.
 * Called by sync.ts after the first post-reset POST succeeds. Subsequent
 * ticks then revert to the normal incremental sessionDeltas path.
 */
export function markUploadComplete(): void {
  const state = loadWatermark();
  // schema-future: never write back, current daemon doesn't understand
  // the file's shape.
  if (state.status === 'schema-future') return;
  // extractor-stale: the on-disk file was concurrently rewound to a
  // different extractorVersion between our tick and this call. Saving
  // here would persist the in-memory `extractor-stale` state which
  // resets all scannedTo to 0 — clobbering whatever scan progress the
  // tick just recorded. Bail; the next tick handles the new stale
  // state cleanly.
  if (state.status === 'extractor-stale') return;
  if (!state.wm.pendingResetUploadAs) return;
  delete state.wm.pendingResetUploadAs;
  saveWatermark(state.wm);
}

/**
 * One tick of the watermark scanner. Idempotent: if nothing has changed
 * since the previous tick, returns zero findings, zero scanned files.
 *
 * Algorithm:
 *   1. Load watermark.
 *   2. Walk projects dir.
 *   3. For each JSONL file:
 *        - If unknown to watermark AND watermark has a recorded createdAt
 *          before file's mtime → new file, scan from byte 0.
 *        - If unknown AND file existed at watermark creation → record
 *          scannedTo = currentSize, scan nothing (forward-only).
 *        - If known and currentSize > scannedTo → scan delta.
 *        - If known and currentSize == scannedTo → skip.
 *   4. Save watermark with updated scannedTo values.
 *
 * Opt-out: NODE9_SCAN_DISABLE=1 short-circuits to an empty result.
 */
export async function tickScanWatcher(): Promise<ScanTickResult> {
  if (process.env.NODE9_SCAN_DISABLE === '1') {
    return emptyTick('deltas');
  }

  const state = loadWatermark();

  if (state.status === 'schema-future') {
    // A newer daemon wrote this watermark file; we don't understand its
    // shape. Skip the tick entirely and don't touch the file. sync.ts
    // sees `schemaFuture: true` and skips the network round-trip too.
    if (process.env.NODE9_DEBUG === '1') {
      process.stderr.write('[node9] watermark schema is from a newer daemon — skipping tick.\n');
    }
    return { ...emptyTick('deltas'), schemaFuture: true };
  }

  if (state.status === 'extractor-stale') {
    // One-shot escape hatch. A user who just ran `node9 scan
    // --upload-history` and is upgrading can set this env var to
    // acknowledge the version drift and skip the re-scan; their stale
    // verdicts in the SaaS will not be refreshed by the daemon, but
    // their next --upload-history run can refresh them. The flag
    // doesn't suppress; it ACKNOWLEDGES — we write the new
    // extractorVersion to the watermark and KEEP existing offsets so
    // subsequent daemon starts run as 'current'.
    if (process.env.NODE9_SKIP_WATERMARK_RESET === '1') {
      // Re-load the on-disk file (pre-reset) so we keep the original
      // scannedTo offsets; then stamp the new extractorVersion.
      const acknowledged = readRawWatermarkPreservingOffsets();
      if (acknowledged) {
        saveWatermark(acknowledged);
      }
      process.stderr.write(
        '[node9] Extractor upgrade acknowledged via NODE9_SKIP_WATERMARK_RESET.\n' +
          '       Existing verdicts not refreshed — run `node9 scan --upload-history`\n' +
          '       to backfill them through the new pipeline.\n'
      );
      // Re-load again now in 'current' state for the actual tick.
      return runActualTick(loadWatermark().wm);
    }
    process.stderr.write(
      '[node9] Detector upgrade detected — re-scanning history through the new\n' +
        '        pipeline. Expect a one-time SaaS payload spike on this tick.\n' +
        '        Set NODE9_SKIP_WATERMARK_RESET=1 to skip.\n'
    );
  }

  return runActualTick(state.wm);
}

function emptyTick(uploadAs: 'deltas' | 'totals'): ScanTickResult {
  return {
    findings: [],
    totalToolCalls: 0,
    toolCallsBySession: {},
    filesScanned: 0,
    filesNew: 0,
    filesSkipped: 0,
    uploadAs,
    schemaFuture: false,
  };
}

/**
 * Re-read the on-disk watermark and produce a Watermark with offsets
 * preserved but extractorVersion stamped to the current value. Used by
 * the NODE9_SKIP_WATERMARK_RESET path to acknowledge an upgrade without
 * triggering a re-scan. Returns null if the file is missing or
 * unparseable (in which case there's nothing meaningful to "preserve").
 */
function readRawWatermarkPreservingOffsets(): Watermark | null {
  let raw: string;
  try {
    raw = fs.readFileSync(WATERMARK_FILE(), 'utf-8');
  } catch {
    return null;
  }
  let parsed: Partial<Watermark>;
  try {
    parsed = JSON.parse(raw) as Partial<Watermark>;
  } catch {
    return null;
  }
  if (typeof parsed.createdAt !== 'string' || !parsed.files || typeof parsed.files !== 'object') {
    return null;
  }
  return {
    schemaVersion: WATERMARK_SCHEMA_VERSION,
    extractorVersion: CANONICAL_EXTRACTOR_VERSION,
    createdAt: parsed.createdAt,
    files: parsed.files as Record<string, WatermarkEntry>,
  };
}

async function runActualTick(wm: Watermark): Promise<ScanTickResult> {
  const watermarkCreatedAt = new Date(wm.createdAt).getTime();
  const findings: ScanFinding[] = [];
  let totalToolCalls = 0;
  const toolCallsBySession: Record<string, number> = {};
  let filesScanned = 0;
  let filesNew = 0;
  let filesSkipped = 0;

  for (const filePath of listJsonlFiles()) {
    const size = fileSize(filePath);
    const known = wm.files[filePath];

    if (!known) {
      // Decide: is this a brand-new file (created after watermark) or
      // a file that existed at watermark time? mtime is the signal.
      let mtimeMs = 0;
      try {
        mtimeMs = fs.statSync(filePath).mtime.getTime();
      } catch {
        continue;
      }
      if (mtimeMs >= watermarkCreatedAt) {
        // New file — scan from byte 0.
        filesNew++;
        const sessionId = path.basename(filePath, '.jsonl');
        const newScannedTo = await scanDelta(filePath, 0, (obj, lineIndex) => {
          totalToolCalls++;
          toolCallsBySession[sessionId] = (toolCallsBySession[sessionId] ?? 0) + 1;
          findings.push(...extractFindingsFromLine(obj, sessionId, lineIndex));
        });
        wm.files[filePath] = { scannedTo: newScannedTo };
        filesScanned++;
      } else {
        // Pre-existing file. Record current size as the floor — never scan
        // historical content. Future appends will be picked up on next tick.
        wm.files[filePath] = { scannedTo: size };
        filesSkipped++;
      }
      continue;
    }

    if (size <= known.scannedTo) {
      filesSkipped++;
      continue;
    }

    // Known file with new bytes → scan delta only.
    const sessionId = path.basename(filePath, '.jsonl');
    const newScannedTo = await scanDelta(filePath, known.scannedTo, (obj, lineIndex) => {
      totalToolCalls++;
      toolCallsBySession[sessionId] = (toolCallsBySession[sessionId] ?? 0) + 1;
      findings.push(...extractFindingsFromLine(obj, sessionId, lineIndex));
    });
    wm.files[filePath] = { scannedTo: newScannedTo };
    filesScanned++;
  }

  const uploadAs: 'deltas' | 'totals' = wm.pendingResetUploadAs === 'totals' ? 'totals' : 'deltas';
  saveWatermark(wm);

  return {
    findings,
    totalToolCalls,
    toolCallsBySession,
    filesScanned,
    filesNew,
    filesSkipped,
    uploadAs,
    schemaFuture: false,
  };
}
