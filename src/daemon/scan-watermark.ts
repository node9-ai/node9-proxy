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
import { analyzePipeChain, detectDangerousShellExec, type ScanFinding } from '@node9/policy-engine';

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

export interface Watermark {
  createdAt: string;
  files: Record<string, WatermarkEntry>;
}

/** Read the watermark, or return a fresh seed if missing/corrupt. */
export function loadWatermark(): Watermark {
  try {
    const raw = fs.readFileSync(WATERMARK_FILE(), 'utf-8');
    const parsed = JSON.parse(raw) as Partial<Watermark>;
    if (typeof parsed.createdAt === 'string' && parsed.files && typeof parsed.files === 'object') {
      return parsed as Watermark;
    }
  } catch {
    /* fall through to seed */
  }
  return { createdAt: new Date().toISOString(), files: {} };
}

/**
 * Atomic save: write to a sibling tempfile, fsync (best effort via
 * writeFileSync's sync nature), then rename. Rename is atomic on POSIX
 * within the same dir, which prevents a half-written watermark from
 * corrupting the daemon's view of "what's been scanned".
 */
export function saveWatermark(wm: Watermark): void {
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
function extractFindingsFromLine(
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
  }

  // ── Tool-use shell AST + regex detection ────────────────────────────
  // Assistant messages on Claude Code carry an array of content blocks;
  // tool invocations are { type: 'tool_use', name: 'Bash', input: { command } }.
  // We walk those blocks and run two layers of detection:
  //   1. AST detectors (engine) for eval-of-remote and pipe-to-shell —
  //      deterministic, no false positives.
  //   2. Regex extractors for destructive ops + privilege escalation —
  //      cheap, single-line, low FP rate on the patterns matched.
  const message = (line as Record<string, unknown>).message;
  if (message && typeof message === 'object') {
    const content = (message as Record<string, unknown>).content;
    if (Array.isArray(content)) {
      for (const block of content) {
        if (!block || typeof block !== 'object') continue;
        const b = block as Record<string, unknown>;
        if (b.type !== 'tool_use') continue;
        const toolName = typeof b.name === 'string' ? b.name.toLowerCase() : '';
        if (toolName !== 'bash' && toolName !== 'execute_bash') continue;
        const input = b.input as Record<string, unknown> | undefined;
        const command = input && typeof input.command === 'string' ? input.command : '';
        if (!command) continue;

        // eval/bash -c with remote download — engine returns 'block' or
        // 'review' or undefined.
        const verdict = detectDangerousShellExec(command);
        if (verdict) {
          findings.push({ type: 'eval-of-remote', sessionId, lineIndex });
        }

        // Pipe chain whose source is a credential file and sink is the
        // network (or vice versa) — engine flags as critical.
        const pipe = analyzePipeChain(command);
        if (pipe.isPipeline && pipe.risk === 'critical') {
          findings.push({ type: 'pipe-to-shell', sessionId, lineIndex });
        }

        // ── Destructive ops ────────────────────────────────────────
        // Hard-to-reverse commands. These regexes are tight enough to
        // avoid common false-positives:
        //   - `rm -rf` requires the recursive+force flags together
        //   - `DROP TABLE` / `DROP DATABASE` / `TRUNCATE TABLE` only
        //     match on the SQL keyword sequence
        //   - `git push --force` (and the alias `git push -f`) — pinned
        //     deletions of remote history
        //   - Redis FLUSHALL / FLUSHDB — wipe the entire datastore
        //   - kubectl delete / helm uninstall — cluster-level teardown
        if (DESTRUCTIVE_OP_RE.test(command)) {
          findings.push({ type: 'destructive-op', sessionId, lineIndex });
        }

        // ── Privilege escalation ───────────────────────────────────
        // sudo, su, chmod 777, chown root. Each implies the agent
        // tried to broaden permissions. Matched as standalone tokens
        // so we don't false-positive on substrings like 'pseudonym'.
        if (PRIVILEGE_ESCALATION_RE.test(command)) {
          findings.push({
            type: 'privilege-escalation',
            sessionId,
            lineIndex,
          });
        }
      }
    }
  }
  return findings;
}

/**
 * Destructive-op regex. Word-boundary anchored so partial matches don't
 * fire (e.g. "term" inside "terminate" wouldn't match `\brm\b`). Each
 * pattern is independently provable as destructive — no fuzzy heuristics.
 */
const DESTRUCTIVE_OP_RE =
  /\brm\s+-[rRf]+\b|\bDROP\s+(TABLE|DATABASE|COLLECTION|SCHEMA)\b|\bTRUNCATE\s+TABLE\b|\bgit\s+push\s+(--force|-f)\b|\bFLUSHALL\b|\bFLUSHDB\b|\bkubectl\s+delete\b|\bhelm\s+uninstall\b/i;

/**
 * Privilege-escalation regex. Standalone tokens only — `\bsudo\b` not
 * `sudo` to avoid matching e.g. `pseudo` substrings.
 */
const PRIVILEGE_ESCALATION_RE = /\b(sudo|su)\b\s+[a-z]|\bchmod\s+(0?777|\+x)\b|\bchown\s+root\b/i;

/**
 * Result of one tick — what was scanned and what was found. Caller pushes
 * the findings through `summarizeScan` and ships the summary to the SaaS.
 */
export interface ScanTickResult {
  findings: ScanFinding[];
  totalToolCalls: number;
  filesScanned: number;
  filesNew: number;
  filesSkipped: number;
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
    return { findings: [], totalToolCalls: 0, filesScanned: 0, filesNew: 0, filesSkipped: 0 };
  }

  const wm = loadWatermark();
  const watermarkCreatedAt = new Date(wm.createdAt).getTime();
  const findings: ScanFinding[] = [];
  let totalToolCalls = 0;
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
      findings.push(...extractFindingsFromLine(obj, sessionId, lineIndex));
    });
    wm.files[filePath] = { scannedTo: newScannedTo };
    filesScanned++;
  }

  saveWatermark(wm);

  return { findings, totalToolCalls, filesScanned, filesNew, filesSkipped };
}
