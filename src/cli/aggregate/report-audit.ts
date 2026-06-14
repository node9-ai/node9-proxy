// src/cli/aggregate/report-audit.ts
//
// Period-aware aggregation of ~/.node9/audit.log into the BuildReportJsonInput
// shape. Shared between:
//   - `node9 report` CLI command (cli/commands/report.ts) — terminal renderer
//   - `node9 monitor` Report [2] view (tui/dashboard/views/report/) — Ink panels
//
// Pure-ish: reads audit.log + Claude/Codex journals via fs (sync), no network,
// no daemon. Inject `now` and `auditLogPath` for test isolation.
//
// The aggregator returns BuildReportJsonInput ready to pass to either:
//   - buildReportJson()  (cli/render/report-json.ts) for `--json` output
//   - the terminal renderer in cli/commands/report.ts
//   - dashboard panel components consuming the same shape
//
// History: lifted out of cli/commands/report.ts's monolithic action handler
// to share the aggregation step across CLI + TUI without duplicating logic.

import fs from 'fs';
import os from 'os';
import path from 'path';

import { decodeProjectDirName } from '../../costSync';
import { pricingFor, normalizeModel } from '../../pricing/litellm';
import { codexPriceFor } from '../../cost-codex';
import type { BuildReportJsonInput, ReportPeriod } from '../render/report-json';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditEntry {
  ts: string;
  tool: string;
  args?: Record<string, unknown>;
  decision: string;
  checkedBy?: string;
  /** Specific smart-rule name (e.g. `shield:project-jail:block-read-ssh`)
   *  for entries written by the orchestrator's smart-rule paths.
   *  `checkedBy` stays as the generic tag (`smart-rule-block` /
   *  `smart-rule-block-override`); `ruleName` is the precise rule
   *  that fired, used by the [2] Report SHIELDS panel to attribute
   *  fires to their owning shield via the rule→shield map. */
  ruleName?: string;
  agent?: string;
  mcpServer?: string;
  source?: string;
  testRun?: boolean;
  testResult?: 'pass' | 'fail';
  /** Stable hash of the tool args — used to pair an intermediate
   *  `smart-rule-block-override` deny row with the daemon's eventual
   *  decision row by argsHash + sessionId. Present on rows written by
   *  the smart-rule and daemon-decision paths (both ends of the pair);
   *  consumers must treat it as optional for forward-compat with
   *  older entries that pre-date the field. */
  argsHash?: string;
  /** Agent session id — scoped pairing key alongside argsHash so two
   *  unrelated sessions running the same exact command don't collide. */
  sessionId?: string;
}

interface JournalEntry {
  type: string;
  timestamp?: string;
  message?: {
    model?: string;
    usage?: {
      input_tokens?: number;
      output_tokens?: number;
      cache_creation_input_tokens?: number;
      cache_read_input_tokens?: number;
    };
  };
}

export interface AggregateOpts {
  /** Inject for tests. Defaults to new Date(). */
  now?: Date;
  /** Inject for tests. Defaults to ~/.node9/audit.log */
  auditLogPath?: string;
  /** Inject for tests. Defaults to ~/.claude/projects */
  claudeProjectsDir?: string;
  /** Inject for tests. Defaults to ~/.codex/sessions */
  codexSessionsDir?: string;
  /** Inject for tests. Defaults to ~/.gemini/tmp */
  geminiTmpDir?: string;
  /** When true, exclude test-runner calls (mirrors --no-tests CLI flag). */
  excludeTests?: boolean;
  /**
   * When provided, skip the synchronous audit-log read and use these entries
   * instead. Lets the dashboard pre-load the audit log via an event-loop-
   * yielding chunked parser (readAuditEntriesAsync) so view switches don't
   * freeze on large logs. The CLI path leaves this undefined and the function
   * falls back to the original sync parseAuditLog.
   */
  preloadedAuditEntries?: AuditEntry[];
  /**
   * When provided, skip the synchronous Claude / Codex JSONL cost walks.
   * The dashboard pre-loads both via async chunked walkers so the [2] view
   * switch doesn't freeze for the full ~250 ms cost-walk duration. The CLI
   * leaves both undefined and the function falls back to the original sync
   * loadClaudeCost / loadCodexCost.
   */
  preloadedClaudeCost?: ClaudeCostData;
  preloadedCodexCost?: CodexCostData;
  preloadedGeminiCost?: GeminiCostData;
}

export interface AggregateResult {
  /** Aggregated state ready for JSON envelope or panel rendering. */
  data: BuildReportJsonInput;
  /**
   * True iff ~/.node9/audit.log exists. The CLI uses this to pick between
   * "no audit data found" (file missing) and "no activity for period"
   * (file present but window empty) warnings. The dashboard ignores it
   * and just renders zeroes.
   */
  hasAuditFile: boolean;
  /**
   * Period-filtered response-dlp entries. The lifetime count is on
   * data.unackedDlp (drives the top-banner warning); this list is what
   * the CLI renderer iterates for the inline Response-DLP section
   * (showing dlpPattern + dlpSample per entry). Dashboard ignores.
   */
  responseDlpEntries: ResponseDlpEntry[];
}

export interface ResponseDlpEntry {
  ts: string;
  dlpPattern?: string;
  dlpSample?: string;
}

// ---------------------------------------------------------------------------
// Test-command detection — shared between buildTestTimestamps and isTestEntry
// ---------------------------------------------------------------------------

const TEST_COMMAND_RE =
  /(?:^|\s)(npm\s+(?:run\s+)?test|npx\s+(?:vitest|jest|mocha)|yarn\s+(?:run\s+)?test|pnpm\s+(?:run\s+)?test|vitest|jest|mocha|pytest|py\.test|cargo\s+test|go\s+test|bundle\s+exec\s+rspec|rspec|phpunit|dotnet\s+test)\b/i;

/** Build a set of timestamps (ms) for Bash test commands from PostToolUse entries.
 * PreToolUse entries store argsHash (not plaintext args) by default, so we
 * identify test commands from the PostToolUse counterpart which always stores
 * full args, then match by time proximity. */
function buildTestTimestamps(allEntries: AuditEntry[]): Set<number> {
  const testTs = new Set<number>();
  for (const e of allEntries) {
    if (e.source !== 'post-hook') continue;
    if (e.tool !== 'Bash' && e.tool !== 'bash') continue;
    const cmd = e.args?.command;
    if (typeof cmd === 'string' && TEST_COMMAND_RE.test(cmd)) {
      testTs.add(new Date(e.ts).getTime());
    }
  }
  return testTs;
}

/** Returns true if this PreToolUse entry is from a test run. */
function isTestEntry(entry: AuditEntry, testTs: Set<number>): boolean {
  // Tagged at write time — applies to any tool type
  if (entry.testRun === true) return true;
  // Remaining fallbacks only apply to Bash
  if (entry.tool !== 'Bash' && entry.tool !== 'bash') return false;
  // Plain args available (auditHashArgs disabled) — exact match
  const cmd = entry.args?.command;
  if (typeof cmd === 'string') return TEST_COMMAND_RE.test(cmd);
  // Fall back: match by PostToolUse timestamp proximity
  const t = new Date(entry.ts).getTime();
  for (const ts of testTs) {
    if (Math.abs(ts - t) <= 3000) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Smart-rule override deduplication
// ---------------------------------------------------------------------------
//
// When a smart rule with verdict=block fires, the orchestrator writes an
// immediate `deny / smart-rule-block-override` audit row, prompts the user,
// then — if the user clicks Allow — writes a second row with
// `allow / checkedBy=daemon` (the daemon's decision record). The tool call
// runs. The pair is reliably distinguishable by:
//   - same argsHash
//   - same sessionId
//   - same tool name
//   - within ~60 seconds (≈ default approval-popup timeout)
//
// Without dedupe, the intermediate deny inflates the "Auto-blocked" bucket
// while the user's actual approval is also recorded separately. The
// dashboard then over-counts blocks AND misattributes the same user-decision
// flow to two different outcome buckets.
//
// Both rows are kept in the audit log for forensic completeness; only the
// aggregator skips counting the intermediate.
//
// Why match by `checkedBy === 'daemon'` (not `source === 'daemon'`): there
// are TWO daemon-related allow rows for each override flow — one with
// `source: 'daemon'` (the routed incoming request, with raw args, no hash)
// and one with `checkedBy: 'daemon'` (the daemon's decision, with hash +
// session). Only the latter carries the fields needed to pair safely.

const SUPERSEDE_WINDOW_MS = 60_000;

/** Returns a Set of "ts|argsHash" keys for smart-rule-block-override
 *  rows that were resolved by a subsequent `allow / checkedBy=daemon`
 *  row in the same session within SUPERSEDE_WINDOW_MS. The main
 *  aggregator loop skips counting these — the user's final approval
 *  row (which has `source === 'daemon'`) is still counted via the
 *  existing user-interactive branch. */
function buildSupersededSet(entries: AuditEntry[]): Set<string> {
  const superseded = new Set<string>();
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.decision !== 'deny') continue;
    if (e.checkedBy !== 'smart-rule-block-override') continue;
    if (!e.argsHash || !e.sessionId) continue;

    const eTs = Date.parse(e.ts);
    if (Number.isNaN(eTs)) continue;

    for (let j = i + 1; j < entries.length; j++) {
      const next = entries[j];
      const nextTs = Date.parse(next.ts);
      if (Number.isNaN(nextTs)) continue;
      if (nextTs - eTs > SUPERSEDE_WINDOW_MS) break;
      if (next.argsHash !== e.argsHash) continue;
      if (next.sessionId !== e.sessionId) continue;
      if (next.tool !== e.tool) continue;
      if (next.decision === 'allow' && next.checkedBy === 'daemon') {
        superseded.add(`${e.ts}|${e.argsHash}`);
        break;
      }
    }
  }
  return superseded;
}

/** Key for membership checks in the superseded set. Stable because the
 *  audit log is append-only — row timestamps don't change. */
function supersedeKey(e: AuditEntry): string {
  return `${e.ts}|${e.argsHash ?? ''}`;
}

// ---------------------------------------------------------------------------
// Date / decision helpers
// ---------------------------------------------------------------------------

/**
 * Resolve a ReportPeriod to a [start, end] Date pair anchored on `now`.
 * Exported for the dashboard's filterScanByPeriod() so scan-data
 * filtering uses the same boundaries as audit aggregation.
 */
export function getReportDateRange(
  period: ReportPeriod,
  now: Date = new Date()
): { start: Date; end: Date } {
  return getDateRange(period, now);
}

export function getDateRange(period: ReportPeriod, now: Date): { start: Date; end: Date } {
  const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const end = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999);
  switch (period) {
    case 'today':
      return { start: todayStart, end };
    case '7d': {
      const s = new Date(todayStart);
      s.setDate(s.getDate() - 6);
      return { start: s, end };
    }
    case '30d': {
      const s = new Date(todayStart);
      s.setDate(s.getDate() - 29);
      return { start: s, end };
    }
    case '90d': {
      // Rolling 90 days (the [Q]uarter keypress in the dashboard).
      // NOT a calendar quarter — that semantic isn't requested and is
      // ambiguous (fiscal vs calendar). Rolling N days is consistent
      // with 7d/30d.
      const s = new Date(todayStart);
      s.setDate(s.getDate() - 89);
      return { start: s, end };
    }
    case 'month':
      return { start: new Date(now.getFullYear(), now.getMonth(), 1), end };
  }
}

function parseAuditLog(logPath: string): AuditEntry[] {
  if (!fs.existsSync(logPath)) return [];
  const raw = fs.readFileSync(logPath, 'utf-8');
  return raw.split('\n').flatMap((line) => {
    if (!line.trim()) return [];
    try {
      return [JSON.parse(line) as AuditEntry];
    } catch {
      return [];
    }
  });
}

function isAllow(decision: string): boolean {
  return decision.startsWith('allow');
}

function isDlp(checkedBy: string | undefined): boolean {
  return !!checkedBy?.includes('dlp');
}

// ---------------------------------------------------------------------------
// Claude Code cost tracking (reads ~/.claude/projects/**/*.jsonl)
// ---------------------------------------------------------------------------

/** Claude per-token pricing, sourced from the SHARED `pricingFor` table
 *  (LiteLLM-backed) — the *same* source the upload path (`costSync`) uses, so
 *  local and cloud no longer carry independent price tables that drift. This
 *  used to be a hardcoded table that did exactly that: `claude-opus-4` read
 *  $15/M locally vs the authoritative $5/M upstream (a silent 3× gap on every
 *  opus-4 session, hidden behind the reconcile net's magnitude band).
 *
 *  Caveat: `pricingFor` resolves against the in-memory LiteLLM cache when it's
 *  been primed (`ensurePricingLoaded`), else the bundled snapshot. The upload
 *  path and the async dashboard reader prime it; the *synchronous* CLI report
 *  walker does not, so it resolves against the bundled snapshot. They agree as
 *  long as the bundle tracks LiteLLM (it's the documented fallback), but a
 *  freshly-changed LiteLLM rate could briefly differ until the bundle updates.
 *
 *  `pricingFor` also does better model-name matching (longest-key-wins +
 *  date/`@` suffix handling). Returns the `{i,o,cw,cr}` shape the cost walker
 *  expects; null when unknown. Exported for the regression test. */
export function claudeModelPrice(
  model: string
): { i: number; o: number; cw: number; cr: number } | null {
  const t = pricingFor(model);
  if (!t) return null;
  const [i, o, cw, cr] = t;
  return { i, o, cw, cr };
}

/** Per-project cost / token rollup. Key = decoded working directory
 *  (e.g. `/home/nadav/node9` rather than the `-home-nadav-node9`
 *  folder name on disk). Decoding uses costSync.decodeProjectDirName
 *  which is lossy when path components themselves contain `-`, but
 *  it's accurate enough for "which projects am I spending on". */
export interface ProjectCostRollup {
  cost: number;
  inputTokens: number;
  outputTokens: number;
}

export interface ClaudeCostData {
  total: number;
  byDay: Map<string, number>;
  byModel: Map<string, number>;
  byProject: Map<string, ProjectCostRollup>;
  inputTokens: number;
  outputTokens: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
}

export interface CodexCostData {
  total: number;
  byDay: Map<string, number>;
  byModel: Map<string, number>;
  toolCalls: number;
}

/** Mutable accumulator shared across per-project cost extraction calls. */
interface ClaudeCostAccumulator {
  total: number;
  inputTokens: number;
  outputTokens: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
  byDay: Map<string, number>;
  byModel: Map<string, number>;
  byProject: Map<string, ProjectCostRollup>;
}

function emptyClaudeCostAccumulator(): ClaudeCostAccumulator {
  return {
    total: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheWriteTokens: 0,
    cacheReadTokens: 0,
    byDay: new Map(),
    byModel: new Map(),
    byProject: new Map(),
  };
}

function freezeClaudeCost(acc: ClaudeCostAccumulator): ClaudeCostData {
  return {
    total: acc.total,
    byDay: acc.byDay,
    byModel: acc.byModel,
    byProject: acc.byProject,
    inputTokens: acc.inputTokens,
    outputTokens: acc.outputTokens,
    cacheWriteTokens: acc.cacheWriteTokens,
    cacheReadTokens: acc.cacheReadTokens,
  };
}

/** Walk one project's JSONLs and fold cost into `acc`. Per-project body
 *  extracted from loadClaudeCost so the sync walker (CLI) and the async
 *  chunked walker (dashboard) share identical logic. */
function processClaudeCostProject(
  proj: string,
  projectsDir: string,
  start: Date,
  end: Date,
  acc: ClaudeCostAccumulator
): void {
  const projPath = path.join(projectsDir, proj);
  let files: string[];
  try {
    const stat = fs.statSync(projPath);
    if (!stat.isDirectory()) return;
    files = fs.readdirSync(projPath).filter((f) => f.endsWith('.jsonl') && !f.startsWith('agent-'));
  } catch {
    return;
  }

  // mtime cutoff — files whose last write predates `start` can't carry
  // assistant entries inside the window. Cheap stat per file saves the
  // read+JSON.parse on years-old session files. Without this, a heavy
  // install (multi-year ~/.claude/projects) parses hundreds of MB just
  // to discard most of it via the per-line `ts < start` check below.
  const startMs = start.getTime();

  for (const file of files) {
    const filePath = path.join(projPath, file);
    try {
      if (fs.statSync(filePath).mtimeMs < startMs) continue;
    } catch {
      continue;
    }
    try {
      const raw = fs.readFileSync(filePath, 'utf-8');
      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        let entry: JournalEntry;
        try {
          entry = JSON.parse(line) as JournalEntry;
        } catch {
          continue;
        }
        if (entry.type !== 'assistant') continue;
        if (!entry.timestamp) continue;
        const ts = new Date(entry.timestamp);
        if (ts < start || ts > end) continue;

        const usage = entry.message?.usage;
        const model = entry.message?.model;
        if (!usage || !model) continue;

        const p = claudeModelPrice(model);
        if (!p) continue;

        const inp = usage.input_tokens ?? 0;
        const out = usage.output_tokens ?? 0;
        const cw = usage.cache_creation_input_tokens ?? 0;
        const cr = usage.cache_read_input_tokens ?? 0;
        const cost = inp * p.i + out * p.o + cw * p.cw + cr * p.cr;

        acc.total += cost;
        acc.inputTokens += inp;
        acc.outputTokens += out;
        acc.cacheWriteTokens += cw;
        acc.cacheReadTokens += cr;

        const dateKey = entry.timestamp.slice(0, 10);
        acc.byDay.set(dateKey, (acc.byDay.get(dateKey) ?? 0) + cost);

        const normModel = model.replace(/@.*$/, '').replace(/-\d{8}$/, '');
        acc.byModel.set(normModel, (acc.byModel.get(normModel) ?? 0) + cost);

        // Per-project rollup. `proj` is the encoded dir name (slashes
        // replaced by dashes), decoded back to a path for display.
        // Lossy decode is OK — this is for "which projects am I
        // spending on at a glance", not for path equality.
        const projectKey = decodeProjectDirName(proj);
        const projectRollup = acc.byProject.get(projectKey) ?? {
          cost: 0,
          inputTokens: 0,
          outputTokens: 0,
        };
        projectRollup.cost += cost;
        projectRollup.inputTokens += inp;
        projectRollup.outputTokens += out;
        acc.byProject.set(projectKey, projectRollup);
      }
    } catch {
      continue;
    }
  }
}

function loadClaudeCost(start: Date, end: Date, projectsDir: string): ClaudeCostData {
  const acc = emptyClaudeCostAccumulator();
  if (!fs.existsSync(projectsDir)) return freezeClaudeCost(acc);

  let dirs: string[];
  try {
    dirs = fs.readdirSync(projectsDir);
  } catch {
    return freezeClaudeCost(acc);
  }

  for (const proj of dirs) {
    processClaudeCostProject(proj, projectsDir, start, end, acc);
  }

  return freezeClaudeCost(acc);
}

/** Async chunked variant — yields between projects so the dashboard's
 *  ink reconciler can repaint and the input handler can dispatch keys
 *  while the [2] view's cost walk is in flight. */
export async function loadClaudeCostAsync(
  start: Date,
  end: Date,
  projectsDir: string
): Promise<ClaudeCostData> {
  const acc = emptyClaudeCostAccumulator();
  if (!fs.existsSync(projectsDir)) return freezeClaudeCost(acc);

  let dirs: string[];
  try {
    dirs = fs.readdirSync(projectsDir);
  } catch {
    return freezeClaudeCost(acc);
  }

  for (const proj of dirs) {
    processClaudeCostProject(proj, projectsDir, start, end, acc);
    await new Promise((resolve) => setImmediate(resolve));
  }

  return freezeClaudeCost(acc);
}

// ---------------------------------------------------------------------------
// Codex cost tracking (reads ~/.codex/sessions/YYYY/MM/DD/*.jsonl)
// ---------------------------------------------------------------------------

interface CodexCostAccumulator {
  total: number;
  toolCalls: number;
  byDay: Map<string, number>;
  byModel: Map<string, number>;
}

/** Walk one Codex session file and fold cost into `acc`. Per-file body
 *  extracted so sync and async chunked walkers share identical logic. */
function processCodexCostFile(
  filePath: string,
  start: Date,
  end: Date,
  acc: CodexCostAccumulator
): void {
  let lines: string[];
  try {
    lines = fs.readFileSync(filePath, 'utf-8').split('\n');
  } catch {
    return;
  }

  let sessionStart = '';
  let model = '';
  let lastTotalInput = 0;
  let lastTotalCached = 0;
  let lastTotalOutput = 0;
  let sessionToolCalls = 0;

  for (const line of lines) {
    if (!line.trim()) continue;
    let entry: { type: string; payload?: Record<string, unknown> };
    try {
      entry = JSON.parse(line) as typeof entry;
    } catch {
      continue;
    }

    const p = (entry.payload ?? {}) as Record<string, unknown>;

    if (entry.type === 'session_meta') {
      sessionStart = String(p['timestamp'] ?? '');
      continue;
    }

    // Codex carries the model on turn_context; last-wins, matching cost-codex.
    if (entry.type === 'turn_context' && typeof p['model'] === 'string') {
      model = p['model'];
      continue;
    }

    if (entry.type === 'event_msg' && p['type'] === 'token_count') {
      const info = (p['info'] ?? {}) as Record<string, unknown>;
      const usage = (info['total_token_usage'] ?? {}) as Record<string, number>;
      lastTotalInput = usage['input_tokens'] ?? lastTotalInput;
      lastTotalCached = usage['cached_input_tokens'] ?? lastTotalCached;
      lastTotalOutput = usage['output_tokens'] ?? lastTotalOutput;
    }

    if (entry.type === 'response_item' && p['type'] === 'function_call') {
      sessionToolCalls++;
    }
  }

  if (!sessionStart) return;
  const ts = new Date(sessionStart);
  if (ts < start || ts > end) return;

  // Price per-model via the SHARED codexPriceFor (pricingFor + fallback) — the
  // SAME source the upload path uses — instead of a flat hardcoded gpt-5 rate.
  const nonCached = Math.max(0, lastTotalInput - lastTotalCached);
  const [pin, pout, , pcr] = codexPriceFor(model || 'gpt-5');
  const cost = nonCached * pin + lastTotalCached * pcr + lastTotalOutput * pout;
  acc.total += cost;
  acc.toolCalls += sessionToolCalls;
  const dateKey = sessionStart.slice(0, 10);
  acc.byDay.set(dateKey, (acc.byDay.get(dateKey) ?? 0) + cost);
  const normModel = normalizeModel(model || 'gpt-5');
  acc.byModel.set(normModel, (acc.byModel.get(normModel) ?? 0) + cost);
}

/** Build the flat list of session JSONL paths under `sessionsBase`. The
 *  Codex layout is YYYY/MM/DD/*.jsonl; this walks the date dirs once so
 *  both sync and async cost loaders can iterate the same path list. */
function listCodexSessionFiles(sessionsBase: string): string[] {
  const jsonlFiles: string[] = [];
  if (!fs.existsSync(sessionsBase)) return jsonlFiles;
  try {
    for (const year of fs.readdirSync(sessionsBase)) {
      const yearPath = path.join(sessionsBase, year);
      try {
        if (!fs.statSync(yearPath).isDirectory()) continue;
      } catch {
        continue;
      }
      for (const month of fs.readdirSync(yearPath)) {
        const monthPath = path.join(yearPath, month);
        try {
          if (!fs.statSync(monthPath).isDirectory()) continue;
        } catch {
          continue;
        }
        for (const day of fs.readdirSync(monthPath)) {
          const dayPath = path.join(monthPath, day);
          try {
            if (!fs.statSync(dayPath).isDirectory()) continue;
          } catch {
            continue;
          }
          for (const file of fs.readdirSync(dayPath)) {
            if (file.endsWith('.jsonl')) jsonlFiles.push(path.join(dayPath, file));
          }
        }
      }
    }
  } catch {
    return [];
  }
  return jsonlFiles;
}

/** Merge per-model cost maps (e.g. Claude + Codex) into one for the report's
 *  byModel breakdown. Keys don't collide across agents (claude vs gpt / o-series). */
function mergeByModel(...maps: Array<Map<string, number>>): Map<string, number> {
  const out = new Map<string, number>();
  for (const m of maps) {
    for (const [k, v] of m) out.set(k, (out.get(k) ?? 0) + v);
  }
  return out;
}

function loadCodexCost(start: Date, end: Date, sessionsBase: string): CodexCostData {
  const acc: CodexCostAccumulator = {
    total: 0,
    toolCalls: 0,
    byDay: new Map(),
    byModel: new Map(),
  };
  const files = listCodexSessionFiles(sessionsBase);
  for (const filePath of files) {
    processCodexCostFile(filePath, start, end, acc);
  }
  return { total: acc.total, byDay: acc.byDay, byModel: acc.byModel, toolCalls: acc.toolCalls };
}

/** Async chunked variant — yields between files. Codex sessions are
 *  smaller than Claude projects so per-file granularity (rather than
 *  per-project) is fine. */
export async function loadCodexCostAsync(
  start: Date,
  end: Date,
  sessionsBase: string
): Promise<CodexCostData> {
  const acc: CodexCostAccumulator = {
    total: 0,
    toolCalls: 0,
    byDay: new Map(),
    byModel: new Map(),
  };
  const files = listCodexSessionFiles(sessionsBase);
  // Yield every CHUNK_SIZE files rather than every file — per-file work is
  // small, and yielding too aggressively adds scheduling overhead.
  const CHUNK_SIZE = 5;
  for (let i = 0; i < files.length; i++) {
    processCodexCostFile(files[i], start, end, acc);
    if (i % CHUNK_SIZE === CHUNK_SIZE - 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
  }
  return { total: acc.total, byDay: acc.byDay, byModel: acc.byModel, toolCalls: acc.toolCalls };
}

// ---------------------------------------------------------------------------
// Gemini cost tracking (reads ~/.gemini/tmp/<project>/chats/session-*.jsonl)
//
// Gemini Code's local journals live under ~/.gemini/tmp/<project-basename>/
// chats/session-*.jsonl. Each turn is one JSONL line with:
//   { id, timestamp, type: 'gemini' | 'user' | 'info', tokens?:
//     { input, output, cached, thoughts, tool, total }, model?: string }
//
// Quirks vs the Claude/Codex walkers:
//   - Every gemini turn is written TWICE in the same file with identical
//     id + tokens (Gemini flushes a partial + final). Dedup by id per-file.
//   - `tokens.input` is the TOTAL prompt size including `tokens.cached`.
//     Bill (input - cached) at the input rate, cached at the cache-read
//     rate (matches Google's billing model).
//   - Preview models (e.g. `gemini-3-flash-preview`) aren't in LiteLLM's
//     price list. Fall back to `gemini-2.5-flash` as a same-tier proxy
//     so we don't undercount; users who care can swap to whatever
//     comparable model lives in the pricing table.
//   - The dir basename ("node9", "node9-wrapper") isn't a full path. We
//     store it as-is in byProject — the panel renders basename anyway,
//     so it merges visually with Claude's `/home/.../node9` row when
//     the user picks the same project across agents.
// ---------------------------------------------------------------------------

/** PricingTuple shape matches src/pricing/litellm.ts:
 *  [input/tok, output/tok, cache_write/tok, cache_read/tok].
 *
 *  Fallback chain when the exact model isn't in LiteLLM: try
 *  gemini-2.5-flash (live LiteLLM cache), then gemini-2.0-flash
 *  (in the bundled fallback table). This keeps tests deterministic
 *  even when ~/.node9/model-pricing.json hasn't been fetched, and
 *  prefers the closest-tier proxy in production where the live
 *  cache has 2.5-flash. cacheRead falls back to the input rate when
 *  the model reports 0 (Gemini's older variants don't expose
 *  cache_read pricing separately). */
const GEMINI_FALLBACK_MODELS = ['gemini-2.5-flash', 'gemini-2.0-flash'];
function geminiPriceFor(
  model: string
): { input: number; output: number; cacheRead: number } | null {
  let tuple = pricingFor(model);
  if (!tuple && /^gemini-/i.test(model)) {
    for (const proxy of GEMINI_FALLBACK_MODELS) {
      tuple = pricingFor(proxy);
      if (tuple) break;
    }
  }
  if (!tuple) return null;
  return { input: tuple[0], output: tuple[1], cacheRead: tuple[3] || tuple[0] };
}

export interface GeminiCostData {
  total: number;
  byDay: Map<string, number>;
  byProject: Map<string, ProjectCostRollup>;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
}

interface GeminiCostAccumulator {
  total: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  byDay: Map<string, number>;
  byProject: Map<string, ProjectCostRollup>;
}

function emptyGeminiAccumulator(): GeminiCostAccumulator {
  return {
    total: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    byDay: new Map(),
    byProject: new Map(),
  };
}

function freezeGeminiCost(acc: GeminiCostAccumulator): GeminiCostData {
  return {
    total: acc.total,
    byDay: acc.byDay,
    byProject: acc.byProject,
    inputTokens: acc.inputTokens,
    outputTokens: acc.outputTokens,
    cacheReadTokens: acc.cacheReadTokens,
  };
}

interface GeminiTurn {
  id: string;
  timestamp: string;
  type: string;
  tokens?: { input?: number; output?: number; cached?: number };
  model?: string;
}

/** Walk one Gemini session file and fold cost into `acc`. Dedup by id
 *  inside the file (each turn is written twice — partial + final). */
function processGeminiCostFile(
  filePath: string,
  projectKey: string,
  start: Date,
  end: Date,
  acc: GeminiCostAccumulator
): void {
  const startMs = start.getTime();
  try {
    if (fs.statSync(filePath).mtimeMs < startMs) return;
  } catch {
    return;
  }
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return;
  }

  const seenIds = new Set<string>();
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    let entry: GeminiTurn;
    try {
      entry = JSON.parse(line) as GeminiTurn;
    } catch {
      continue;
    }
    if (entry.type !== 'gemini') continue;
    if (!entry.tokens || !entry.model || !entry.timestamp) continue;
    if (entry.id) {
      if (seenIds.has(entry.id)) continue;
      seenIds.add(entry.id);
    }
    const ts = new Date(entry.timestamp);
    if (ts < start || ts > end) continue;

    const price = geminiPriceFor(entry.model);
    if (!price) continue;

    const inp = entry.tokens.input ?? 0;
    const out = entry.tokens.output ?? 0;
    const cached = Math.min(entry.tokens.cached ?? 0, inp);
    const fresh = Math.max(0, inp - cached);
    const cost = fresh * price.input + cached * price.cacheRead + out * price.output;

    acc.total += cost;
    acc.inputTokens += inp;
    acc.outputTokens += out;
    acc.cacheReadTokens += cached;

    const dateKey = entry.timestamp.slice(0, 10);
    acc.byDay.set(dateKey, (acc.byDay.get(dateKey) ?? 0) + cost);

    const rollup = acc.byProject.get(projectKey) ?? {
      cost: 0,
      inputTokens: 0,
      outputTokens: 0,
    };
    rollup.cost += cost;
    rollup.inputTokens += inp;
    rollup.outputTokens += out;
    acc.byProject.set(projectKey, rollup);
  }
}

/** List every session JSONL under ~/.gemini/tmp/<project>/chats/. */
function listGeminiSessionFiles(geminiTmpDir: string): Array<{ projectKey: string; file: string }> {
  const out: Array<{ projectKey: string; file: string }> = [];
  let dirs: string[];
  try {
    if (!fs.statSync(geminiTmpDir).isDirectory()) return out;
    dirs = fs.readdirSync(geminiTmpDir);
  } catch {
    return out;
  }
  for (const proj of dirs) {
    const chatsDir = path.join(geminiTmpDir, proj, 'chats');
    let files: string[];
    try {
      if (!fs.statSync(chatsDir).isDirectory()) continue;
      files = fs.readdirSync(chatsDir);
    } catch {
      continue;
    }
    for (const f of files) {
      if (!f.endsWith('.jsonl')) continue;
      out.push({ projectKey: proj, file: path.join(chatsDir, f) });
    }
  }
  return out;
}

function loadGeminiCost(start: Date, end: Date, geminiTmpDir: string): GeminiCostData {
  const acc = emptyGeminiAccumulator();
  if (!fs.existsSync(geminiTmpDir)) return freezeGeminiCost(acc);
  for (const { projectKey, file } of listGeminiSessionFiles(geminiTmpDir)) {
    processGeminiCostFile(file, projectKey, start, end, acc);
  }
  return freezeGeminiCost(acc);
}

/** Async chunked variant — yields every CHUNK_SIZE files. */
export async function loadGeminiCostAsync(
  start: Date,
  end: Date,
  geminiTmpDir: string
): Promise<GeminiCostData> {
  const acc = emptyGeminiAccumulator();
  if (!fs.existsSync(geminiTmpDir)) return freezeGeminiCost(acc);
  const files = listGeminiSessionFiles(geminiTmpDir);
  const CHUNK_SIZE = 5;
  for (let i = 0; i < files.length; i++) {
    processGeminiCostFile(files[i].file, files[i].projectKey, start, end, acc);
    if (i % CHUNK_SIZE === CHUNK_SIZE - 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
  }
  return freezeGeminiCost(acc);
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/**
 * Aggregate ~/.node9/audit.log + Claude/Codex journals for the given period
 * into the canonical BuildReportJsonInput shape. Always returns a result —
 * empty audit log produces a zeroed envelope rather than throwing, so
 * dashboard consumers don't need a null check.
 */
export function aggregateReportFromAudit(
  period: ReportPeriod,
  opts: AggregateOpts = {}
): AggregateResult {
  const now = opts.now ?? new Date();
  const auditLogPath = opts.auditLogPath ?? path.join(os.homedir(), '.node9', 'audit.log');
  const claudeProjectsDir =
    opts.claudeProjectsDir ?? path.join(os.homedir(), '.claude', 'projects');
  const codexSessionsDir = opts.codexSessionsDir ?? path.join(os.homedir(), '.codex', 'sessions');
  const geminiTmpDir = opts.geminiTmpDir ?? path.join(os.homedir(), '.gemini', 'tmp');

  const hasAuditFile = fs.existsSync(auditLogPath);
  const allEntries = opts.preloadedAuditEntries ?? parseAuditLog(auditLogPath);

  const unackedDlp = allEntries.filter((e) => e.source === 'response-dlp');

  const { start, end } = getDateRange(period, now);

  // Period-filtered response-dlp entries — the CLI renderer needs the per-
  // entry dlpPattern + dlpSample fields, which aren't in BuildReportJsonInput.
  const responseDlpEntries: ResponseDlpEntry[] = allEntries
    .filter((e) => {
      if (e.source !== 'response-dlp') return false;
      const ts = new Date(e.ts);
      return ts >= start && ts <= end;
    })
    .map((e) => {
      const raw = e as unknown as Record<string, unknown>;
      return {
        ts: e.ts,
        dlpPattern: typeof raw.dlpPattern === 'string' ? raw.dlpPattern : undefined,
        dlpSample: typeof raw.dlpSample === 'string' ? raw.dlpSample : undefined,
      };
    });

  const claudeCost = opts.preloadedClaudeCost ?? loadClaudeCost(start, end, claudeProjectsDir);
  const codexCost = opts.preloadedCodexCost ?? loadCodexCost(start, end, codexSessionsDir);
  const geminiCost = opts.preloadedGeminiCost ?? loadGeminiCost(start, end, geminiTmpDir);

  // Merge Codex + Gemini daily costs into Claude's byDay map (the wire
  // format has a single byDay; Claude's map is mutable so we extend it
  // in place).
  for (const [day, c] of codexCost.byDay) {
    claudeCost.byDay.set(day, (claudeCost.byDay.get(day) ?? 0) + c);
  }
  for (const [day, c] of geminiCost.byDay) {
    claudeCost.byDay.set(day, (claudeCost.byDay.get(day) ?? 0) + c);
  }

  // Merge Gemini per-project rollups into Claude's byProject map. Match
  // by basename: Claude stores decoded paths like `/home/u/node9`,
  // Gemini stores bare dir names like `node9`. Same basename = same
  // project across agents. Falls back to insert-new on no match.
  for (const [geminiKey, gRollup] of geminiCost.byProject) {
    let mergedInto: string | null = null;
    for (const claudeKey of claudeCost.byProject.keys()) {
      const claudeBase = claudeKey.match(/[^/\\]+$/)?.[0] ?? claudeKey;
      if (claudeBase === geminiKey) {
        mergedInto = claudeKey;
        break;
      }
    }
    const targetKey = mergedInto ?? geminiKey;
    const existing = claudeCost.byProject.get(targetKey) ?? {
      cost: 0,
      inputTokens: 0,
      outputTokens: 0,
    };
    existing.cost += gRollup.cost;
    existing.inputTokens += gRollup.inputTokens;
    existing.outputTokens += gRollup.outputTokens;
    claudeCost.byProject.set(targetKey, existing);
  }

  // Prior period for block-trend arrow (same duration, immediately before start)
  const periodMs = end.getTime() - start.getTime();
  const priorEnd = new Date(start.getTime() - 1);
  const priorStart = new Date(start.getTime() - periodMs);
  const priorEntries = allEntries.filter((e) => {
    if (e.source === 'post-hook') return false;
    const ts = new Date(e.ts);
    return ts >= priorStart && ts <= priorEnd;
  });
  const priorBlocked = priorEntries.filter((e) => !isAllow(e.decision)).length;
  const priorBlockRate = priorEntries.length > 0 ? priorBlocked / priorEntries.length : null;

  // PreToolUse entries inside the period (post-hook + response-dlp dropped)
  const excludeTests = opts.excludeTests === true;
  const testTs = excludeTests ? buildTestTimestamps(allEntries) : new Set<number>();
  let excludedTests = 0;
  const entries = allEntries.filter((e) => {
    if (e.source === 'post-hook') return false;
    if (e.source === 'response-dlp') return false;
    const ts = new Date(e.ts);
    if (ts < start || ts > end) return false;
    if (excludeTests && isTestEntry(e, testTs)) {
      excludedTests++;
      return false;
    }
    return true;
  });

  // Pre-pass: identify smart-rule-block-override deny rows that were
  // resolved by a subsequent daemon allow within the same approval
  // flow. The intermediate deny rows are skipped in the bucket loop
  // below so PROTECTION counters reflect final outcomes. The matching
  // allow row is counted normally via the user-interactive branch.
  // See buildSupersededSet for the algorithm + the audit-shape
  // rationale around matching by `checkedBy === 'daemon'`.
  const superseded = buildSupersededSet(entries);

  // ── Aggregate ──
  // userApproved / userDenied: only count decisions where the user actually
  // interacted via an approver (popup, browser, terminal). These have
  // source === 'daemon'. Auto-passed calls (local-policy, trust, ignored)
  // are excluded — they never reached the user.
  let userApproved = 0;
  let userDenied = 0;
  let timedOut = 0; // daemon showed popup but no response within timeout
  let hardBlocked = 0; // auto-blocked by smart rule or persistent-deny
  let dlpBlocked = 0; // actual DLP blocks (not observe-mode)
  let observeDlp = 0; // observe-mode: DLP would-block but action was allowed
  let loopHits = 0;
  let testPasses = 0;
  let testFails = 0;
  const toolMap = new Map<string, { calls: number; blocked: number }>();
  const blockMap = new Map<string, number>();
  /** Per-specific-rule fire count. Populated from AuditEntry.ruleName
   *  (set by the orchestrator's smart-rule paths). Distinct from
   *  blockMap which groups by the generic `checkedBy` tag
   *  (`smart-rule-block`, `timeout`, etc.). ruleMap is what `[2]`
   *  Report's SHIELDS panel reads to attribute fires to their
   *  owning shield via the rule→shield map. */
  const ruleMap = new Map<string, number>();
  const agentMap = new Map<string, number>();
  const mcpMap = new Map<string, number>();
  const dailyMap = new Map<string, { calls: number; blocked: number }>();
  const hourMap = new Map<number, number>();

  for (const e of entries) {
    // Skip intermediate `smart-rule-block-override` rows that were
    // resolved by a later daemon allow. The user-approval row carries
    // the authoritative outcome — counting both inflates buckets and
    // misattributes a single decision to two different outcomes.
    if (superseded.has(supersedeKey(e))) continue;

    const allow = isAllow(e.decision);
    const dateKey = e.ts.slice(0, 10);
    const userInteracted = e.source === 'daemon';

    if (userInteracted) {
      if (allow) userApproved++;
      else userDenied++;
    } else if (!allow) {
      if (e.checkedBy === 'timeout') timedOut++;
      else if (e.checkedBy === 'observe-mode-dlp-would-block') observeDlp++;
      else if (isDlp(e.checkedBy)) dlpBlocked++;
      // A native-OS popup deny — the user clicked Block. Same intent
      // as a SaaS-approver deny (source=daemon), just a different
      // channel. Bucket it as user-denied so the dashboard's
      // "Auto-blocked" tile only reflects truly auto-decided blocks.
      else if (e.checkedBy === 'local-decision') userDenied++;
      else if (e.checkedBy !== 'loop-detected') hardBlocked++;
    }
    if (e.checkedBy === 'loop-detected') loopHits++;

    const t = toolMap.get(e.tool) ?? { calls: 0, blocked: 0 };
    t.calls++;
    if (!allow) t.blocked++;
    toolMap.set(e.tool, t);

    if (!allow) {
      // SaaS-approver denials (source=daemon, no checkedBy tag) are
      // user-initiated denies — the same conceptual bucket as native-
      // popup denies (checkedBy=local-decision). Without this fold,
      // TOP BLOCKS would show "User denied 9" while PROTECTION shows
      // "Denied 19" because the SaaS rows have no checkedBy to group
      // under. Treat them as local-decision in blockMap so both tiles
      // agree on the user-denied total.
      const key = e.checkedBy ?? (e.source === 'daemon' ? 'local-decision' : null);
      if (key) {
        blockMap.set(key, (blockMap.get(key) ?? 0) + 1);
      }
    }
    // Specific-rule attribution: only present on smart-rule paths.
    // Counts both block and review fires (everything that wasn't an
    // explicit allow).
    if (!allow && e.ruleName) {
      ruleMap.set(e.ruleName, (ruleMap.get(e.ruleName) ?? 0) + 1);
    }

    if (e.agent) agentMap.set(e.agent, (agentMap.get(e.agent) ?? 0) + 1);
    if (e.mcpServer) mcpMap.set(e.mcpServer, (mcpMap.get(e.mcpServer) ?? 0) + 1);

    const hour = new Date(e.ts).getHours();
    hourMap.set(hour, (hourMap.get(hour) ?? 0) + 1);

    const d = dailyMap.get(dateKey) ?? { calls: 0, blocked: 0 };
    d.calls++;
    if (!allow) d.blocked++;
    dailyMap.set(dateKey, d);
  }

  // Test results live in separate 'test-result' source entries (in allEntries)
  for (const e of allEntries) {
    if (e.source !== 'test-result') continue;
    const ts = new Date(e.ts);
    if (ts < start || ts > end) continue;
    if (e.testResult === 'pass') testPasses++;
    else if (e.testResult === 'fail') testFails++;
  }

  // Codex doesn't write to audit.log (no hooks) — fold its tool-call count in
  if (codexCost.toolCalls > 0) {
    agentMap.set('Codex', (agentMap.get('Codex') ?? 0) + codexCost.toolCalls);
  }

  const data: BuildReportJsonInput = {
    period,
    start,
    end,
    excludedTests,
    // Subtract superseded rows so the headline event count agrees with
    // the bucket counters (which skip them in the loop above).
    total: entries.length - superseded.size,
    userApproved,
    userDenied,
    timedOut,
    hardBlocked,
    dlpBlocked,
    observeDlp,
    loopHits,
    testPasses,
    testFails,
    unackedDlp: unackedDlp.length,
    priorBlockRate,
    cost: {
      claudeUSD: claudeCost.total,
      codexUSD: codexCost.total,
      geminiUSD: geminiCost.total,
      inputTokens: claudeCost.inputTokens + geminiCost.inputTokens,
      outputTokens: claudeCost.outputTokens + geminiCost.outputTokens,
      cacheWriteTokens: claudeCost.cacheWriteTokens,
      cacheReadTokens: claudeCost.cacheReadTokens + geminiCost.cacheReadTokens,
      byDay: claudeCost.byDay,
      byModel: mergeByModel(claudeCost.byModel, codexCost.byModel),
      byProject: claudeCost.byProject,
    },
    toolMap,
    blockMap,
    ruleMap,
    agentMap,
    mcpMap,
    dailyMap,
    hourMap,
    generatedAt: now.toISOString(),
  };

  return { data, hasAuditFile, responseDlpEntries };
}
