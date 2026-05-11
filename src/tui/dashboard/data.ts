// src/tui/dashboard/data.ts
//
// Data plumbing for `node9 monitor`. No React in this file — pure
// I/O + parsing helpers. Components import from here.
//
// Three sources:
//   1. SSE stream from the daemon (live activity)
//   2. ~/.node9/audit.log (historical aggregates within window)
//   3. runBlast() (current disk exposure)

import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';
import { runBlast } from '../../cli/commands/blast.js';
import { DAEMON_HOST, DAEMON_PORT, getInternalToken } from '../../auth/daemon.js';
import { parseJSONLFile, type DailyEntry } from '../../costSync.js';
import { SHIELDS, readActiveShields } from '../../shields.js';
import { extractFindingsFromLine } from '../../daemon/scan-watermark.js';
import {
  aggregateReportFromAudit,
  getDateRange,
  loadClaudeCostAsync,
  loadCodexCostAsync,
  type AggregateResult,
} from '../../cli/aggregate/report-audit.js';
import {
  scanClaudeHistoryAsync,
  scanGeminiHistory,
  scanCodexHistory,
} from '../../cli/commands/scan.js';
import {
  PROTECTIVE_SHIELDS,
  PROTECTIVE_SHIELD_DISCOUNT,
  type ActivityEvent,
  type AuditAggregates,
  type BlastSnapshot,
  type CostSnapshot,
  type ForensicSseEvent,
  type ProtectionSummary,
  type ReportPeriod,
  type ScanCache,
  type ScanSignalsSnapshot,
  type SessionActivityAgg,
  type SessionForensicAgg,
  type SessionShieldsAgg,
  type ShieldStatus,
} from './types.js';

// ---------------------------------------------------------------------------
// Audit log parsing — minimal copy of the report.ts helper.
// We could refactor report.ts to export it but that's a separate cleanup.
// ---------------------------------------------------------------------------

interface AuditEntry {
  ts: string;
  tool: string;
  args?: Record<string, unknown>;
  decision: string;
  checkedBy?: string;
  agent?: string;
  mcpServer?: string;
  source?: string;
  sessionId?: string;
}

function auditLogPath(): string {
  return path.join(os.homedir(), '.node9', 'audit.log');
}

export function readAuditEntries(): AuditEntry[] {
  const p = auditLogPath();
  if (!fs.existsSync(p)) return [];
  try {
    const lines = fs.readFileSync(p, 'utf8').split('\n');
    const out: AuditEntry[] = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const e = JSON.parse(line) as AuditEntry;
        if (e && typeof e.ts === 'string') out.push(e);
      } catch {
        // ignore malformed lines — same forgiving parse report.ts uses
      }
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Async, event-loop-friendly variant of readAuditEntries(). Reads the audit
 * log once (4 MB / ~10 k lines is cheap), then JSON.parses in chunks of
 * `chunkSize` lines per setImmediate-yielded tick. Between chunks the React
 * reconciler can repaint the dashboard, so a 30-second auto-refresh on the
 * Realtime view no longer feels like a 200-300 ms freeze.
 *
 * For 11 k entries with chunkSize=1000 → 12 ticks of ~25 ms each, ink gets
 * to repaint between every batch. Total wall-clock is essentially the same
 * as the sync path; only the responsiveness changes.
 *
 * The sync readAuditEntries() is kept for `node9 audit` / `node9 report`
 * CLI consumers that print and exit — yielding adds latency for no gain
 * when there's no UI to repaint.
 */
export function readAuditEntriesAsync(
  chunkSize: number = 1000,
  /** Test-only override. Production callers always read ~/.node9/audit.log. */
  customPath?: string
): Promise<AuditEntry[]> {
  return new Promise((resolve) => {
    const p = customPath ?? auditLogPath();
    if (!fs.existsSync(p)) {
      resolve([]);
      return;
    }
    let raw: string;
    try {
      raw = fs.readFileSync(p, 'utf8');
    } catch {
      resolve([]);
      return;
    }
    const lines = raw.split('\n');
    const out: AuditEntry[] = [];
    let i = 0;
    const total = lines.length;

    const processChunk = (): void => {
      const end = Math.min(i + chunkSize, total);
      for (; i < end; i++) {
        const line = lines[i];
        if (!line.trim()) continue;
        try {
          const e = JSON.parse(line) as AuditEntry;
          if (e && typeof e.ts === 'string') out.push(e);
        } catch {
          // ignore malformed lines — same forgiving parse the sync path uses
        }
      }
      if (i < total) {
        setImmediate(processChunk);
      } else {
        resolve(out);
      }
    };

    processChunk();
  });
}

// ---------------------------------------------------------------------------
// Aggregation — given audit entries within window, produce the numbers
// each panel needs. Pure; safe to call on every window change.
// ---------------------------------------------------------------------------

const TEST_TOOLS = new Set(['Bash', 'bash']);

export function aggregateAudit(
  entries: AuditEntry[],
  startMs: number,
  endMs: number = Date.now()
): AuditAggregates {
  const inWindow = entries.filter((e) => {
    if (e.source === 'post-hook' || e.source === 'response-dlp') return false;
    const t = Date.parse(e.ts);
    return t >= startMs && t <= endMs;
  });

  let allow = 0;
  let block = 0;
  let review = 0;
  let loops = 0;
  let dlpHits = 0;
  const sessionSet = new Set<string>();
  const mcpSet = new Set<string>();
  const toolMap = new Map<string, { calls: number; blocked: number }>();
  const blockMap = new Map<string, number>();
  const shellMap = new Map<string, { count: number; blocked: number }>();

  for (const e of inWindow) {
    if (e.sessionId) sessionSet.add(e.sessionId);
    if (e.mcpServer) mcpSet.add(e.mcpServer);

    const isAllow = e.decision === 'allow' || e.decision === 'observe-allow';
    const isReview = e.decision === 'review';
    const isLoop = e.checkedBy === 'loop-detected';
    // DLP rules emit checkedBy values like `dlp-block`, `dlp-saas:aws`,
    // `response-dlp-aws`, etc. Substring check covers all variants.
    const isDlp = !!(e.checkedBy && e.checkedBy.toLowerCase().includes('dlp'));
    if (isAllow) allow++;
    else if (isReview) review++;
    else block++;
    if (isLoop) loops++;
    if (isDlp) dlpHits++;

    const t = toolMap.get(e.tool) ?? { calls: 0, blocked: 0 };
    t.calls++;
    if (!isAllow && !isReview) t.blocked++;
    toolMap.set(e.tool, t);

    if (!isAllow && e.checkedBy) {
      blockMap.set(e.checkedBy, (blockMap.get(e.checkedBy) ?? 0) + 1);
    }

    // Shell-cmd extraction: first token of args.command for Bash entries.
    // Tracks blocked count per shell command so REPORT can show it
    // symmetrically with the tools column.
    if (TEST_TOOLS.has(e.tool) && typeof e.args?.command === 'string') {
      const head = (e.args.command as string).trim().split(/\s+/)[0];
      if (head && /^[a-zA-Z0-9._-]+$/.test(head)) {
        const s = shellMap.get(head) ?? { count: 0, blocked: 0 };
        s.count++;
        if (!isAllow && !isReview) s.blocked++;
        shellMap.set(head, s);
      }
    }
  }

  return {
    total: inWindow.length,
    allow,
    block,
    review,
    loops,
    dlpHits,
    sessions: sessionSet.size,
    mcpServers: mcpSet.size,
    mcpCalls: [...inWindow].filter((e) => !!e.mcpServer).length,
    byTool: [...toolMap.entries()]
      .sort((a, b) => b[1].calls - a[1].calls)
      .slice(0, 5)
      .map(([tool, v]) => ({ tool, calls: v.calls, blocked: v.blocked })),
    byBlock: [...blockMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([rule, count]) => ({ rule, count })),
    byShell: [...shellMap.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 5)
      .map(([cmd, v]) => ({ cmd, count: v.count, blocked: v.blocked })),
  };
}

// ---------------------------------------------------------------------------
// Audit → ActivityEvent — backfill seed for the LIVE panel on mount.
// Lets the dashboard open already populated with recent history rather
// than empty until the next SSE event arrives.
// ---------------------------------------------------------------------------

/**
 * Project an audit-log row to the LIVE row shape. Audit entries lack
 * a few SSE-only fields (no `id`, no inline `reason`). We synthesize
 * a deterministic id so React keys stay stable across re-renders.
 *
 * Preview handling: PreToolUse entries store `argsHash` (never
 * plaintext) when audit-arg-hashing is enabled — the default for
 * privacy. There is no way to recover plaintext from the hash, and
 * pre→post timestamp pairing is unreliable (long-running tools cause
 * 30+ second gaps). When args has no readable command/path, surface
 * the rule name (`→ block-force-push`) — much more informative than
 * a generic "(redacted)" sentinel.
 */
export function auditEntryToActivityEvent(e: AuditEntry, index: number): ActivityEvent {
  const ts = normalizeTs(e.ts);
  const verdict: 'allow' | 'block' | 'review' | 'pending' =
    e.decision === 'allow' || e.decision === 'observe-allow'
      ? 'allow'
      : e.decision === 'review'
        ? 'review'
        : 'block';
  return {
    kind: 'tool',
    id: `audit-${ts}-${e.tool}-${index}`,
    ts,
    tool: e.tool,
    agent: e.agent,
    preview: previewFromEntry(e),
    verdict,
    checkedBy: e.checkedBy,
    sessionId: e.sessionId,
    mcpServer: e.mcpServer,
  };
}

/**
 * Best-effort one-line preview from an audit row.
 *   1. Plaintext command / file_path / path (post-hook + non-hashed pre)
 *   2. argsSummary if a writer included one
 *   3. → checkedBy rule name (informative even when args are hashed)
 *   4. (no preview) — last resort; surfaces verdict-only rows with
 *      no rule attribution. Rare in practice.
 */
function previewFromEntry(e: AuditEntry): string {
  const args = e.args;
  if (args) {
    if (typeof args.command === 'string' && args.command.length > 0) {
      return args.command.replace(/\s+/g, ' ').slice(0, 70);
    }
    if (typeof args.file_path === 'string' && args.file_path.length > 0) {
      return compactPath(args.file_path).slice(0, 70);
    }
    if (typeof args.path === 'string' && args.path.length > 0) {
      return compactPath(args.path).slice(0, 70);
    }
    if (typeof args.argsSummary === 'string' && args.argsSummary.length > 0) {
      return args.argsSummary.slice(0, 70);
    }
  }
  // No plaintext available — surface the rule that fired so the row
  // still carries signal. PreToolUse rows almost always have checkedBy
  // (every gating decision references the rule that gated it).
  if (e.checkedBy) return `→ ${e.checkedBy}`;
  return '(no preview)';
}

/**
 * Compact a long absolute or home-relative path to `.../parent/file`
 * so the LIVE column doesn't get blown out by deep project paths.
 *   /home/user/repo/src/tui/dashboard/data.ts → .../dashboard/data.ts
 *   ~/projects/foo/bar/baz/main.ts            → .../baz/main.ts
 * Short paths (≤ 3 segments) pass through unchanged.
 */
export function compactPath(p: string): string {
  if (!p) return p;
  const looksLikePath = p.startsWith('/') || p.startsWith('~') || p.includes('/');
  if (!looksLikePath) return p;
  const segs = p.split('/').filter((s) => s.length > 0);
  if (segs.length <= 3) return p;
  return '.../' + segs.slice(-2).join('/');
}

/**
 * Walk a shell command string and replace every absolute / homedir path
 * token with its compactPath form. URLs (which start with a scheme like
 * `https:`) and short paths are left untouched. This keeps the LIVE row
 * readable when an agent runs something like
 *   `cd /home/nadav/node9/node9-proxy && wc -l src/tui/dashboard/data.ts`
 * which would otherwise blow past the 70-char preview budget.
 */
export function compactPathsInCommand(cmd: string): string {
  if (!cmd) return cmd;
  // Match a non-whitespace run that begins with `/` or `~/`. Greedy on
  // the run itself is fine — shell tokens are whitespace-delimited at
  // the level of granularity we care about for display.
  return cmd.replace(/(?:\/|~\/)[^\s]+/g, (match) => compactPath(match));
}

/**
 * Build a backfill seed for the LIVE panel: the most recent N audit
 * entries. Returned in chronological order so appending SSE events to
 * the end keeps the buffer monotonic.
 *
 * Skips post-hook (would double up with the matching pre-hook row's
 * verdict) and response-dlp (not tool calls). PreToolUse rows are the
 * source of record — they carry the verdict and the rule name. When
 * args is hashed (auditHashArgs default), the row's preview falls
 * back to the rule name via previewFromEntry; we don't try to merge
 * plaintext from the matching post-hook because timestamps can drift
 * 30+ seconds for long-running tools and the pairing is unreliable.
 */
export function buildLiveBackfill(n: number): ActivityEvent[] {
  if (n <= 0) return [];
  const all = readAuditEntries().filter(
    (e) => e.source !== 'post-hook' && e.source !== 'response-dlp'
  );
  const tail = all.slice(-n);
  return tail.map((e, i) => auditEntryToActivityEvent(e, i));
}

// ---------------------------------------------------------------------------
// Cost — wraps costSync.collectEntries() with async dispatch + aggregation.
// collectEntries walks every JSONL under ~/.claude/projects, so it's
// expensive (1-5s on a heavy install). Callers should run it on mount
// and on `r` keypress, never on every render.
// ---------------------------------------------------------------------------

/**
 * Lookback for the dashboard's mount-time JSONL walks (cost + scan signals).
 *
 * The dashboard exposes up to a 60-day TimeWindow option, but the *common*
 * panels (HighLevel cost-since-open, Report-tab default) need at most ~7
 * days of history. `node9 report --7d` walks the same files in ~2 s by
 * limiting work to that window; the dashboard was walking ALL history
 * (~30 s on a heavy install) — for most sessions that 23 extra seconds
 * was wasted JSON.parse on data the panels filter out before display
 * anyway.
 *
 * Trade-off: when the user picks the 30d / 60d TimeWindow option from
 * the Realtime view, the cost panel will under-report initially because
 * we don't have that history loaded. Acceptable: the next 30s refresh
 * tick has the same constraint, and `node9 report --30d` (the
 * authoritative source) is a keystroke away. We could lazy-extend the
 * walk on window change, but that's complexity beyond what the typical
 * "is the dashboard fast enough" question demands.
 */
const COST_WALK_LOOKBACK_MS = 7 * 24 * 60 * 60 * 1000;

/** Chunk size for the per-project yields below. ~3 projects per yield
 *  keeps each event-loop "Check" phase batch under ~30 ms on a heavy
 *  install — short enough that stdin keypresses (q / Ctrl+C) dispatch
 *  with at most one batch of latency. Lowering further hits diminishing
 *  returns since each setImmediate boundary itself costs ~0.1 ms. */
const PROJECTS_PER_YIELD = 3;

export async function loadCostEntries(): Promise<DailyEntry[]> {
  // Walk Claude project dirs in batches, yielding to the event loop after
  // each batch so ink can repaint and keypresses dispatch. Total wall-
  // clock is similar to the sync collectEntries; what changes is that
  // the dashboard stays responsive throughout. mtime filter still skips
  // pre-window files (the cheapest single optimization).
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  if (!fs.existsSync(projectsDir)) return [];
  let dirs: string[];
  try {
    dirs = fs.readdirSync(projectsDir);
  } catch {
    return [];
  }
  const sinceMs = Date.now() - COST_WALK_LOOKBACK_MS;
  const combined = new Map<string, DailyEntry>();

  for (let i = 0; i < dirs.length; i += PROJECTS_PER_YIELD) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    const batch = dirs.slice(i, i + PROJECTS_PER_YIELD);
    for (const dir of batch) {
      const dirPath = path.join(projectsDir, dir);
      try {
        if (!fs.statSync(dirPath).isDirectory()) continue;
      } catch {
        continue;
      }
      let files: string[];
      try {
        files = fs.readdirSync(dirPath).filter((f) => f.endsWith('.jsonl'));
      } catch {
        continue;
      }
      const fallbackWorkingDir = path.basename(dir);
      for (const file of files) {
        const filePath = path.join(dirPath, file);
        try {
          if (fs.statSync(filePath).mtimeMs < sinceMs) continue;
        } catch {
          continue;
        }
        // costSync's parseJSONLFile is per-file pure; reuse it. The
        // yield boundary above is what matters for responsiveness.
        const entries = parseJSONLFile(filePath, fallbackWorkingDir);
        for (const [key, e] of entries) {
          const prev = combined.get(key);
          if (prev) {
            prev.costUSD += e.costUSD;
            prev.inputTokens += e.inputTokens;
            prev.outputTokens += e.outputTokens;
            prev.cacheWriteTokens += e.cacheWriteTokens;
            prev.cacheReadTokens += e.cacheReadTokens;
          } else {
            combined.set(key, { ...e });
          }
        }
      }
    }
  }

  return [...combined.values()];
}

/**
 * Subtract a baseline snapshot from cost entries so HIGH LEVEL can show
 * since-monitor-opened spend instead of today's running total.
 *
 * costSync.collectEntries returns one row per (date, model, workingDir,
 * runId) tuple — multiple entries can share the same (date, model). The
 * baseline must therefore key on the FULL tuple; collapsing on (date,
 * model) only would alias unrelated rows together and produce wildly
 * wrong deltas.
 *
 * Entries the user already had at mount time form the baseline; rows
 * that grow during the session contribute their delta; rows that didn't
 * exist at mount (new session, new project dir, tomorrow's date) pass
 * through unchanged.
 *
 * Pure function. Returns a fresh array of new DailyEntry objects with
 * the original tuple fields preserved and numeric fields adjusted.
 * Math.max(0, ...) guards against negative values that could arise if
 * the underlying cost data is rebuilt or trimmed externally.
 */
function entryKey(e: DailyEntry): string {
  // Match the same tuple costSync uses internally (parseJSONLFile:97):
  // `${date}::${norm}::${workingDir}::${runId}`. We use `|` separators
  // here for readability since we never round-trip the key back into
  // costSync — it's local bookkeeping only.
  return `${e.date}|${e.model}|${e.workingDir ?? ''}|${e.runId ?? ''}`;
}

export function subtractCostBaseline(
  entries: DailyEntry[],
  baseline: Map<string, DailyEntry>
): DailyEntry[] {
  return entries.map((e) => {
    const b = baseline.get(entryKey(e));
    if (!b) return e;
    return {
      ...e,
      costUSD: Math.max(0, e.costUSD - b.costUSD),
      inputTokens: Math.max(0, e.inputTokens - b.inputTokens),
      outputTokens: Math.max(0, e.outputTokens - b.outputTokens),
      cacheReadTokens: Math.max(0, e.cacheReadTokens - b.cacheReadTokens),
      cacheWriteTokens: Math.max(0, e.cacheWriteTokens - b.cacheWriteTokens),
    };
  });
}

/** Build the (date|model|workingDir|runId)→entry baseline map used by
 *  subtractCostBaseline. Captured once on the first cost-load after
 *  monitor mount. */
export function buildCostBaseline(entries: DailyEntry[]): Map<string, DailyEntry> {
  const map = new Map<string, DailyEntry>();
  for (const e of entries) map.set(entryKey(e), { ...e });
  return map;
}

export function aggregateCost(
  entries: DailyEntry[],
  startMs: number,
  endMs: number = Date.now()
): CostSnapshot {
  // entries are keyed by `date: YYYY-MM-DD`. Compare against the window
  // by converting each date to start-of-day UTC. We include any day
  // whose start-of-day overlaps the window, which means we may slightly
  // over-count at the leading edge — acceptable for HUD-level numbers.
  let totalUSD = 0;
  let inputTokens = 0;
  let outputTokens = 0;
  let cacheReadTokens = 0;
  let cacheWriteTokens = 0;
  const byModelMap = new Map<string, { costUSD: number; calls: number }>();
  const dayMs = 86_400_000;
  for (const e of entries) {
    const t = Date.parse(e.date);
    if (Number.isNaN(t)) continue;
    if (t + dayMs < startMs) continue;
    if (t > endMs) continue;
    totalUSD += e.costUSD;
    inputTokens += e.inputTokens;
    outputTokens += e.outputTokens;
    cacheReadTokens += e.cacheReadTokens;
    cacheWriteTokens += e.cacheWriteTokens;
    // DailyEntry doesn't have a per-row call count, but it IS one
    // distinct day×model bucket, so counting buckets gives an
    // approximate session-day measure. The real value here is the
    // per-model cost split, which IS exact.
    const m = byModelMap.get(e.model) ?? { costUSD: 0, calls: 0 };
    m.costUSD += e.costUSD;
    m.calls += 1;
    byModelMap.set(e.model, m);
  }
  return {
    totalUSD,
    inputTokens,
    outputTokens,
    cacheReadTokens,
    cacheWriteTokens,
    byModel: [...byModelMap.entries()]
      .sort((a, b) => b[1].costUSD - a[1].costUSD)
      .map(([model, v]) => ({ model, costUSD: v.costUSD, calls: v.calls })),
    loaded: true,
  };
}

// ---------------------------------------------------------------------------
// Blast — wraps runBlast() with privacy-friendly path truncation.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Forensic scan signals — async walk of ~/.claude/projects JSONL files,
// running the canonical extractor per line. Surfaces the 7 detection
// categories the audit log doesn't carry (PII, sensitive-file-reads,
// privilege-escalation, destructive-op, pipe-to-shell, eval-of-remote,
// long-output-redacted). Expensive: 5-10s on a heavy install — same
// cost `node9 scan` already pays. Run once on mount + 5min refresh.
// ---------------------------------------------------------------------------

const EMPTY_SIGNALS: Omit<ScanSignalsSnapshot, 'loaded'> = {
  pii: 0,
  sensitiveFileRead: 0,
  privilegeEscalation: 0,
  destructiveOp: 0,
  pipeToShell: 0,
  evalOfRemote: 0,
  longOutputRedacted: 0,
};

export async function loadScanSignals(): Promise<ScanSignalsSnapshot> {
  try {
    const counts = await walkClaudeJsonlsForSignals();
    return { loaded: true, ...counts };
  } catch {
    return { loaded: true, ...EMPTY_SIGNALS };
  }
}

async function walkClaudeJsonlsForSignals(): Promise<Omit<ScanSignalsSnapshot, 'loaded'>> {
  const counts = { ...EMPTY_SIGNALS };
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  if (!fs.existsSync(projectsDir)) return counts;

  let dirs: string[];
  try {
    dirs = fs.readdirSync(projectsDir);
  } catch {
    return counts;
  }

  // Same lookback as cost — files older than this can't carry signals
  // relevant to any TimeWindow option the dashboard exposes. Avoids
  // JSON.parsing years-old session files on every mount.
  const sinceMs = Date.now() - COST_WALK_LOOKBACK_MS;

  for (let pIdx = 0; pIdx < dirs.length; pIdx += PROJECTS_PER_YIELD) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    const batch = dirs.slice(pIdx, pIdx + PROJECTS_PER_YIELD);
    for (const dir of batch) {
      const dirPath = path.join(projectsDir, dir);
      try {
        if (!fs.statSync(dirPath).isDirectory()) continue;
      } catch {
        continue;
      }
      let files: string[];
      try {
        files = fs.readdirSync(dirPath).filter((f) => f.endsWith('.jsonl'));
      } catch {
        continue;
      }
      for (const file of files) {
        const sessionId = file.replace(/\.jsonl$/, '');
        const filePath = path.join(dirPath, file);
        try {
          if (fs.statSync(filePath).mtimeMs < sinceMs) continue;
        } catch {
          continue;
        }
        let content: string;
        try {
          content = fs.readFileSync(filePath, 'utf8');
        } catch {
          continue;
        }
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (!line.trim()) continue;
          let parsed: unknown;
          try {
            parsed = JSON.parse(line);
          } catch {
            continue;
          }
          let findings;
          try {
            findings = extractFindingsFromLine(parsed, sessionId, i);
          } catch {
            continue;
          }
          for (const f of findings) {
            switch (f.type) {
              case 'pii':
                counts.pii++;
                break;
              case 'sensitive-file-read':
                counts.sensitiveFileRead++;
                break;
              case 'privilege-escalation':
                counts.privilegeEscalation++;
                break;
              case 'destructive-op':
                counts.destructiveOp++;
                break;
              case 'pipe-to-shell':
                counts.pipeToShell++;
                break;
              case 'eval-of-remote':
                counts.evalOfRemote++;
                break;
              case 'long-output-redacted':
                counts.longOutputRedacted++;
                break;
              // 'dlp', 'loop', 'network-exfil' tracked via other paths
              // (audit / session-level) — skip here to avoid double-count.
              default:
                break;
            }
          }
        }
      }
    }
  }
  return counts;
}

/**
 * Read the user's shield-config state. Cheap (small JSON file in
 * ~/.node9/) so safe to call alongside loadBlast on the same cadence.
 * Returns active + inactive shield names. "Inactive" means a registered
 * shield (builtin or user) that's not in ~/.node9/shields.json's active
 * list — these are the call-to-action items shown at the bottom of RISK.
 */
export function loadShieldStatus(): ShieldStatus {
  try {
    const all = Object.keys(SHIELDS).sort();
    const activeSet = new Set(readActiveShields());
    const active = all.filter((n) => activeSet.has(n));
    const inactive = all.filter((n) => !activeSet.has(n));
    return { active, inactive };
  } catch {
    return { active: [], inactive: [] };
  }
}

export function loadBlast(): BlastSnapshot {
  try {
    const r = runBlast();
    return {
      score: r.score,
      paths: r.reachable.slice(0, 5).map((f) => ({
        label: shortenPath(f.full),
        description: f.description,
        score: f.score,
      })),
      envFindings: r.envFindings.length,
    };
  } catch {
    return { score: 100, paths: [], envFindings: 0 };
  }
}

function shortenPath(p: string): string {
  const home = os.homedir();
  return p.startsWith(home) ? p.replace(home, '~') : p;
}

// ---------------------------------------------------------------------------
// Report [2] data loaders — period-aware audit aggregator + scan-walk cache
// ---------------------------------------------------------------------------

/**
 * Period-aware audit aggregation for Report [2]. Thin wrapper around the
 * shared aggregator in cli/aggregate/report-audit so the dashboard pulls
 * audit data through the same code path as `node9 report --json`. Sync —
 * fine for the CLI, but the dashboard should prefer loadReportAuditAsync
 * below to avoid blocking ink for 200-300 ms on a 4 MB audit log.
 */
export function loadReportAudit(period: ReportPeriod): AggregateResult {
  return aggregateReportFromAudit(period);
}

/**
 * Async-friendly variant of loadReportAudit. Pre-loads the audit log via
 * the chunked readAuditEntriesAsync, then feeds the result into the shared
 * aggregator via the new preloadedAuditEntries opt. The aggregator's other
 * sync work (claude / codex JSONL cost walks) still blocks — that's the
 * job of the scan-walker chunking refactor (#2 in the responsiveness plan).
 * This change alone removes the audit-parse component of the [2] freeze.
 */
export async function loadReportAuditAsync(period: ReportPeriod): Promise<AggregateResult> {
  // Pre-load every slow input through chunked async walkers, but
  // SEQUENTIALLY rather than via Promise.all. Concurrent async walkers
  // each schedule a setImmediate per yield; with N walkers, the event
  // loop's Check phase queues N callbacks per tick. Each callback runs
  // a 30-100 ms sync chunk, so a single Check phase can occupy the loop
  // for 100-400 ms — long enough that stdin events (including q) wait
  // 100-400 ms per keypress before they're delivered.
  //
  // Running the walks one at a time costs us a few hundred ms of total
  // wall-clock latency to fully populate Report [2], but it keeps each
  // Check-phase batch small (one chunk) so the Poll phase fires often
  // and stdin keypresses dispatch promptly. Net UX: [2] takes ~200 ms
  // longer to finish loading, but q quits ~instantly throughout.
  const claudeProjectsDir = path.join(os.homedir(), '.claude', 'projects');
  const codexSessionsDir = path.join(os.homedir(), '.codex', 'sessions');
  const { start, end } = getDateRange(period, new Date());
  const entries = await readAuditEntriesAsync();
  const claudeCost = await loadClaudeCostAsync(start, end, claudeProjectsDir);
  const codexCost = await loadCodexCostAsync(start, end, codexSessionsDir);
  return aggregateReportFromAudit(period, {
    preloadedAuditEntries: entries,
    preloadedClaudeCost: claudeCost,
    preloadedCodexCost: codexCost,
  });
}

/**
 * Kick off a background walk of all three agent histories
 * (~/.claude/projects, ~/.gemini, ~/.codex/sessions) and stream cache
 * updates via onUpdate. The walkers themselves are sync, so we yield
 * once via setImmediate to avoid blocking the initial paint that
 * triggered the walk.
 *
 * Returns a cancel function — when called before the walk completes,
 * suppresses the final onUpdate. Useful for unmount cleanup or for
 * superseding a stale walk after the user pressed [r] refresh.
 *
 * Lifecycle:
 *   1. caller invokes startScanWalk(setCache)
 *   2. immediate onUpdate({ status: 'loading' })   — ReportView re-renders
 *      with placeholders on scan-derived panels; non-scan panels (audit /
 *      blast / shields) render normally
 *   3. setImmediate fires; walkers run sync; takes ~1–2 s on warm machines
 *   4. on completion: onUpdate({ status: 'ready', results, readyAt })
 *   5. on throw:      onUpdate({ status: 'error', error })
 *
 * The scan-walker `onProgress` callbacks are not threaded through here —
 * we'd need a shared total-files count to render percentages and the
 * walkers don't expose one. Keeping this simple until phase 3f decides
 * whether per-panel progress bars are worth the plumbing.
 */
/** Resolves on the next event-loop tick. Used to break long sync work
 *  into shorter chunks so ink can repaint and `useInput` can dispatch
 *  keypresses (q / Ctrl+C / view switch) between chunks. */
function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

export function startScanWalk(onUpdate: (cache: ScanCache) => void): () => void {
  let cancelled = false;

  onUpdate({ status: 'loading' });

  // Same 7-day lookback the cost + signals walks use, for the same
  // reason: the [2] Report panels filter by period before display, so
  // walking older history is wasted JSON.parse + AST work. Without this
  // filter scanClaudeHistoryAsync(null) processes every assistant entry
  // ever recorded — observed 60+ seconds on a heavy install vs ~2 s for
  // `node9 report --7d` against the same data.
  const lookbackStart = new Date(Date.now() - COST_WALK_LOOKBACK_MS);

  void (async () => {
    try {
      await yieldToEventLoop();
      if (cancelled) return;

      const claude = await scanClaudeHistoryAsync(lookbackStart);
      if (cancelled) return;
      await yieldToEventLoop();
      if (cancelled) return;

      const gemini = scanGeminiHistory(lookbackStart);
      if (cancelled) return;
      await yieldToEventLoop();
      if (cancelled) return;

      const codex = scanCodexHistory(lookbackStart);
      if (cancelled) return;

      onUpdate({
        status: 'ready',
        results: { claude, gemini, codex },
        readyAt: Date.now(),
      });
    } catch (err) {
      if (cancelled) return;
      onUpdate({
        status: 'error',
        error: err instanceof Error ? err : new Error(String(err)),
      });
    }
  })();

  return () => {
    cancelled = true;
  };
}

// ---------------------------------------------------------------------------
// SSE subscription — connects to the daemon and yields ActivityEvent rows.
// Returns a teardown function the React effect cleans up.
// ---------------------------------------------------------------------------

export interface SsePayload {
  id?: string;
  /**
   * Daemon broadcasts ts as either an ISO-8601 string (audit.log path)
   * or as an epoch-ms number (server.ts:275 → entry.timestamp = Date.now()).
   * Always normalize before .slice() / Date parsing.
   */
  ts?: string | number;
  /**
   * Tool name. The daemon's `event: activity` payload uses `tool`; the
   * `event: add` payload (queued for approval) uses `toolName`. Different
   * conventions; both fields appear on the wire. toActivityEvent reads
   * either via the normalized helper below.
   */
  tool?: string;
  toolName?: string;
  agent?: string;
  args?: Record<string, unknown>;
  /**
   * Decision/status fields — also use different conventions across
   * daemon broadcast paths.
   *   - `decision` appears on `event: remove` payloads ("allow"/"deny"/"trust")
   *   - `status` appears on `event: activity-result` ("allow"/"block"/"review"/"dlp"/"timeout")
   *   - `event: activity` may carry either, depending on the broadcast site
   * mapResultStatus accepts both vocabularies; call sites pass `data.status ?? data.decision`.
   */
  decision?: string;
  status?: string;
  reason?: string;
  checkedBy?: string;
  sessionId?: string;
  mcpServer?: string;
  // Snapshot-event-only fields (daemon emits these on `event: snapshot`).
  hash?: string;
  argsSummary?: string;
  fileCount?: number;
  // Activity events have these on the inner `activity` field on some events;
  // we union both shapes since the daemon broadcasts a few SSE event names.
  activity?: SsePayload;
}

/**
 * Map a daemon decision/status string to an ActivityEvent verdict.
 *
 * Accepts both vocabularies the daemon uses:
 *   - status (from `activity-result`): allow / block / review / dlp / timeout
 *   - decision (from `remove`): allow / deny / trust
 * The two paths share this mapper because the call site does
 * `mapResultStatus(data.status ?? data.decision)`.
 */
export function mapResultStatus(status: unknown): ResolvedVerdict | undefined {
  if (typeof status !== 'string') return undefined;
  if (status === 'allow' || status === 'observe-allow' || status === 'trust') return 'allow';
  // status: dlp / block / denied / timeout — all render as block on the row.
  // decision: deny — same outcome bucket.
  if (
    status === 'dlp' ||
    status === 'block' ||
    status === 'denied' ||
    status === 'deny' ||
    status === 'timeout'
  ) {
    return 'block';
  }
  if (status === 'review') return 'review';
  return undefined;
}

function normalizeTs(ts: unknown): string {
  if (typeof ts === 'string' && ts.length > 0) return ts;
  if (typeof ts === 'number' && Number.isFinite(ts)) {
    return new Date(ts).toISOString();
  }
  return new Date().toISOString();
}

/**
 * POST a decision to the daemon's `/decision/<id>` endpoint. Mirrors
 * the call shape `node9 tail` uses (src/tui/tail.ts:postDecisionHttp).
 * Returns success on HTTP 200 OR 409 (race-loser conflict — another
 * approver got there first, which is still a resolved state).
 */
export function submitDecision(
  id: string,
  decision: 'allow' | 'deny' | 'trust'
): Promise<{ ok: boolean; error?: string }> {
  return new Promise((resolve) => {
    const token = getInternalToken();
    if (!token) {
      resolve({ ok: false, error: 'daemon not running' });
      return;
    }
    const bodyObj: Record<string, unknown> = { decision, source: 'dashboard' };
    if (decision === 'trust') bodyObj.persist = true;
    const body = JSON.stringify(bodyObj);
    const req = http.request(
      {
        hostname: DAEMON_HOST,
        port: DAEMON_PORT,
        path: `/decision/${encodeURIComponent(id)}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'X-Node9-Internal': token,
        },
      },
      (res) => {
        res.resume();
        if (res.statusCode === 200 || res.statusCode === 409) {
          resolve({ ok: true });
        } else {
          resolve({ ok: false, error: `daemon returned ${res.statusCode}` });
        }
      }
    );
    req.on('error', (err) => resolve({ ok: false, error: err.message }));
    req.end(body);
  });
}

/** Final verdict the daemon assigned to a previously-pending tool call. */
export type ResolvedVerdict = 'allow' | 'block' | 'review';

/** Known forensic categories — used to validate inbound SSE payloads
 *  before dispatch so a daemon-side bug emitting an unknown category
 *  doesn't silently fall through applyForensicEvent's default branch. */
const FORENSIC_CATEGORIES: ReadonlySet<ForensicSseEvent['category']> = new Set([
  'dlp',
  'pii',
  'sensitive-file-read',
  'privilege-escalation',
  'network-exfil',
  'pipe-to-shell',
  'eval-of-remote',
  'destructive-op',
  'loop',
  'long-output-redacted',
]);

/** Type guard for inbound 'forensic' SSE payloads. Validates required
 *  fields exist and category is one of the known union members. */
export function isValidForensicEvent(e: unknown): e is ForensicSseEvent {
  if (!e || typeof e !== 'object') return false;
  const ev = e as Partial<ForensicSseEvent>;
  return (
    typeof ev.id === 'string' &&
    typeof ev.sessionId === 'string' &&
    typeof ev.category === 'string' &&
    FORENSIC_CATEGORIES.has(ev.category as ForensicSseEvent['category'])
  );
}

/**
 * Pure reducer: increment the matching counter on a forensic SSE event.
 * 'dlp', 'loop', 'network-exfil' arrive via the audit-aggregation path
 * (counted separately) — skip here to avoid double-count.
 */
export function applyForensicEvent(
  agg: SessionForensicAgg,
  ev: ForensicSseEvent
): SessionForensicAgg {
  const next = { ...agg };
  switch (ev.category) {
    case 'pii':
      next.pii++;
      break;
    case 'sensitive-file-read':
      next.sensitiveFileRead++;
      break;
    case 'privilege-escalation':
      next.privilegeEscalation++;
      break;
    case 'destructive-op':
      next.destructiveOp++;
      break;
    case 'pipe-to-shell':
      next.pipeToShell++;
      break;
    case 'eval-of-remote':
      next.evalOfRemote++;
      break;
    case 'long-output-redacted':
      next.longOutputRedacted++;
      break;
    default:
      break;
  }
  return next;
}

/**
 * Pure reducer: tally a tool event into the live activity aggregate.
 * Called once per `kind:'tool'` SSE event. Increments tools[tool],
 * shell[firstToken] (Bash only — uses the same first-token + identifier
 * regex aggregateAudit uses so live + history match), and dlp/loops via
 * checkedBy substring (same rules aggregateAudit applies offline).
 *
 * Pending events still carry checkedBy on the wire when a rule has
 * already classified them, so we tally on every event — no second pass
 * needed in the resolve handler.
 */
export function applyActivityEvent(agg: SessionActivityAgg, e: ActivityEvent): SessionActivityAgg {
  if (e.kind !== 'tool') return agg;
  const tools = { ...agg.tools, [e.tool]: (agg.tools[e.tool] ?? 0) + 1 };
  let shell = agg.shell;
  if (SHELL_TOOLS.has(e.tool) && typeof e.preview === 'string' && e.preview.length > 0) {
    const head = e.preview.trim().split(/\s+/)[0];
    if (head && /^[a-zA-Z0-9._-]+$/.test(head)) {
      shell = { ...shell, [head]: (shell[head] ?? 0) + 1 };
    }
  }
  let dlp = agg.dlp;
  let loops = agg.loops;
  if (e.checkedBy) {
    if (e.checkedBy === 'loop-detected') loops++;
    if (e.checkedBy.toLowerCase().includes('dlp')) dlp++;
  }
  return { tools, shell, dlp, loops };
}

const SHELL_TOOLS: ReadonlySet<string> = new Set(['Bash', 'bash']);

/**
 * Build a checkedBy-rule-name → shield-name lookup once at startup. Walks
 * the SHIELDS registry (builtins + user shields loaded from
 * ~/.node9/shields/). Rules without a `name` field are skipped (they
 * can't be attributed back to a shield). Built-in detectors that emit
 * checkedBy values like `dlp-block` / `loop-detected` aren't in SHIELDS
 * and so won't appear in the returned map — that's intentional; LIVE
 * SECURITY already counts those separately.
 */
export function buildRuleToShieldMap(): Map<string, string> {
  const map = new Map<string, string>();
  for (const [shieldName, def] of Object.entries(SHIELDS)) {
    for (const rule of def.smartRules) {
      if (rule.name) map.set(rule.name, shieldName);
    }
  }
  return map;
}

/**
 * Pure function: combine blast exposure with active-shield protection
 * into a single effective score plus an actionable suggestion. Drives
 * the RISK box in the idle Notification slot and the secure / at-risk
 * threshold in the header health badge.
 *
 * Math:
 *   exposed   = 100 - blast.score  (points lost to reachable paths)
 *   protect   = min(exposed, exposed × PROTECTIVE_SHIELD_DISCOUNT)
 *               if ANY protective shield is active, else 0
 *   effective = clamp(100 - exposed + protect, 0, 100)
 *
 * The discount is a single rule (not per-shield-additive) because the
 * jails overlap heavily — both filesystem-jail AND project-jail active
 * isn't meaningfully more protection than either one alone. v2 could
 * add finer-grained per-path attribution.
 *
 * `suggestedShield` is the highest-value INACTIVE protective shield;
 * suggestedBonus is the protection points that enabling it would add.
 * Null when nothing's left to enable or effective is already maxed.
 */
export function computeProtection(
  blast: BlastSnapshot | null,
  shieldStatus: ShieldStatus | null
): ProtectionSummary {
  const score = blast?.score ?? 100;
  const exposed = Math.max(0, 100 - score);
  const active = shieldStatus?.active ?? [];
  const inactive = shieldStatus?.inactive ?? [];
  const anyProtectiveActive = active.some((name) => PROTECTIVE_SHIELDS.has(name));
  const protect = anyProtectiveActive ? Math.round(exposed * PROTECTIVE_SHIELD_DISCOUNT) : 0;
  const effective = Math.max(0, Math.min(100, 100 - exposed + protect));
  const suggestedShield =
    !anyProtectiveActive && exposed > 0
      ? (inactive.find((name) => PROTECTIVE_SHIELDS.has(name)) ?? null)
      : null;
  const suggestedBonus = suggestedShield ? Math.round(exposed * PROTECTIVE_SHIELD_DISCOUNT) : 0;
  return { exposed, protect, effective, suggestedShield, suggestedBonus };
}

/**
 * Pure reducer: tally a tool event into the per-shield activity
 * aggregate. Increments blocks for verdict='block', reviews for
 * verdict='review', skips allow/pending. Events whose checkedBy
 * doesn't map to a user shield are skipped — they're either built-in
 * detector events (counted in LIVE SECURITY) or system events without
 * a checkedBy at all.
 */
export function applyActivityToShields(
  agg: SessionShieldsAgg,
  e: ActivityEvent,
  ruleToShield: Map<string, string>
): SessionShieldsAgg {
  if (e.kind !== 'tool' || !e.checkedBy) return agg;
  if (e.verdict !== 'block' && e.verdict !== 'review') return agg;
  const shieldName = ruleToShield.get(e.checkedBy);
  if (!shieldName) return agg;
  const current = agg.byShield[shieldName] ?? { blocks: 0, reviews: 0 };
  const updated = {
    blocks: current.blocks + (e.verdict === 'block' ? 1 : 0),
    reviews: current.reviews + (e.verdict === 'review' ? 1 : 0),
  };
  return { byShield: { ...agg.byShield, [shieldName]: updated } };
}

/** Initial reconnect delay (ms). Doubles on each failure up to MAX. */
const SSE_BACKOFF_INITIAL_MS = 1_000;
const SSE_BACKOFF_MAX_MS = 30_000;

export function subscribeToSse(
  onEvent: (e: ActivityEvent) => void,
  onResolve: (id: string, verdict?: ResolvedVerdict) => void,
  onForensic: (e: ForensicSseEvent) => void,
  onError: (msg: string) => void
): () => void {
  const token = getInternalToken();
  if (!token) {
    onError('daemon not running (no ~/.node9/daemon.pid). Run: node9 daemon start');
    return () => {};
  }

  let req: http.ClientRequest | undefined;
  let reconnectTimer: NodeJS.Timeout | undefined;
  let aborted = false;
  // Backoff resets to INITIAL after a successful 200 connect, doubles
  // on each failure up to MAX. Survives daemon restarts cleanly: the
  // dashboard reconnects automatically with a visible "reconnecting…"
  // hint instead of going silent.
  let backoffMs = SSE_BACKOFF_INITIAL_MS;

  const scheduleReconnect = (reason: string) => {
    if (aborted) return;
    const wait = backoffMs;
    onError(`${reason}; reconnecting in ${Math.round(wait / 1000)}s…`);
    backoffMs = Math.min(backoffMs * 2, SSE_BACKOFF_MAX_MS);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = undefined;
      connect();
    }, wait);
  };

  const connect = () => {
    if (aborted) return;
    req = http.get(
      `http://${DAEMON_HOST}:${DAEMON_PORT}/events`,
      { headers: { 'X-Node9-Internal': token, Accept: 'text/event-stream' } },
      (res) => {
        if (res.statusCode !== 200) {
          // Drain the response so the socket can be reused / closed.
          res.resume();
          scheduleReconnect(`daemon /events returned ${res.statusCode}`);
          return;
        }
        // Successful connect — reset backoff so subsequent failures
        // start with a short retry rather than the last grown delay.
        backoffMs = SSE_BACKOFF_INITIAL_MS;
        let buf = '';
        let currentEvent = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          buf += chunk;
          let idx: number;
          while ((idx = buf.indexOf('\n')) !== -1) {
            const line = buf.slice(0, idx).replace(/\r$/, '');
            buf = buf.slice(idx + 1);
            if (line.startsWith('event:')) {
              currentEvent = line.slice(6).trim();
            } else if (line.startsWith('data:')) {
              const raw = line.slice(5).trim();
              if (!raw) continue;
              try {
                // Forensic events have their own payload shape (categorical
                // metadata only — see ForensicSseEvent). Parse + validate
                // (category must be a known union member) before dispatch.
                if (currentEvent === 'forensic') {
                  const fEvent: unknown = JSON.parse(raw);
                  if (isValidForensicEvent(fEvent)) {
                    onForensic(fEvent);
                  }
                  continue;
                }
                const data = JSON.parse(raw) as SsePayload;
                // Resolution events (`activity-result`, `remove`) carry
                // an id but no full tool shape. They tell the UI to
                // clear a pending approval card (or update its row's
                // verdict in a future iteration).
                if (currentEvent === 'activity-result' || currentEvent === 'remove') {
                  if (typeof data.id === 'string') {
                    // activity-result carries the final verdict on `status`
                    // ("block"/"allow"/"review"/"dlp"/"timeout"). `remove`
                    // uses `decision` instead ("allow"/"deny"/"trust").
                    // Pass either to the same mapper — see mapResultStatus.
                    const verdict = mapResultStatus(data.status ?? data.decision);
                    onResolve(data.id, verdict);
                  }
                  continue;
                }
                const evt = toActivityEvent(currentEvent, data);
                if (evt) onEvent(evt);
              } catch {
                /* ignore malformed lines */
              }
            }
          }
        });
        res.on('end', () => {
          if (!aborted) scheduleReconnect('daemon disconnected');
        });
      }
    );
    req.on('error', (err) => {
      if (!aborted) scheduleReconnect(`connection failed: ${err.message}`);
    });
  };

  connect();

  return () => {
    aborted = true;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    if (req) req.destroy();
  };
}

export function toActivityEvent(eventName: string, data: SsePayload): ActivityEvent | null {
  // The daemon broadcasts several event types: `activity`, `activity-result`,
  // `add`, `remove`, `snapshot`, `execution-result`. The dashboard renders
  // `activity` / `add` as tool rows and `snapshot` as snapshot rows.
  // Others are ignored.
  const payload = data.activity ?? data;
  const ts = normalizeTs(payload.ts);

  if (eventName === 'snapshot') {
    // Mirrors the format `node9 tail` uses (see src/tui/tail.ts).
    // argsSummary is typically a file path ("/home/.../src/foo.ts"); compactPath
    // collapses long absolutes to ".../parent/file" so the live row stays inside
    // the column budget. Tool name and the literal 'snapshot' fallback are left
    // alone — compactPath is a no-op on non-path strings anyway.
    const rawSummary = payload.argsSummary ?? payload.tool ?? 'snapshot';
    return {
      kind: 'snapshot',
      id: payload.id ?? `${ts}-snapshot`,
      ts,
      hash: payload.hash ?? '',
      summary: compactPath(rawSummary),
      fileCount: typeof payload.fileCount === 'number' ? payload.fileCount : 0,
    };
  }

  if (eventName !== 'activity' && eventName !== 'add') return null;
  // 'activity' events carry `tool`; 'add' events (queued approvals)
  // carry `toolName`. Without this fallback, every 'add' SSE event was
  // silently dropped at parse time, leaving NotificationArea blind to
  // approvals that needed user action. Confirmed via wire-log capture.
  const toolName = payload.tool ?? payload.toolName;
  if (!toolName) return null;

  const verdict: 'allow' | 'block' | 'review' | 'pending' = (() => {
    // Same dual-vocabulary problem as resolves: status is the standard,
    // decision is what 'remove' uses. Check both.
    const d = payload.decision ?? payload.status;
    if (d === 'allow' || d === 'observe-allow' || d === 'trust') return 'allow';
    if (d === 'block' || d === 'deny' || d === 'denied' || d === 'dlp') return 'block';
    if (d === 'review') return 'review';
    return 'pending';
  })();

  // Pick the most useful arg field for the live row. Bash → command;
  // Read/Edit/Write → file_path; Glob → path. Long file paths get
  // compacted via compactPath so deep project trees don't blow out
  // the column ("…/dashboard/data.ts" instead of the full absolute).
  let preview: string;
  if (typeof payload.args?.command === 'string' && payload.args.command.length > 0) {
    preview = compactPathsInCommand(payload.args.command.replace(/\s+/g, ' ')).slice(0, 70);
  } else if (typeof payload.args?.file_path === 'string' && payload.args.file_path.length > 0) {
    preview = compactPath(payload.args.file_path).slice(0, 70);
  } else if (typeof payload.args?.path === 'string' && payload.args.path.length > 0) {
    preview = compactPath(payload.args.path).slice(0, 70);
  } else {
    preview = JSON.stringify(payload.args ?? {})
      .replace(/\s+/g, ' ')
      .slice(0, 70);
  }

  return {
    kind: 'tool',
    id: payload.id ?? `${ts}-${toolName}`,
    ts,
    tool: toolName,
    agent: payload.agent,
    preview,
    verdict,
    reason: payload.reason,
    checkedBy: payload.checkedBy,
    sessionId: payload.sessionId,
    mcpServer: payload.mcpServer,
    // Only `add` SSE events are sent to the approval channel — those
    // are real "queued for human approval" entries. `activity` events
    // with status:'pending' look identical at the wire level (no
    // decision, transient) but should NOT pop the notification card.
    isApprovalRequest: eventName === 'add',
  };
}
