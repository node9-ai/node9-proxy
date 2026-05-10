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
import { collectEntries, type DailyEntry } from '../../costSync.js';
import { SHIELDS, readActiveShields } from '../../shields.js';
import { extractFindingsFromLine } from '../../daemon/scan-watermark.js';
import {
  aggregateReportFromAudit,
  type AggregateResult,
} from '../../cli/aggregate/report-audit.js';
import { scanClaudeHistory, scanGeminiHistory, scanCodexHistory } from '../../cli/commands/scan.js';
import type {
  ActivityEvent,
  AuditAggregates,
  BlastSnapshot,
  CostSnapshot,
  ForensicSseEvent,
  ReportPeriod,
  ScanCache,
  ScanSignalsSnapshot,
  SessionForensicAgg,
  ShieldStatus,
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

export function loadCostEntries(): Promise<DailyEntry[]> {
  // Defer to next tick so React render isn't blocked by the file walk.
  return new Promise((resolve) => {
    setImmediate(() => {
      try {
        resolve(collectEntries());
      } catch {
        resolve([]);
      }
    });
  });
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

export function loadScanSignals(): Promise<ScanSignalsSnapshot> {
  return new Promise((resolve) => {
    setImmediate(() => {
      try {
        resolve({ loaded: true, ...walkClaudeJsonlsForSignals() });
      } catch {
        resolve({ loaded: true, ...EMPTY_SIGNALS });
      }
    });
  });
}

function walkClaudeJsonlsForSignals(): Omit<ScanSignalsSnapshot, 'loaded'> {
  const counts = { ...EMPTY_SIGNALS };
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  if (!fs.existsSync(projectsDir)) return counts;

  let dirs: string[];
  try {
    dirs = fs.readdirSync(projectsDir);
  } catch {
    return counts;
  }

  for (const dir of dirs) {
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
 * audit data through the same code path as `node9 report --json`. Sync
 * (~10 ms on a typical audit log) — the heavy stuff is the scan walk
 * which goes through startScanWalk() instead.
 */
export function loadReportAudit(period: ReportPeriod): AggregateResult {
  return aggregateReportFromAudit(period);
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
export function startScanWalk(onUpdate: (cache: ScanCache) => void): () => void {
  let cancelled = false;

  onUpdate({ status: 'loading' });

  setImmediate(() => {
    if (cancelled) return;
    try {
      const claude = scanClaudeHistory(null);
      if (cancelled) return;
      const gemini = scanGeminiHistory(null);
      if (cancelled) return;
      const codex = scanCodexHistory(null);
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
  });

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
