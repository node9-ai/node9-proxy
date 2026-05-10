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
  agent?: string;
  mcpServer?: string;
  source?: string;
  testRun?: boolean;
  testResult?: 'pass' | 'fail';
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

function getDateRange(period: ReportPeriod, now: Date): { start: Date; end: Date } {
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

const CLAUDE_PRICING: Record<string, { i: number; o: number; cw: number; cr: number }> = {
  'claude-opus-4-6': { i: 5e-6, o: 25e-6, cw: 6.25e-6, cr: 0.5e-6 },
  'claude-opus-4-5': { i: 5e-6, o: 25e-6, cw: 6.25e-6, cr: 0.5e-6 },
  'claude-opus-4': { i: 15e-6, o: 75e-6, cw: 18.75e-6, cr: 1.5e-6 },
  'claude-sonnet-4-6': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-sonnet-4-5': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-sonnet-4': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-3-7-sonnet': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-3-5-sonnet': { i: 3e-6, o: 15e-6, cw: 3.75e-6, cr: 0.3e-6 },
  'claude-haiku-4-5': { i: 1e-6, o: 5e-6, cw: 1.25e-6, cr: 0.1e-6 },
  'claude-3-5-haiku': { i: 0.8e-6, o: 4e-6, cw: 1e-6, cr: 0.08e-6 },
};

function claudeModelPrice(model: string): { i: number; o: number; cw: number; cr: number } | null {
  const base = model.replace(/@.*$/, '').replace(/-\d{8}$/, '');
  for (const [key, p] of Object.entries(CLAUDE_PRICING)) {
    if (base === key || base.startsWith(key + '-') || base.startsWith(key)) return p;
  }
  return null;
}

interface ClaudeCostData {
  total: number;
  byDay: Map<string, number>;
  byModel: Map<string, number>;
  inputTokens: number;
  outputTokens: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
}

function loadClaudeCost(start: Date, end: Date, projectsDir: string): ClaudeCostData {
  const empty: ClaudeCostData = {
    total: 0,
    byDay: new Map(),
    byModel: new Map(),
    inputTokens: 0,
    outputTokens: 0,
    cacheWriteTokens: 0,
    cacheReadTokens: 0,
  };
  if (!fs.existsSync(projectsDir)) return empty;

  let dirs: string[];
  try {
    dirs = fs.readdirSync(projectsDir);
  } catch {
    return empty;
  }

  let total = 0;
  let inputTokens = 0;
  let outputTokens = 0;
  let cacheWriteTokens = 0;
  let cacheReadTokens = 0;
  const byDay = new Map<string, number>();
  const byModel = new Map<string, number>();

  for (const proj of dirs) {
    const projPath = path.join(projectsDir, proj);
    let files: string[];
    try {
      const stat = fs.statSync(projPath);
      if (!stat.isDirectory()) continue;
      files = fs
        .readdirSync(projPath)
        .filter((f) => f.endsWith('.jsonl') && !f.startsWith('agent-'));
    } catch {
      continue;
    }

    for (const file of files) {
      try {
        const raw = fs.readFileSync(path.join(projPath, file), 'utf-8');
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

          total += cost;
          inputTokens += inp;
          outputTokens += out;
          cacheWriteTokens += cw;
          cacheReadTokens += cr;

          const dateKey = entry.timestamp.slice(0, 10);
          byDay.set(dateKey, (byDay.get(dateKey) ?? 0) + cost);

          const normModel = model.replace(/@.*$/, '').replace(/-\d{8}$/, '');
          byModel.set(normModel, (byModel.get(normModel) ?? 0) + cost);
        }
      } catch {
        continue;
      }
    }
  }

  return { total, byDay, byModel, inputTokens, outputTokens, cacheWriteTokens, cacheReadTokens };
}

// ---------------------------------------------------------------------------
// Codex cost tracking (reads ~/.codex/sessions/YYYY/MM/DD/*.jsonl)
// ---------------------------------------------------------------------------

function loadCodexCost(
  start: Date,
  end: Date,
  sessionsBase: string
): { total: number; byDay: Map<string, number>; toolCalls: number } {
  const byDay = new Map<string, number>();
  let total = 0;
  let toolCalls = 0;

  if (!fs.existsSync(sessionsBase)) return { total, byDay, toolCalls };

  const jsonlFiles: string[] = [];

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
    return { total, byDay, toolCalls };
  }

  for (const filePath of jsonlFiles) {
    let lines: string[];
    try {
      lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    } catch {
      continue;
    }

    let sessionStart = '';
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

    if (!sessionStart) continue;
    const ts = new Date(sessionStart);
    if (ts < start || ts > end) continue;

    const nonCached = Math.max(0, lastTotalInput - lastTotalCached);
    const cost = nonCached * 5e-6 + lastTotalCached * 2.5e-6 + lastTotalOutput * 15e-6;
    total += cost;
    toolCalls += sessionToolCalls;
    const dateKey = sessionStart.slice(0, 10);
    byDay.set(dateKey, (byDay.get(dateKey) ?? 0) + cost);
  }

  return { total, byDay, toolCalls };
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

  const claudeCost = loadClaudeCost(start, end, claudeProjectsDir);
  const codexCost = loadCodexCost(start, end, codexSessionsDir);

  // Merge Codex daily costs into Claude's byDay map (the wire format has a
  // single byDay; Claude's map is mutable so we extend it in place).
  for (const [day, c] of codexCost.byDay) {
    claudeCost.byDay.set(day, (claudeCost.byDay.get(day) ?? 0) + c);
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
  const agentMap = new Map<string, number>();
  const mcpMap = new Map<string, number>();
  const dailyMap = new Map<string, { calls: number; blocked: number }>();
  const hourMap = new Map<number, number>();

  for (const e of entries) {
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
      else if (e.checkedBy !== 'loop-detected') hardBlocked++;
    }
    if (e.checkedBy === 'loop-detected') loopHits++;

    const t = toolMap.get(e.tool) ?? { calls: 0, blocked: 0 };
    t.calls++;
    if (!allow) t.blocked++;
    toolMap.set(e.tool, t);

    if (!allow && e.checkedBy) {
      blockMap.set(e.checkedBy, (blockMap.get(e.checkedBy) ?? 0) + 1);
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
    total: entries.length,
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
      inputTokens: claudeCost.inputTokens,
      outputTokens: claudeCost.outputTokens,
      cacheWriteTokens: claudeCost.cacheWriteTokens,
      cacheReadTokens: claudeCost.cacheReadTokens,
      byDay: claudeCost.byDay,
      byModel: claudeCost.byModel,
    },
    toolMap,
    blockMap,
    agentMap,
    mcpMap,
    dailyMap,
    hourMap,
    generatedAt: now.toISOString(),
  };

  return { data, hasAuditFile, responseDlpEntries };
}
