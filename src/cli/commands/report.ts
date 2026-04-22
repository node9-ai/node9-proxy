// src/cli/commands/report.ts
// Registered as `node9 report` by cli.ts.
// Reads ~/.node9/audit.log and renders a summary dashboard for a chosen period.

import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Period = 'today' | '7d' | '30d' | 'month';

interface AuditEntry {
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

/** Returns true if this PreToolUse entry is from a test run.
 * New entries: tagged testRun:true at write time (reliable, any tool).
 * Old Bash entries: fall back to command matching or time-join with PostToolUse. */
function isTestEntry(entry: AuditEntry, testTs: Set<number>): boolean {
  // Tagged at write time — applies to any tool type
  if (entry.testRun === true) return true;
  // Remaining fallbacks only apply to Bash
  if (entry.tool !== 'Bash' && entry.tool !== 'bash') return false;
  // Plain args available (auditHashArgs disabled) — exact
  const cmd = entry.args?.command;
  if (typeof cmd === 'string') return TEST_COMMAND_RE.test(cmd);
  // Fall back: match by PostToolUse timestamp proximity — approximate
  const t = new Date(entry.ts).getTime();
  for (const ts of testTs) {
    if (Math.abs(ts - t) <= 3000) return true;
  }
  return false;
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getDateRange(period: Period): { start: Date; end: Date } {
  const now = new Date();
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

const BLOCK_REASON_LABELS: Record<string, string> = {
  timeout: 'Popup timeout',
  'smart-rule-block': 'Smart rule',
  'observe-mode-dlp-would-block': 'DLP (observe)',
  'persistent-deny': 'Persistent deny',
  'local-decision': 'User denied',
  'dlp-block': 'DLP block',
  'loop-detected': 'Loop detected',
};

function humanBlockReason(reason: string): string {
  return BLOCK_REASON_LABELS[reason] ?? reason;
}

/** Plain bar string — no chalk so padEnd works on the raw string. */
function barStr(value: number, max: number, width: number): string {
  if (max === 0 || width <= 0) return '░'.repeat(width);
  const filled = Math.max(1, Math.round((value / max) * width));
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

function colorBar(value: number, max: number, width: number): string {
  const s = barStr(value, max, width);
  const filled = Math.max(1, Math.round(max > 0 ? (value / max) * width : 0));
  return chalk.cyan(s.slice(0, filled)) + chalk.dim(s.slice(filled));
}

function fmtDate(d: Date | string): string {
  const date = typeof d === 'string' ? new Date(d + 'T12:00:00') : d;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function num(n: number): string {
  return n.toLocaleString();
}

function fmtCost(usd: number): string {
  if (usd < 0.001) return '< $0.001';
  if (usd < 1) return '$' + usd.toFixed(4);
  return '$' + usd.toFixed(2);
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

interface CostData {
  total: number;
  byDay: Map<string, number>;
  byModel: Map<string, number>;
  inputTokens: number;
  outputTokens: number;
  cacheWriteTokens: number;
  cacheReadTokens: number;
}

function loadClaudeCost(start: Date, end: Date): CostData {
  const empty: CostData = {
    total: 0,
    byDay: new Map(),
    byModel: new Map(),
    inputTokens: 0,
    outputTokens: 0,
    cacheWriteTokens: 0,
    cacheReadTokens: 0,
  };
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
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
  end: Date
): { total: number; byDay: Map<string, number>; toolCalls: number } {
  const sessionsBase = path.join(os.homedir(), '.codex', 'sessions');
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
// Main command
// ---------------------------------------------------------------------------

export function registerReportCommand(program: Command): void {
  program
    .command('report')
    .description('Activity and security report — what Claude did, what was blocked')
    .option('--period <period>', 'today | 7d | 30d | month', '7d')
    .option('--no-tests', 'exclude test runner calls (npm test, vitest, pytest…) from stats')
    .action((options: { period: string; tests: boolean }) => {
      const period: Period = (['today', '7d', '30d', 'month'] as const).includes(
        options.period as Period
      )
        ? (options.period as Period)
        : '7d';

      const logPath = path.join(os.homedir(), '.node9', 'audit.log');
      const allEntries = parseAuditLog(logPath);

      // Warn immediately if any unacknowledged response-DLP findings exist
      const unackedDlp = allEntries.filter((e) => e.source === 'response-dlp');
      if (unackedDlp.length > 0) {
        console.log('');
        console.log(
          chalk.bgRed.white.bold(
            ` ⚠️  DLP ALERT: ${unackedDlp.length} secret${unackedDlp.length !== 1 ? 's' : ''} found in Claude response text `
          ) +
            '  ' +
            chalk.yellow('→ run: node9 dlp')
        );
      }

      if (allEntries.length === 0) {
        console.log(
          chalk.yellow('\n  No audit data found. Run node9 with Claude Code to generate entries.\n')
        );
        return;
      }

      const { start, end } = getDateRange(period);

      const {
        total: claudeCostUSD,
        byDay: costByDay,
        byModel: costByModel,
        inputTokens: costInputTokens,
        outputTokens: costOutputTokens,
        cacheWriteTokens: costCacheWrite,
        cacheReadTokens: costCacheRead,
      } = loadClaudeCost(start, end);

      const {
        total: codexCostUSD,
        byDay: codexCostByDay,
        toolCalls: codexToolCalls,
      } = loadCodexCost(start, end);
      const costUSD = claudeCostUSD + codexCostUSD;
      // Merge Codex daily costs into costByDay
      for (const [day, c] of codexCostByDay) {
        costByDay.set(day, (costByDay.get(day) ?? 0) + c);
      }

      // Prior period for block trend (same duration, immediately before start)
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

      // Only count PreToolUse entries (skip PostToolUse source: post-hook duplicates)
      const excludeTests = options.tests === false;
      const testTs = excludeTests ? buildTestTimestamps(allEntries) : new Set<number>();
      let filteredTestCount = 0;
      const entries = allEntries.filter((e) => {
        if (e.source === 'post-hook') return false;
        if (e.source === 'response-dlp') return false;
        const ts = new Date(e.ts);
        if (ts < start || ts > end) return false;
        if (excludeTests && isTestEntry(e, testTs)) {
          filteredTestCount++;
          return false;
        }
        return true;
      });

      if (entries.length === 0) {
        console.log(chalk.yellow(`\n  No activity for period "${period}".\n`));
        return;
      }

      // --- Aggregate ---
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
      const hourMap = new Map<number, number>(); // 0–23

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

      // Test results come from separate 'test-result' source entries in allEntries
      for (const e of allEntries) {
        if (e.source !== 'test-result') continue;
        const ts = new Date(e.ts);
        if (ts < start || ts > end) continue;
        if (e.testResult === 'pass') testPasses++;
        else if (e.testResult === 'fail') testFails++;
      }

      // Add Codex to agentMap if it had activity in the period (no hooks, so not in audit.log)
      if (codexToolCalls > 0) agentMap.set('Codex', (agentMap.get('Codex') ?? 0) + codexToolCalls);

      const total = entries.length;
      const topTools = [...toolMap.entries()].sort((a, b) => b[1].calls - a[1].calls).slice(0, 8);
      const topBlocks = [...blockMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
      const dailyList = [...dailyMap.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(-14);

      const maxTool = Math.max(...topTools.map(([, v]) => v.calls), 1);
      const maxBlock = Math.max(...topBlocks.map(([, v]) => v), 1);
      const maxDaily = Math.max(...dailyList.map(([, v]) => v.calls), 1);

      // --- Layout ---
      const W = Math.min(process.stdout.columns || 80, 100);
      const INNER = W - 4; // 2 chars indent each side
      const COL = Math.floor(INNER / 2) - 1;
      const LABEL = 24;
      const BAR = Math.max(6, Math.min(14, COL - LABEL - 8));
      // Fixed-width count columns so numbers right-align regardless of magnitude
      const TOOL_COUNT_W = Math.max(...topTools.map(([, v]) => num(v.calls).length), 1);
      const BLOCK_COUNT_W = Math.max(...topBlocks.map(([, v]) => num(v).length), 1);

      const line = chalk.dim('─'.repeat(W - 2));

      // ── Header ──
      const periodLabel: Record<Period, string> = {
        today: 'Today',
        '7d': 'Last 7 Days',
        '30d': 'Last 30 Days',
        month: 'This Month',
      };
      console.log('');
      console.log(
        '  ' +
          chalk.bold.cyan('🛡 node9 Report') +
          chalk.dim('  ·  ') +
          chalk.white(periodLabel[period]) +
          chalk.dim(`  ${fmtDate(start)} – ${fmtDate(end)}`) +
          chalk.dim(`  ${num(total)} events`) +
          (excludeTests ? chalk.dim(`  –tests (–${filteredTestCount})`) : '')
      );
      console.log('  ' + line);

      // ── Protection Summary ──
      const totalBlocked = timedOut + hardBlocked + dlpBlocked + loopHits + userDenied;
      const currentRate = total > 0 ? totalBlocked / total : 0;
      const trendLabel = (() => {
        if (priorBlockRate === null) return '';
        const delta = Math.round((currentRate - priorBlockRate) * 100);
        if (delta === 0) return '';
        return (
          '  ' +
          (delta > 0 ? chalk.red(`▲${delta}%`) : chalk.green(`▼${Math.abs(delta)}%`)) +
          chalk.dim(' vs prior')
        );
      })();

      const reads = toolMap.get('Read')?.calls ?? 0;
      const edits = (toolMap.get('Edit')?.calls ?? 0) + (toolMap.get('Write')?.calls ?? 0);
      const ratioLabel =
        reads > 0 ? chalk.dim(`edit/read ${(edits / reads).toFixed(1)}`) : chalk.dim('edit/read –');
      const testLabel =
        testPasses + testFails > 0
          ? chalk.dim('tests ') +
            chalk.green(`${testPasses}✓`) +
            (testFails > 0 ? ' ' + chalk.red(`${testFails}✗`) : '')
          : chalk.dim('tests –');

      console.log('');
      console.log('  ' + chalk.bold('Protection Summary'));
      console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));
      console.log(
        '  ' + chalk.dim('Intercepted') + '  ' + chalk.white(num(total)) + chalk.dim(' tool calls')
      );
      console.log('');

      const COL1 = 18;
      const summaryRow = (
        icon: string,
        label: string,
        count: number,
        note?: string,
        colorFn: (s: string) => string = (s) => s
      ) => {
        const countStr = colorFn(num(count));
        const noteStr = note ? chalk.dim('   ' + note) : '';
        console.log('    ' + icon + '  ' + chalk.white(label.padEnd(COL1)) + countStr + noteStr);
      };

      summaryRow(
        userApproved > 0 ? chalk.green('✅') : chalk.dim('✅'),
        'User approved',
        userApproved,
        userApproved === 0 ? 'no popups this period' : undefined,
        userApproved > 0 ? (s) => chalk.green(s) : (s) => chalk.dim(s)
      );
      summaryRow(
        userDenied > 0 ? chalk.red('🚫') : chalk.dim('🚫'),
        'User denied',
        userDenied,
        undefined,
        userDenied > 0 ? (s) => chalk.red(s) : (s) => chalk.dim(s)
      );
      summaryRow(
        timedOut > 0 ? chalk.yellow('⏱') : chalk.dim('⏱'),
        'Timed out',
        timedOut,
        timedOut > 0 ? 'no approval response' : undefined,
        timedOut > 0 ? (s) => chalk.yellow(s) : (s) => chalk.dim(s)
      );
      summaryRow(
        hardBlocked > 0 ? chalk.red('🛑') : chalk.dim('🛑'),
        'Auto-blocked',
        hardBlocked,
        undefined,
        hardBlocked > 0 ? (s) => chalk.red(s) : (s) => chalk.dim(s)
      );
      summaryRow(
        dlpBlocked > 0 ? chalk.yellow('🚨') : chalk.dim('🚨'),
        'DLP blocked',
        dlpBlocked,
        undefined,
        dlpBlocked > 0 ? (s) => chalk.yellow(s) : (s) => chalk.dim(s)
      );
      summaryRow(
        observeDlp > 0 ? chalk.blue('👁') : chalk.dim('👁'),
        'DLP (observe)',
        observeDlp,
        observeDlp > 0 ? 'would-block in strict mode' : undefined,
        observeDlp > 0 ? (s) => chalk.blue(s) : (s) => chalk.dim(s)
      );
      summaryRow(
        loopHits > 0 ? chalk.yellow('🔄') : chalk.dim('🔄'),
        'Loops detected',
        loopHits,
        undefined,
        loopHits > 0 ? (s) => chalk.yellow(s) : (s) => chalk.dim(s)
      );

      if (trendLabel || ratioLabel || testPasses + testFails > 0) {
        console.log('');
        console.log('  ' + ratioLabel + '   ' + testLabel + trendLabel);
      }
      console.log('');

      // ── Top Tools | Top Blocks ──
      const toolHeaderRaw = 'Top Tools';
      const blockHeaderRaw = 'Top Blocks';
      console.log(
        '  ' +
          chalk.bold(toolHeaderRaw) +
          ' '.repeat(COL - toolHeaderRaw.length) +
          '  ' +
          chalk.bold(blockHeaderRaw)
      );
      console.log('  ' + chalk.dim('─'.repeat(COL)) + '  ' + chalk.dim('─'.repeat(COL)));

      const rows = Math.max(topTools.length, topBlocks.length, 1);
      for (let i = 0; i < rows; i++) {
        // Left: tool — fixed layout: LABEL + BAR + space + right-aligned count
        let leftStyled = ' '.repeat(COL);
        if (i < topTools.length) {
          const [tool, { calls }] = topTools[i];
          const label = tool.length > LABEL - 1 ? tool.slice(0, LABEL - 2) + '…' : tool;
          const countStr = num(calls).padStart(TOOL_COUNT_W);
          const b = colorBar(calls, maxTool, BAR);
          const rawLen = LABEL + BAR + 1 + TOOL_COUNT_W;
          const pad = Math.max(0, COL - rawLen);
          leftStyled =
            chalk.white(label.padEnd(LABEL)) + b + ' ' + chalk.white(countStr) + ' '.repeat(pad);
        }

        // Right: block reason — fixed layout: LABEL + BAR + space + right-aligned count
        let rightStyled = '';
        if (i < topBlocks.length) {
          const [reason, count] = topBlocks[i];
          const readable = humanBlockReason(reason);
          const label = readable.length > LABEL - 1 ? readable.slice(0, LABEL - 2) + '…' : readable;
          const countStr = num(count).padStart(BLOCK_COUNT_W);
          const b = colorBar(count, maxBlock, BAR);
          rightStyled = chalk.white(label.padEnd(LABEL)) + b + ' ' + chalk.red(countStr);
        }

        console.log('  ' + leftStyled + '  ' + rightStyled);
      }

      if (topBlocks.length === 0) {
        // overwrite the last line with a "nothing blocked" note in the right col
        // (already handled by rows loop printing empty right side)
        console.log('  ' + ' '.repeat(COL) + '  ' + chalk.dim('nothing blocked ✓'));
      }

      // ── Agent breakdown ──
      if (agentMap.size >= 1) {
        console.log('');
        console.log('  ' + chalk.bold('Agents'));
        console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));
        const maxAgent = Math.max(...agentMap.values(), 1);
        for (const [agent, count] of [...agentMap.entries()].sort((a, b) => b[1] - a[1])) {
          const label = agent.slice(0, LABEL - 1);
          const b = colorBar(count, maxAgent, BAR);
          console.log('  ' + chalk.white(label.padEnd(LABEL)) + b + ' ' + chalk.white(num(count)));
        }
      }

      // ── MCP Servers ──
      if (mcpMap.size > 0) {
        console.log('');
        console.log('  ' + chalk.bold('MCP Servers'));
        console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));
        const maxMcp = Math.max(...mcpMap.values(), 1);
        for (const [server, count] of [...mcpMap.entries()].sort((a, b) => b[1] - a[1])) {
          const label = server.slice(0, LABEL - 1).padEnd(LABEL);
          const b = colorBar(count, maxMcp, BAR);
          console.log('  ' + chalk.white(label) + b + ' ' + chalk.white(num(count)));
        }
      }

      // ── Hour of Day ──
      if (hourMap.size > 0) {
        const BLOCKS = ' ▁▂▃▄▅▆▇█';
        const maxHour = Math.max(...hourMap.values(), 1);
        const bar = Array.from({ length: 24 }, (_, h) => {
          const v = hourMap.get(h) ?? 0;
          return BLOCKS[Math.round((v / maxHour) * 8)];
        }).join('');
        console.log('');
        console.log('  ' + chalk.bold('Hour of Day') + chalk.dim('  (local, 0h – 23h)'));
        console.log('  ' + chalk.cyan(bar));
        console.log('  ' + chalk.dim('0h' + ' '.repeat(10) + '12h' + ' '.repeat(7) + '23h'));
      }

      // ── Daily Activity ──
      if (dailyList.length > 1) {
        console.log('');
        console.log('  ' + chalk.bold('Daily Activity'));
        console.log('  ' + chalk.dim('─'.repeat(W - 2)));
        const DAY_BAR = Math.max(8, Math.min(30, W - 36));
        for (const [dateKey, { calls, blocked: db }] of dailyList) {
          const label = fmtDate(dateKey).padEnd(10);
          const b = colorBar(calls, maxDaily, DAY_BAR);
          const dayCost = costByDay.get(dateKey);
          const costNote = dayCost ? chalk.magenta(`  ${fmtCost(dayCost)}`) : '';
          const blockNote = db > 0 ? chalk.red(`  ${db} blocked`) : '';
          console.log(
            '  ' +
              chalk.dim(label) +
              '  ' +
              b +
              '  ' +
              chalk.white(num(calls)) +
              blockNote +
              costNote
          );
        }
      }

      // ── Tokens ──
      const totalTokens = costInputTokens + costOutputTokens + costCacheWrite + costCacheRead;
      if (totalTokens > 0) {
        const cacheHitPct =
          costInputTokens + costCacheRead > 0
            ? Math.round((costCacheRead / (costInputTokens + costCacheRead)) * 100)
            : 0;
        console.log('');
        console.log('  ' + chalk.bold('Tokens') + '  ' + chalk.dim(`${num(totalTokens)} total`));
        console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));
        const TOK_BAR = Math.max(6, Math.min(20, W - 30));
        const TOK_LABEL = 14;
        // Scale bars on non-cache tokens so cache-read (which can be 100x larger) doesn't dwarf them
        const maxNonCache = Math.max(costInputTokens, costOutputTokens, costCacheWrite, 1);
        const nonCacheRows: Array<[string, number, string]> = [
          ['Input', costInputTokens, chalk.cyan(num(costInputTokens))],
          ['Output', costOutputTokens, chalk.white(num(costOutputTokens))],
          ['Cache write', costCacheWrite, chalk.yellow(num(costCacheWrite))],
        ];
        for (const [label, count, colored] of nonCacheRows) {
          if (count === 0) continue;
          const b = colorBar(count, maxNonCache, TOK_BAR);
          console.log('  ' + chalk.white(label.padEnd(TOK_LABEL)) + b + '  ' + colored);
        }
        if (costCacheRead > 0) {
          const cacheBar = colorBar(costCacheRead, costCacheRead, TOK_BAR);
          const pct = cacheHitPct > 0 ? chalk.dim(`  ${cacheHitPct}% hit rate`) : '';
          console.log(
            '  ' +
              chalk.white('Cache read'.padEnd(TOK_LABEL)) +
              cacheBar +
              '  ' +
              chalk.green(num(costCacheRead)) +
              pct
          );
        }
      }

      // ── Cost ──
      if (costUSD > 0) {
        const periodDays = Math.max(1, Math.ceil((end.getTime() - start.getTime()) / 86400000));
        const avgPerDay = costUSD / periodDays;
        const cacheHitPct =
          costInputTokens + costCacheRead > 0
            ? Math.round((costCacheRead / (costInputTokens + costCacheRead)) * 100)
            : 0;

        const costHeaderRight = [
          chalk.yellow(fmtCost(costUSD)),
          chalk.dim(`avg ${fmtCost(avgPerDay)}/day`),
          cacheHitPct > 0 ? chalk.dim(`${cacheHitPct}% cache hit`) : null,
        ]
          .filter(Boolean)
          .join(chalk.dim('  ·  '));

        console.log('');
        console.log('  ' + chalk.bold('Cost') + '  ' + costHeaderRight);
        console.log('  ' + chalk.dim('─'.repeat(Math.min(50, W - 4))));

        if (codexCostUSD > 0)
          costByModel.set(
            'codex (openai)',
            (costByModel.get('codex (openai)') ?? 0) + codexCostUSD
          );
        const modelList = [...costByModel.entries()].sort((a, b) => b[1] - a[1]);
        const maxModelCost = Math.max(...modelList.map(([, v]) => v), 1e-9);
        const MODEL_LABEL = 22;
        const MODEL_BAR = Math.max(6, Math.min(20, W - MODEL_LABEL - 12));
        for (const [model, cost] of modelList) {
          const label =
            model.length > MODEL_LABEL - 1 ? model.slice(0, MODEL_LABEL - 2) + '…' : model;
          const b = colorBar(cost, maxModelCost, MODEL_BAR);
          console.log(
            '  ' + chalk.white(label.padEnd(MODEL_LABEL)) + b + '  ' + chalk.yellow(fmtCost(cost))
          );
        }
      }

      // ── Response DLP ──
      const responseDlpEntries = allEntries.filter((e) => {
        if (e.source !== 'response-dlp') return false;
        const ts = new Date(e.ts);
        return ts >= start && ts <= end;
      });
      if (responseDlpEntries.length > 0) {
        console.log('');
        console.log(
          '  ' +
            chalk.red.bold('⚠️  Response DLP') +
            chalk.dim('  ·  ') +
            chalk.red(
              `${responseDlpEntries.length} secret${responseDlpEntries.length !== 1 ? 's' : ''} found in Claude response text`
            )
        );
        console.log('  ' + chalk.dim('─'.repeat(Math.min(60, W - 4))));
        console.log(
          '  ' + chalk.yellow('These were NOT blocked — Claude included them in response prose.')
        );
        console.log('  ' + chalk.yellow('Rotate affected keys immediately.'));
        for (const e of responseDlpEntries.slice(0, 5)) {
          const ts = chalk.dim(fmtDate(e.ts) + '  ');
          const pattern = chalk.red((e as unknown as Record<string, string>).dlpPattern ?? 'DLP');
          const sample = chalk.gray((e as unknown as Record<string, string>).dlpSample ?? '');
          console.log(`    ${ts}${pattern}  ${sample}`);
        }
        if (responseDlpEntries.length > 5) {
          console.log(chalk.dim(`    … and ${responseDlpEntries.length - 5} more`));
        }
      }

      // ── Footer ──
      console.log('');
      console.log(
        '  ' +
          chalk.dim('node9 audit --deny') +
          chalk.dim('  ·  ') +
          chalk.dim('node9 report --period today|7d|30d|month  --no-tests')
      );
      console.log('');
    });
}
