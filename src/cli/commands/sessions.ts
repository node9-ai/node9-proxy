// src/cli/commands/sessions.ts
// Registered as `node9 sessions` by cli.ts.
//
// Shows what your AI agent did, grouped by session.
// Reads ~/.claude/history.jsonl (prompt index) and the per-session JSONL files.
// Supports list view (default) and full tool trace (--detail <session-id>).

import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HistoryEntry {
  display: string;
  timestamp: string;
  project: string; // absolute path, e.g. /home/nadav/node9
  sessionId: string;
}

export interface ToolCall {
  tool: string;
  input: Record<string, unknown>;
  timestamp: string;
}

export interface SessionSummary {
  sessionId: string;
  project: string; // absolute path
  projectLabel: string; // display label, e.g. ~/node9/node9-proxy
  firstPrompt: string;
  startTime: string; // ISO
  toolCalls: ToolCall[];
  costUSD: number;
  hasSnapshot: boolean;
  modifiedFiles: string[]; // files touched by Write/Edit tools
}

interface JournalLine {
  type: string;
  timestamp?: string;
  message?: {
    model?: string;
    content?: Array<{ type: string; name?: string; input?: Record<string, unknown> }>;
    usage?: {
      input_tokens?: number;
      output_tokens?: number;
      cache_creation_input_tokens?: number;
      cache_read_input_tokens?: number;
    };
  };
}

// ---------------------------------------------------------------------------
// Pricing (same table as scan.ts)
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

function modelPrice(model: string): { i: number; o: number; cw: number; cr: number } | null {
  const base = model.replace(/@.*$/, '').replace(/-\d{8}$/, '');
  for (const [key, p] of Object.entries(CLAUDE_PRICING)) {
    if (base === key || base.startsWith(key)) return p;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

export function encodeProjectPath(projectPath: string): string {
  // /home/nadav/node9 → -home-nadav-node9
  return projectPath.replace(/\//g, '-');
}

export function sessionJsonlPath(projectPath: string, sessionId: string): string {
  const encoded = encodeProjectPath(projectPath);
  return path.join(os.homedir(), '.claude', 'projects', encoded, `${sessionId}.jsonl`);
}

function projectLabel(projectPath: string): string {
  return projectPath.replace(os.homedir(), '~');
}

// ---------------------------------------------------------------------------
// Parsers (exported for testing)
// ---------------------------------------------------------------------------

/** Parse lines from ~/.claude/history.jsonl into HistoryEntry[].
 * Claude Code writes timestamp as Unix ms (number), so we normalise to ISO string. */
export function parseHistoryLines(lines: string[]): HistoryEntry[] {
  const entries: HistoryEntry[] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const obj = JSON.parse(line) as Record<string, unknown>;
      if (
        typeof obj['display'] === 'string' &&
        (typeof obj['timestamp'] === 'string' || typeof obj['timestamp'] === 'number') &&
        typeof obj['project'] === 'string' &&
        typeof obj['sessionId'] === 'string'
      ) {
        const ts =
          typeof obj['timestamp'] === 'number'
            ? new Date(obj['timestamp']).toISOString()
            : (obj['timestamp'] as string);
        entries.push({
          display: obj['display'] as string,
          timestamp: ts,
          project: obj['project'] as string,
          sessionId: obj['sessionId'] as string,
        });
      }
    } catch {
      // skip malformed lines
    }
  }
  return entries;
}

/** Parse lines from a session JSONL file into tool calls, cost, snapshot flag. */
export function parseSessionLines(lines: string[]): {
  toolCalls: ToolCall[];
  costUSD: number;
  hasSnapshot: boolean;
  modifiedFiles: string[];
} {
  const toolCalls: ToolCall[] = [];
  let costUSD = 0;
  let hasSnapshot = false;
  const modifiedFiles: string[] = [];
  const seenFiles = new Set<string>();

  for (const line of lines) {
    if (!line.trim()) continue;
    let entry: JournalLine;
    try {
      entry = JSON.parse(line) as JournalLine;
    } catch {
      continue;
    }

    if (entry.type === 'file-history-snapshot') {
      hasSnapshot = true;
      continue;
    }

    if (entry.type !== 'assistant') continue;

    // Accumulate cost
    const usage = entry.message?.usage;
    const model = entry.message?.model;
    if (usage && model) {
      const p = modelPrice(model);
      if (p) {
        costUSD +=
          (usage.input_tokens ?? 0) * p.i +
          (usage.output_tokens ?? 0) * p.o +
          (usage.cache_creation_input_tokens ?? 0) * p.cw +
          (usage.cache_read_input_tokens ?? 0) * p.cr;
      }
    }

    // Extract tool calls
    const content = entry.message?.content;
    if (!Array.isArray(content)) continue;

    for (const block of content) {
      if (block.type !== 'tool_use') continue;
      const tool = block.name ?? '';
      const input = block.input ?? {};
      toolCalls.push({ tool, input, timestamp: entry.timestamp ?? '' });

      // Track modified files (Write / Edit / NotebookEdit)
      const toolLower = tool.toLowerCase();
      if (toolLower === 'write' || toolLower === 'edit' || toolLower === 'notebookedit') {
        const fp = input.file_path ?? input.path;
        if (typeof fp === 'string' && !seenFiles.has(fp)) {
          seenFiles.add(fp);
          modifiedFiles.push(fp);
        }
      }
    }
  }

  return { toolCalls, costUSD, hasSnapshot, modifiedFiles };
}

// ---------------------------------------------------------------------------
// Build session summaries
// ---------------------------------------------------------------------------

export function buildSessions(days: number | null, historyPath?: string): SessionSummary[] {
  const hPath = historyPath ?? path.join(os.homedir(), '.claude', 'history.jsonl');

  let historyRaw: string;
  try {
    historyRaw = fs.readFileSync(hPath, 'utf-8');
  } catch {
    return [];
  }

  const cutoff =
    days !== null
      ? (() => {
          const d = new Date();
          d.setDate(d.getDate() - days);
          d.setHours(0, 0, 0, 0);
          return d;
        })()
      : null;

  const entries = parseHistoryLines(historyRaw.split('\n'));

  // Filter by date and deduplicate by sessionId (keep the earliest entry per session)
  const bySession = new Map<string, HistoryEntry>();
  for (const e of entries) {
    if (cutoff && new Date(e.timestamp) < cutoff) continue;
    const existing = bySession.get(e.sessionId);
    if (!existing || e.timestamp < existing.timestamp) {
      bySession.set(e.sessionId, e);
    }
  }

  const summaries: SessionSummary[] = [];

  for (const entry of bySession.values()) {
    const jsonlFile = sessionJsonlPath(entry.project, entry.sessionId);
    let sessionLines: string[] = [];
    try {
      sessionLines = fs.readFileSync(jsonlFile, 'utf-8').split('\n');
    } catch {
      // JSONL not found — still include session with empty tool calls
    }

    const { toolCalls, costUSD, hasSnapshot, modifiedFiles } = parseSessionLines(sessionLines);

    summaries.push({
      sessionId: entry.sessionId,
      project: entry.project,
      projectLabel: projectLabel(entry.project),
      firstPrompt: entry.display,
      startTime: entry.timestamp,
      toolCalls,
      costUSD,
      hasSnapshot,
      modifiedFiles,
    });
  }

  // Sort newest first
  summaries.sort((a, b) => (a.startTime > b.startTime ? -1 : 1));
  return summaries;
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

function fmtCost(usd: number): string {
  if (usd === 0) return '';
  if (usd < 0.001) return '< $0.001';
  if (usd < 1) return '$' + usd.toFixed(3);
  return '$' + usd.toFixed(2);
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  } catch {
    return iso.slice(0, 10);
  }
}

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
  } catch {
    return iso.slice(11, 16);
  }
}

function fmtDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
  } catch {
    return iso;
  }
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function toolInputSummary(tool: string, input: Record<string, unknown>): string {
  const fp = input.file_path ?? input.path;
  if (typeof fp === 'string') return fp;
  const cmd = input.command;
  if (typeof cmd === 'string') return truncate(cmd.replace(/\s+/g, ' '), 60);
  const q = input.query ?? input.url;
  if (typeof q === 'string') return truncate(String(q), 60);
  return '';
}

function toolColor(tool: string): chalk.Chalk {
  const t = tool.toLowerCase();
  if (t === 'bash' || t === 'execute_bash') return chalk.red;
  if (t === 'write') return chalk.green;
  if (t === 'edit' || t === 'notebookedit') return chalk.yellow;
  if (t === 'read') return chalk.cyan;
  return chalk.gray;
}

// ---------------------------------------------------------------------------
// Render: summary block (high-level stats)
// ---------------------------------------------------------------------------

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

function renderSummary(summaries: SessionSummary[]): void {
  const totalTools = summaries.reduce((n, s) => n + s.toolCalls.length, 0);
  const totalCost = summaries.reduce((n, s) => n + s.costUSD, 0);
  const totalFiles = summaries.reduce((n, s) => n + s.modifiedFiles.length, 0);
  const snapshots = summaries.filter((s) => s.hasSnapshot).length;
  const avgCost = summaries.length > 0 ? totalCost / summaries.length : 0;

  // Tool type breakdown
  const toolCounts = new Map<string, number>();
  for (const s of summaries) {
    for (const tc of s.toolCalls) {
      const key = tc.tool.toLowerCase();
      toolCounts.set(key, (toolCounts.get(key) ?? 0) + 1);
    }
  }

  // Normalise tool names to display groups
  const groups: Record<string, number> = { Bash: 0, Read: 0, Write: 0, Edit: 0, Other: 0 };
  for (const [tool, count] of toolCounts) {
    if (tool === 'bash' || tool === 'execute_bash') groups['Bash'] += count;
    else if (tool === 'read') groups['Read'] += count;
    else if (tool === 'write') groups['Write'] += count;
    else if (tool === 'edit' || tool === 'notebookedit') groups['Edit'] += count;
    else groups['Other'] += count;
  }

  // Project breakdown — top 3
  const projCosts = new Map<string, number>();
  for (const s of summaries) {
    projCosts.set(s.projectLabel, (projCosts.get(s.projectLabel) ?? 0) + s.costUSD);
  }
  const topProjects = [...projCosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);

  const W = 20; // bar width

  console.log(chalk.dim('  ' + '─'.repeat(70)));
  console.log(
    '  ' +
      chalk.bold.white(String(summaries.length).padEnd(4)) +
      chalk.dim('sessions    ') +
      chalk.bold.yellow(fmtCost(totalCost).padEnd(10)) +
      chalk.dim('total    ') +
      chalk.bold.white(String(totalTools).padEnd(6)) +
      chalk.dim('tool calls    ') +
      chalk.bold.white(String(totalFiles)) +
      chalk.dim(' files modified')
  );
  console.log(
    '  ' +
      chalk.dim('avg ') +
      chalk.white(fmtCost(avgCost).padEnd(10)) +
      chalk.dim('/session    ') +
      chalk.green(String(snapshots)) +
      chalk.dim(` of ${summaries.length} sessions had snapshots`)
  );
  console.log('');

  // Tool breakdown bars
  console.log('  ' + chalk.dim('Tool breakdown:'));
  const maxGroup = Math.max(...Object.values(groups));
  for (const [label, count] of Object.entries(groups)) {
    if (count === 0) continue;
    const pct = totalTools > 0 ? Math.round((count / totalTools) * 100) : 0;
    console.log(
      '    ' +
        label.padEnd(6) +
        '  ' +
        colorBar(count, maxGroup, W) +
        '  ' +
        chalk.white(String(count).padStart(4)) +
        chalk.dim(` (${String(pct)}%)`)
    );
  }
  console.log('');

  // Project cost breakdown
  if (topProjects.length > 1) {
    console.log('  ' + chalk.dim('Cost by project:'));
    const maxProjCost = topProjects[0][1];
    for (const [proj, cost] of topProjects) {
      console.log(
        '    ' +
          proj.slice(0, 28).padEnd(28) +
          '  ' +
          colorBar(cost, maxProjCost, W) +
          '  ' +
          chalk.yellow(fmtCost(cost))
      );
    }
    console.log('');
  }

  console.log(chalk.dim('  ' + '─'.repeat(70)));
  console.log('');
}

// ---------------------------------------------------------------------------
// Render: list view
// ---------------------------------------------------------------------------

function renderList(summaries: SessionSummary[], totalCost: number): void {
  if (summaries.length === 0) {
    console.log(chalk.yellow('  No sessions found in the requested range.\n'));
    return;
  }

  const totalLabel = totalCost > 0 ? chalk.dim('  ~' + fmtCost(totalCost) + ' total') : '';
  console.log(
    '  ' +
      chalk.white(String(summaries.length)) +
      chalk.dim(` session${summaries.length !== 1 ? 's' : ''}`) +
      totalLabel
  );
  console.log('');

  // Group by date + project for headers
  let lastGroup = '';
  for (const s of summaries) {
    const group = fmtDate(s.startTime) + '  ' + s.projectLabel;
    if (group !== lastGroup) {
      console.log(
        chalk.dim('  ─── ') + chalk.bold(fmtDate(s.startTime)) + chalk.dim('  ' + s.projectLabel)
      );
      lastGroup = group;
    }

    const timeStr = chalk.dim(fmtTime(s.startTime));
    const prompt = chalk.white(truncate(s.firstPrompt.replace(/\n/g, ' '), 50).padEnd(50));
    const tools =
      s.toolCalls.length > 0
        ? chalk.dim(String(s.toolCalls.length).padStart(3) + ' tools')
        : chalk.dim('  0 tools');
    const cost = s.costUSD > 0 ? chalk.dim('  ' + fmtCost(s.costUSD).padEnd(8)) : '          ';
    const snap = s.hasSnapshot ? chalk.green('  📸') : '';
    const sid = chalk.dim('  ' + s.sessionId.slice(0, 8));

    console.log(`  ${timeStr}  ${prompt}  ${tools}${cost}${snap}${sid}`);
  }
  console.log('');
  console.log(
    chalk.dim('  Run') +
      ' ' +
      chalk.cyan('node9 sessions --detail <session-id>') +
      chalk.dim(' for full tool trace.')
  );
  console.log('');
}

// ---------------------------------------------------------------------------
// Render: detail view
// ---------------------------------------------------------------------------

function renderDetail(s: SessionSummary): void {
  console.log('');
  console.log(chalk.bold('  Session  ') + chalk.dim(s.sessionId));
  console.log(
    chalk.bold('  Prompt   ') + chalk.white(s.firstPrompt.replace(/\n/g, ' ').slice(0, 120))
  );
  console.log(chalk.bold('  Project  ') + chalk.white(s.projectLabel));
  console.log(chalk.bold('  When     ') + chalk.white(fmtDateTime(s.startTime)));
  if (s.costUSD > 0)
    console.log(chalk.bold('  Cost     ') + chalk.yellow('~' + fmtCost(s.costUSD)));
  console.log(
    chalk.bold('  Snapshot ') + (s.hasSnapshot ? chalk.green('✓ taken') : chalk.dim('none'))
  );
  console.log('');

  if (s.toolCalls.length === 0) {
    console.log(chalk.dim('  No tool calls recorded.\n'));
    return;
  }

  console.log(chalk.bold(`  Tool calls (${s.toolCalls.length}):`));
  console.log('');
  for (const tc of s.toolCalls) {
    const colorFn = toolColor(tc.tool);
    const toolPad = colorFn(tc.tool.padEnd(16));
    const detail = chalk.gray(truncate(toolInputSummary(tc.tool, tc.input), 70));
    const ts = tc.timestamp ? chalk.dim(fmtTime(tc.timestamp) + '  ') : '       ';
    console.log(`    ${ts}${toolPad}  ${detail}`);
  }
  console.log('');

  if (s.modifiedFiles.length > 0) {
    console.log(chalk.bold(`  Files modified (${s.modifiedFiles.length}):`));
    for (const f of s.modifiedFiles) {
      console.log('    ' + chalk.yellow(f));
    }
    console.log('');
  }
}

// ---------------------------------------------------------------------------
// Registered command
// ---------------------------------------------------------------------------

export function registerSessionsCommand(program: Command): void {
  program
    .command('sessions')
    .description('Show what your AI agent did — sessions, tool calls, cost, and file changes')
    .option('--all', 'Show all sessions (default: last 7 days)')
    .option('--days <n>', 'Show last N days of sessions', '7')
    .option('--detail <sessionId>', 'Show full tool trace for a session')
    .action((options: { all?: boolean; days: string; detail?: string }) => {
      console.log('');
      console.log(chalk.cyan.bold('📋  node9 sessions') + chalk.dim('  — what your AI agent did'));
      console.log('');

      const historyPath = path.join(os.homedir(), '.claude', 'history.jsonl');
      if (!fs.existsSync(historyPath)) {
        console.log(chalk.yellow('  No Claude session history found at ~/.claude/history.jsonl'));
        console.log(chalk.gray('  Install Claude Code, run a few sessions, then try again.\n'));
        return;
      }

      // --detail always loads all sessions so the session-id can be found regardless of age
      const days =
        options.detail || options.all ? null : Math.max(1, parseInt(options.days, 10) || 7);
      const rangeLabel = options.detail
        ? 'all time'
        : options.all
          ? 'all time'
          : `last ${String(days)} days`;
      console.log(chalk.dim('  ' + rangeLabel));
      console.log('');

      process.stdout.write(chalk.dim('  Loading…'));
      const summaries = buildSessions(days);
      process.stdout.write('\r' + ' '.repeat(20) + '\r');

      // ── Detail view ────────────────────────────────────────────────────────
      if (options.detail) {
        const target = summaries.find(
          (s) => s.sessionId === options.detail || s.sessionId.startsWith(options.detail as string)
        );
        if (!target) {
          console.log(chalk.red(`  Session not found: ${options.detail}`));
          console.log(chalk.dim('  Run `node9 sessions` to list recent sessions.\n'));
          return;
        }
        renderDetail(target);
        return;
      }

      // ── List view ──────────────────────────────────────────────────────────
      const totalCost = summaries.reduce((sum, s) => sum + s.costUSD, 0);
      if (summaries.length > 0) renderSummary(summaries);
      renderList(summaries, totalCost);
    });
}
