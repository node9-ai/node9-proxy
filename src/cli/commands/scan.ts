// src/cli/commands/scan.ts
// Registered as `node9 scan` by cli.ts.
//
// Forecast: reads Claude JSONL history and shows what node9 would catch
// if installed. Uses the real policy engine (shields + user rules + cloud rules)
// so results are identical to live enforcement.
//
// Distinct from `node9 report`:
//   report = ongoing monitoring using audit.log (needs node9 running)
//   scan   = day-0 forecast from raw agent history (no audit.log needed)

import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { SHIELDS } from '../../shields';
import { getConfig, DEFAULT_CONFIG } from '../../config';
import {
  evaluateSmartConditions,
  matchesPattern,
  detectDangerousShellExec,
} from '../../policy/index';
import { scanArgs } from '../../dlp';
import type { SmartRule } from '../../core';
import {
  classifyRuleSeverity as engineClassifyRuleSeverity,
  narrativeRuleLabel as engineNarrativeRuleLabel,
} from '@node9/policy-engine';
import { isDaemonRunning, getInternalToken, DAEMON_PORT, DAEMON_HOST } from '../../auth/daemon';
import { isTestingMode } from '../daemon-starter';
import {
  buildScanSummary,
  type FindingRef,
  type RuleGroup,
  type ScanSummary,
} from '../../scan-summary';
import { getAgentsStatus } from '../../setup';
import { runBlast, type BlastFinding } from './blast';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type RuleSourceType = 'default' | 'shield' | 'user';

interface RuleSource {
  shieldName: string;
  shieldLabel: string;
  sourceType: RuleSourceType;
  rule: SmartRule;
}

interface Finding {
  source: RuleSource;
  toolName: string;
  input: Record<string, unknown>;
  timestamp: string;
  project: string;
  sessionId: string;
  agent: 'claude' | 'gemini' | 'codex';
}

interface DlpFinding {
  patternName: string;
  redactedSample: string;
  toolName: string;
  timestamp: string;
  project: string;
  sessionId: string;
  agent: 'claude' | 'gemini' | 'codex' | 'shell';
}

export interface LoopFinding {
  toolName: string;
  commandPreview: string;
  count: number;
  timestamp: string;
  project: string;
  sessionId: string;
  agent: 'claude' | 'gemini' | 'codex';
}

interface JournalEntry {
  type: string;
  timestamp?: string;
  message?: {
    model?: string;
    content?: Array<{
      type: string;
      id?: string;
      name?: string;
      input?: Record<string, unknown>;
      // tool_result fields (present in user-role entries)
      tool_use_id?: string;
      content?: string | Array<{ type: string; text?: string }>;
    }>;
    usage?: {
      input_tokens?: number;
      output_tokens?: number;
      cache_creation_input_tokens?: number;
      cache_read_input_tokens?: number;
    };
  };
}

export interface ScanResult {
  filesScanned: number;
  sessions: number;
  totalToolCalls: number;
  bashCalls: number;
  findings: Finding[];
  dlpFindings: DlpFinding[];
  loopFindings: LoopFinding[];
  totalCostUSD: number;
  firstDate: string | null;
  lastDate: string | null;
  sessionsWithEarlySecrets: number;
}

// ---------------------------------------------------------------------------
// Pricing (for all-time cost summary)
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
    if (base === key || base.startsWith(key)) return p;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Gemini pricing
// ---------------------------------------------------------------------------

const GEMINI_PRICING: Record<string, { i: number; o: number; cr: number }> = {
  'gemini-2.5-pro': { i: 1.25e-6, o: 10e-6, cr: 0.31e-6 },
  'gemini-2.5-flash': { i: 0.15e-6, o: 0.6e-6, cr: 0.0375e-6 },
  'gemini-2.0-flash': { i: 0.1e-6, o: 0.4e-6, cr: 0.025e-6 },
  'gemini-1.5-pro': { i: 1.25e-6, o: 5e-6, cr: 0.3125e-6 },
  'gemini-1.5-flash': { i: 0.075e-6, o: 0.3e-6, cr: 0.01875e-6 },
  'gemini-3-flash': { i: 0.1e-6, o: 0.4e-6, cr: 0.025e-6 },
};

function geminiModelPrice(model: string): { i: number; o: number; cr: number } | null {
  const base = model
    .replace(/-preview$/, '')
    .replace(/-exp$/, '')
    .replace(/-\d{4}-\d{2}-\d{2}$/, '');
  for (const [key, p] of Object.entries(GEMINI_PRICING)) {
    if (base === key || base.startsWith(key)) return p;
  }
  if (base.includes('flash')) return GEMINI_PRICING['gemini-2.0-flash']!;
  return null;
}

// ---------------------------------------------------------------------------
// Gemini session types
// ---------------------------------------------------------------------------

interface GeminiSessionFile {
  sessionId?: string;
  startTime?: string;
  messages?: Array<{
    type: string;
    timestamp?: string;
    tokens?: { input: number; output: number; cached: number };
    model?: string;
    toolCalls?: Array<{ name?: string; args?: Record<string, unknown> }>;
    content?: Array<{ text?: string }> | string;
  }>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// File extensions whose contents are skipped for DLP scanning.
// Source code files contain auth patterns (template literals, test fixtures)
// that look like secrets but are not.
const CODE_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.rb',
  '.go',
  '.rs',
  '.java',
  '.kt',
  '.swift',
  '.c',
  '.cpp',
  '.h',
  '.cs',
  '.php',
  '.sh',
  '.bash',
  '.html',
  '.css',
  '.scss',
  '.vue',
  '.svelte',
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function num(n: number): string {
  return n.toLocaleString();
}

function fmtCost(usd: number): string {
  if (usd < 0.001) return '< $0.001';
  if (usd < 1) return '$' + usd.toFixed(4);
  return '$' + usd.toFixed(2);
}

function fmtTs(ts: string): string {
  try {
    return new Date(ts).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return ts.slice(0, 10);
  }
}

// Strip ANSI escape sequences and non-printable control characters from
// strings that originated in AI session history before rendering to the
// user's terminal. A malicious AI tool input could embed `\x1b[2J` to
// clear the user's screen, OSC sequences to set fake titles, or other
// terminal-control payloads. These never carry security-relevant content
// for our display, so unconditional removal is safe and avoids the class
// entirely.
//
// Pattern matches:
//   - ESC ([\x1b]) followed by typical CSI/OSC/SS3 control sequence terminators
//   - Lone ESC bytes (defence)
//   - C0 control characters except whitespace (TAB, LF, CR are kept; the
//     subsequent whitespace collapse normalizes them)
//   - DEL (0x7f)
// eslint-disable-next-line no-control-regex
const TERMINAL_ESCAPE_RE =
  /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;

export function stripTerminalEscapes(s: string): string {
  return s.replace(TERMINAL_ESCAPE_RE, '');
}

function preview(input: Record<string, unknown>, max: number): string {
  const cmd = input.command ?? input.query ?? input.file_path ?? JSON.stringify(input);
  const s = stripTerminalEscapes(String(cmd)).replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

// ---------------------------------------------------------------------------
// Loop detection
// ---------------------------------------------------------------------------

const LOOP_TOOLS = new Set([
  'bash',
  'execute_bash',
  'exec_command',
  'shell',
  'run_shell_command',
  'write',
  'edit',
  'multiedit',
]);
const LOOP_THRESHOLD = 3;
const STUCK_TOOLS_MIN_WASTE = 5;
const STUCK_TOOLS_LIMIT = 3;

// ── DLP confidence decay tunables ────────────────────────────────────────
// A pattern is "recurring" when it appears in this many distinct sessions
// or more. Three is the smallest signal that's not a one-off.
const RECURRING_SESSION_THRESHOLD = 3;
// Findings older than this are visually dimmed (still shown, just lower
// emphasis) so users prioritize fresh secrets to rotate first.
const STALE_AGE_DAYS = 30;

export interface StuckTool {
  toolName: string;
  /** Wasted calls = sum of (count - 1) across all loop findings for this tool. */
  waste: number;
  /** Share of total wasted calls across all tools, rounded to nearest %. */
  pct: number;
}

/**
 * Aggregates loop findings by toolName to surface which tool is burning
 * the most tokens on retries. Returns the top STUCK_TOOLS_LIMIT entries
 * by waste, sorted descending. Returns [] when total waste is below
 * STUCK_TOOLS_MIN_WASTE (avoids noise on light users with 1-2 small loops).
 *
 * Pure function — testable in isolation.
 */
export function computeStuckTools(loopFindings: LoopFinding[]): StuckTool[] {
  const byTool = new Map<string, number>();
  for (const f of loopFindings) {
    const waste = Math.max(0, f.count - 1);
    if (waste === 0) continue;
    byTool.set(f.toolName, (byTool.get(f.toolName) ?? 0) + waste);
  }
  const totalWaste = [...byTool.values()].reduce((a, b) => a + b, 0);
  if (totalWaste < STUCK_TOOLS_MIN_WASTE) return [];
  return [...byTool.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, STUCK_TOOLS_LIMIT)
    .map(([toolName, waste]) => ({
      toolName,
      waste,
      pct: Math.round((waste / totalWaste) * 100),
    }));
}

/**
 * Normalizes a DLP finding's toolName field into a user-facing entry-path
 * label. The internal toolName captures where the secret was observed in
 * the agent's session — different paths suggest different mitigations:
 *
 *   tool-output   → secret came back FROM a tool (audit which tools)
 *   user-prompt   → user typed it (rotate the credential)
 *   shell-config  → in ~/.zshrc / ~/.bashrc (move to a secret manager)
 *   tool-input    → secret was passed INTO a tool (enable project-jail
 *                   shield, review which files the AI read)
 *
 * Pure function — testable in isolation.
 */
export function entryPathLabel(toolName: string): string {
  if (toolName === 'tool-result') return 'tool-output';
  if (toolName === 'user-prompt') return 'user-prompt';
  if (toolName === 'shell-config') return 'shell-config';
  return 'tool-input';
}

/**
 * Counts how many distinct sessions each DLP pattern appears in. Used by
 * isRecurringPattern to flag patterns the user keeps leaking across
 * multiple sessions — those should be at the top of their attention.
 *
 * Pure function — testable in isolation.
 */
export function buildRecurringPatternSet(
  findings: Array<{ patternName: string; sessionId: string }>
): Set<string> {
  const sessionsByPattern = new Map<string, Set<string>>();
  for (const f of findings) {
    if (!f.sessionId) continue;
    if (!sessionsByPattern.has(f.patternName)) {
      sessionsByPattern.set(f.patternName, new Set());
    }
    sessionsByPattern.get(f.patternName)!.add(f.sessionId);
  }
  const recurring = new Set<string>();
  for (const [pattern, sessions] of sessionsByPattern) {
    if (sessions.size >= RECURRING_SESSION_THRESHOLD) recurring.add(pattern);
  }
  return recurring;
}

/**
 * Returns true when the finding's timestamp is older than STALE_AGE_DAYS.
 * Defensive about parse failures: unparseable timestamps are treated as
 * non-stale so we never accidentally hide a real fresh leak.
 *
 * `now` is injected for testability.
 */
export function isStaleFinding(timestamp: string, now: number = Date.now()): boolean {
  if (!timestamp) return false;
  const t = Date.parse(timestamp);
  if (Number.isNaN(t)) return false;
  const ageDays = (now - t) / 86_400_000;
  return ageDays > STALE_AGE_DAYS;
}

/**
 * Sorts DLP findings so the most actionable ones surface first:
 *   1. Recurring patterns before one-offs
 *   2. Then non-stale before stale
 *   3. Then most recent first
 *
 * Stable: equal-priority findings preserve original order.
 */
export function sortDlpFindingsByPriority<
  T extends { patternName: string; timestamp: string; sessionId: string },
>(findings: T[], now: number = Date.now()): T[] {
  const recurring = buildRecurringPatternSet(findings);
  const indexed = findings.map((f, i) => ({ f, i }));
  indexed.sort((a, b) => {
    const aR = recurring.has(a.f.patternName);
    const bR = recurring.has(b.f.patternName);
    if (aR !== bR) return aR ? -1 : 1;
    const aS = isStaleFinding(a.f.timestamp, now);
    const bS = isStaleFinding(b.f.timestamp, now);
    if (aS !== bS) return aS ? 1 : -1;
    const aT = Date.parse(a.f.timestamp || '') || 0;
    const bT = Date.parse(b.f.timestamp || '') || 0;
    if (aT !== bT) return bT - aT;
    return a.i - b.i; // stable tie-breaker
  });
  return indexed.map(({ f }) => f);
}

function detectLoops(
  calls: Array<{ toolName: string; input: Record<string, unknown>; timestamp: string }>,
  project: string,
  sessionId: string,
  agent: 'claude' | 'gemini' | 'codex'
): LoopFinding[] {
  const counts = new Map<
    string,
    { count: number; timestamp: string; input: Record<string, unknown>; toolName: string }
  >();
  for (const call of calls) {
    const tl = call.toolName.toLowerCase();
    if (!LOOP_TOOLS.has(tl)) continue;
    const key = tl + '\0' + preview(call.input, 200);
    const entry = counts.get(key) ?? {
      count: 0,
      timestamp: call.timestamp,
      input: call.input,
      toolName: call.toolName,
    };
    entry.count++;
    counts.set(key, entry);
  }
  const findings: LoopFinding[] = [];
  for (const [, entry] of counts) {
    if (entry.count >= LOOP_THRESHOLD) {
      findings.push({
        toolName: entry.toolName,
        commandPreview: preview(entry.input, 80),
        count: entry.count,
        timestamp: entry.timestamp,
        project,
        sessionId,
        agent,
      });
    }
  }
  return findings.sort((a, b) => b.count - a.count);
}

// ---------------------------------------------------------------------------
// Build the rule set for scan
// ---------------------------------------------------------------------------

const DEFAULT_RULE_NAMES = new Set(
  DEFAULT_CONFIG.policy.smartRules.map((r) => r.name).filter(Boolean)
);

function buildRuleSources(): RuleSource[] {
  const sources: RuleSource[] = [];

  // 1. All shields (builtin + user-installed)
  for (const [shieldName, shield] of Object.entries(SHIELDS)) {
    for (const rule of shield.smartRules) {
      sources.push({ shieldName, shieldLabel: shieldName, sourceType: 'shield', rule });
    }
  }

  // 2. Default built-in rules + user custom rules + cloud rules
  try {
    const config = getConfig();
    for (const rule of config.policy.smartRules) {
      if (!rule.name) continue;
      if (rule.name.startsWith('shield:')) continue;
      const isCloud = rule.name.startsWith('cloud:');
      const isDefault = DEFAULT_RULE_NAMES.has(rule.name);
      const sourceType: RuleSourceType = isCloud ? 'user' : isDefault ? 'default' : 'user';
      sources.push({
        shieldName: isCloud ? 'cloud' : isDefault ? 'default' : 'custom',
        shieldLabel: isCloud ? 'Cloud Policy' : isDefault ? 'Default Rules' : 'Your Rules',
        sourceType,
        rule,
      });
    }
  } catch {
    // getConfig() may fail on a truly fresh install — skip user rules silently
  }

  return sources;
}

// ---------------------------------------------------------------------------
// JSONL scanner
// ---------------------------------------------------------------------------

function countScanFiles(): number {
  let total = 0;
  const claudeDir = path.join(os.homedir(), '.claude', 'projects');
  if (fs.existsSync(claudeDir)) {
    try {
      for (const proj of fs.readdirSync(claudeDir)) {
        const p = path.join(claudeDir, proj);
        try {
          if (!fs.statSync(p).isDirectory()) continue;
          total += fs
            .readdirSync(p)
            .filter((f) => f.endsWith('.jsonl') && !f.startsWith('agent-')).length;
        } catch {
          continue;
        }
      }
    } catch {
      /* ignore */
    }
  }
  const geminiDir = path.join(os.homedir(), '.gemini', 'tmp');
  if (fs.existsSync(geminiDir)) {
    try {
      for (const slug of fs.readdirSync(geminiDir)) {
        const p = path.join(geminiDir, slug);
        try {
          if (!fs.statSync(p).isDirectory()) continue;
          const chatsDir = path.join(p, 'chats');
          if (fs.existsSync(chatsDir)) {
            try {
              total += fs.readdirSync(chatsDir).filter((f) => f.endsWith('.json')).length;
            } catch {
              /* ignore */
            }
          }
        } catch {
          continue;
        }
      }
    } catch {
      /* ignore */
    }
  }
  const codexDir = path.join(os.homedir(), '.codex', 'sessions');
  if (fs.existsSync(codexDir)) {
    try {
      for (const year of fs.readdirSync(codexDir)) {
        const yp = path.join(codexDir, year);
        try {
          if (!fs.statSync(yp).isDirectory()) continue;
          for (const month of fs.readdirSync(yp)) {
            const mp = path.join(yp, month);
            try {
              if (!fs.statSync(mp).isDirectory()) continue;
              for (const day of fs.readdirSync(mp)) {
                const dp = path.join(mp, day);
                try {
                  if (!fs.statSync(dp).isDirectory()) continue;
                  total += fs.readdirSync(dp).filter((f) => f.endsWith('.jsonl')).length;
                } catch {
                  continue;
                }
              }
            } catch {
              continue;
            }
          }
        } catch {
          continue;
        }
      }
    } catch {
      /* ignore */
    }
  }
  return total;
}

function renderProgressBar(done: number, total: number, lines: number): void {
  const width = 28;
  const pct = total > 0 ? done / total : 0;
  const filled = Math.min(width, Math.round(pct * width));
  const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
  const fileLabel = total > 0 ? `${done}/${total} files` : `${done} files`;
  const lineLabel = lines > 0 ? chalk.dim(`  ${lines.toLocaleString()} lines`) : '';
  process.stdout.write(
    `\r  ${chalk.cyan('Scanning')}  [${chalk.cyan(bar)}]  ${chalk.dim(fileLabel)}${lineLabel}  `
  );
}

export function scanClaudeHistory(
  startDate: Date | null,
  onProgress?: (done: number) => void,
  onLine?: () => void
): ScanResult {
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');

  const result: ScanResult = {
    filesScanned: 0,
    sessions: 0,
    totalToolCalls: 0,
    bashCalls: 0,
    findings: [],
    dlpFindings: [],
    loopFindings: [],
    totalCostUSD: 0,
    firstDate: null,
    lastDate: null,
    sessionsWithEarlySecrets: 0,
  };

  if (!fs.existsSync(projectsDir)) return result;

  let projDirs: string[];
  try {
    projDirs = fs.readdirSync(projectsDir);
  } catch {
    return result;
  }

  const ruleSources = buildRuleSources();

  for (const proj of projDirs) {
    const projPath = path.join(projectsDir, proj);
    try {
      if (!fs.statSync(projPath).isDirectory()) continue;
    } catch {
      continue;
    }

    const projLabel = stripTerminalEscapes(
      decodeURIComponent(proj).replace(os.homedir(), '~')
    ).slice(0, 40);

    let files: string[];
    try {
      files = fs
        .readdirSync(projPath)
        .filter((f) => f.endsWith('.jsonl') && !f.startsWith('agent-'));
    } catch {
      continue;
    }

    for (const file of files) {
      result.filesScanned++;
      result.sessions++;
      onProgress?.(result.filesScanned);

      const sessionId = file.replace(/\.jsonl$/, '');

      let raw: string;
      try {
        raw = fs.readFileSync(path.join(projPath, file), 'utf-8');
      } catch {
        continue;
      }

      const sessionCalls: Array<{
        toolName: string;
        input: Record<string, unknown>;
        timestamp: string;
      }> = [];

      // Maps tool_use id → file extension so tool_result scanning can skip code files
      const toolUseFilePaths = new Map<string, string>();

      // Metric: secrets before first useful edit
      let firstDlpTs: string | null = null;
      let firstEditTs: string | null = null;

      for (const line of raw.split('\n')) {
        if (!line.trim()) continue;
        onLine?.();

        let entry: JournalEntry;
        try {
          entry = JSON.parse(line) as JournalEntry;
        } catch {
          continue;
        }

        if (entry.type !== 'assistant' && entry.type !== 'user') continue;

        // Date filter
        if (startDate && entry.timestamp) {
          if (new Date(entry.timestamp) < startDate) continue;
        }

        // Track date range
        if (entry.timestamp) {
          if (!result.firstDate || entry.timestamp < result.firstDate)
            result.firstDate = entry.timestamp;
          if (!result.lastDate || entry.timestamp > result.lastDate)
            result.lastDate = entry.timestamp;
        }

        // ── User prompt DLP scan ───────────────────────────────────────────
        if (entry.type === 'user') {
          const content = entry.message?.content;
          if (Array.isArray(content)) {
            const text = content
              .filter((b) => b.type === 'text')
              .map((b) => (b as Record<string, unknown>)['text'] ?? '')
              .join('\n');
            if (text) {
              const dlpMatch = scanArgs({ text });
              if (dlpMatch) {
                const isDupe = result.dlpFindings.some(
                  (f) =>
                    f.patternName === dlpMatch.patternName &&
                    f.redactedSample === dlpMatch.redactedSample &&
                    f.project === projLabel
                );
                if (!isDupe) {
                  result.dlpFindings.push({
                    patternName: dlpMatch.patternName,
                    redactedSample: dlpMatch.redactedSample,
                    toolName: 'user-prompt',
                    timestamp: entry.timestamp ?? '',
                    project: projLabel,
                    sessionId,
                    agent: 'claude',
                  });
                }
              }
            }

            // ── Tool result DLP scan ─────────────────────────────────────
            // Secrets that Claude read back (file contents, command output)
            // are stored in tool_result blocks inside user-role entries.
            // Skip code files — they contain auth patterns in source code
            // that are not real secrets (template literals, test fixtures, etc.)
            for (const block of content) {
              if (block.type !== 'tool_result') continue;
              const filePath = block.tool_use_id
                ? toolUseFilePaths.get(block.tool_use_id)
                : undefined;
              if (filePath) {
                const ext = path.extname(filePath).toLowerCase();
                if (CODE_EXTENSIONS.has(ext)) continue;
              }
              const resultText =
                typeof block.content === 'string'
                  ? block.content
                  : Array.isArray(block.content)
                    ? block.content.map((c) => c.text ?? '').join('\n')
                    : null;
              if (!resultText) continue;
              const dlpMatch = scanArgs({ text: resultText });
              if (dlpMatch) {
                if (firstDlpTs === null) firstDlpTs = entry.timestamp ?? null;
                const isDupe = result.dlpFindings.some(
                  (f) =>
                    f.patternName === dlpMatch.patternName &&
                    f.redactedSample === dlpMatch.redactedSample &&
                    f.project === projLabel
                );
                if (!isDupe) {
                  result.dlpFindings.push({
                    patternName: dlpMatch.patternName,
                    redactedSample: dlpMatch.redactedSample,
                    toolName: 'tool-result',
                    timestamp: entry.timestamp ?? '',
                    project: projLabel,
                    sessionId,
                    agent: 'claude',
                  });
                }
              }
            }
          }
          continue;
        }

        // Cost
        const usage = entry.message?.usage;
        const model = entry.message?.model;
        if (usage && model) {
          const p = claudeModelPrice(model);
          if (p) {
            result.totalCostUSD +=
              (usage.input_tokens ?? 0) * p.i +
              (usage.output_tokens ?? 0) * p.o +
              (usage.cache_creation_input_tokens ?? 0) * p.cw +
              (usage.cache_read_input_tokens ?? 0) * p.cr;
          }
        }

        // Tool calls
        const content = entry.message?.content;
        if (!Array.isArray(content)) continue;

        for (const block of content) {
          if (block.type !== 'tool_use') continue;
          result.totalToolCalls++;

          const toolName = block.name ?? '';
          const toolNameLower = toolName.toLowerCase();
          const input = block.input ?? {};

          // Record file path for tool_result DLP filtering
          if (block.id && typeof input.file_path === 'string') {
            toolUseFilePaths.set(block.id, input.file_path);
          }

          sessionCalls.push({ toolName, input, timestamp: entry.timestamp ?? '' });

          if (toolNameLower === 'bash' || toolNameLower === 'execute_bash') {
            result.bashCalls++;
          }

          // Track first edit/write for early-secrets metric
          if (
            firstEditTs === null &&
            (toolNameLower === 'edit' ||
              toolNameLower === 'write' ||
              toolNameLower === 'write_file' ||
              toolNameLower === 'edit_file' ||
              toolNameLower === 'multiedit')
          ) {
            firstEditTs = entry.timestamp ?? null;
          }

          // Skip node9's own read-only CLI calls
          const rawCmd = String(input.command ?? '').trimStart();
          if (/^node9\s+(scan|explain|report|tail|dlp|status|sessions|audit)\b/.test(rawCmd))
            continue;

          // ── DLP scan ───────────────────────────────────────────────────
          // Skip code files — Edit/Write pass full source in old_string/new_string
          // which contains auth patterns that are not real secrets.
          const inputFilePath = typeof input.file_path === 'string' ? input.file_path : '';
          const inputFileExt = inputFilePath ? path.extname(inputFilePath).toLowerCase() : '';
          if (CODE_EXTENSIONS.has(inputFileExt)) continue;

          const dlpMatch = scanArgs(input);
          if (dlpMatch) {
            if (firstDlpTs === null) firstDlpTs = entry.timestamp ?? null;
            const isDupe = result.dlpFindings.some(
              (f) =>
                f.patternName === dlpMatch.patternName &&
                f.redactedSample === dlpMatch.redactedSample &&
                f.project === projLabel
            );
            if (!isDupe) {
              result.dlpFindings.push({
                patternName: dlpMatch.patternName,
                redactedSample: dlpMatch.redactedSample,
                toolName,
                timestamp: entry.timestamp ?? '',
                project: projLabel,
                sessionId,
                agent: 'claude',
              });
            }
          }

          // ── Smart rule matching ────────────────────────────────────────
          let ruleMatched = false;
          for (const source of ruleSources) {
            const { rule } = source;

            if (rule.verdict === 'allow') continue;
            if (rule.tool && !matchesPattern(toolNameLower, rule.tool)) continue;
            if (!evaluateSmartConditions(input, rule)) continue;

            const inputPreview = preview(input, 120);
            const isDupe = result.findings.some(
              (f) =>
                f.source.rule.name === rule.name &&
                preview(f.input, 120) === inputPreview &&
                f.project === projLabel
            );
            if (!isDupe) {
              result.findings.push({
                source,
                toolName,
                input,
                timestamp: entry.timestamp ?? '',
                project: projLabel,
                sessionId,
                agent: 'claude',
              });
            }

            ruleMatched = true;
            break; // First matching rule wins per tool call
          }

          // ── AST shell exec detection (catches eval/bash -c with remote download)
          if (!ruleMatched && (toolNameLower === 'bash' || toolNameLower === 'execute_bash')) {
            const shellVerdict = detectDangerousShellExec(String(input.command ?? ''));
            if (shellVerdict) {
              const astRule: SmartRule = {
                name: `ast:bash-safe:${shellVerdict}-shell-exec-remote`,
                tool: 'bash',
                conditions: [],
                verdict: shellVerdict,
                reason: `Shell execution of remote download detected by AST analysis (bash-safe)`,
              };
              const inputPreview = preview(input, 120);
              const isDupe = result.findings.some(
                (f) =>
                  f.source.rule.name === astRule.name &&
                  preview(f.input, 120) === inputPreview &&
                  f.project === projLabel
              );
              if (!isDupe) {
                result.findings.push({
                  source: {
                    shieldName: 'bash-safe',
                    shieldLabel: 'bash-safe (AST)',
                    sourceType: 'shield',
                    rule: astRule,
                  },
                  toolName,
                  input,
                  timestamp: entry.timestamp ?? '',
                  project: projLabel,
                  sessionId,
                  agent: 'claude',
                });
              }
            }
          }
        }
      }
      result.loopFindings.push(...detectLoops(sessionCalls, projLabel, sessionId, 'claude'));

      // Metric 1: secret entered context before first useful edit
      if (firstDlpTs !== null && (firstEditTs === null || firstDlpTs < firstEditTs)) {
        result.sessionsWithEarlySecrets++;
      }
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Gemini history scanner
// ---------------------------------------------------------------------------

export function scanGeminiHistory(
  startDate: Date | null,
  onProgress?: (done: number) => void,
  onLine?: () => void
): ScanResult {
  const tmpDir = path.join(os.homedir(), '.gemini', 'tmp');
  const result: ScanResult = {
    filesScanned: 0,
    sessions: 0,
    totalToolCalls: 0,
    bashCalls: 0,
    findings: [],
    dlpFindings: [],
    loopFindings: [],
    totalCostUSD: 0,
    firstDate: null,
    lastDate: null,
    sessionsWithEarlySecrets: 0,
  };

  if (!fs.existsSync(tmpDir)) return result;

  let slugDirs: string[];
  try {
    slugDirs = fs.readdirSync(tmpDir);
  } catch {
    return result;
  }

  const ruleSources = buildRuleSources();

  for (const slug of slugDirs) {
    const slugPath = path.join(tmpDir, slug);
    try {
      if (!fs.statSync(slugPath).isDirectory()) continue;
    } catch {
      continue;
    }

    let projLabel = stripTerminalEscapes(slug).slice(0, 40);
    try {
      projLabel = stripTerminalEscapes(
        fs.readFileSync(path.join(slugPath, '.project_root'), 'utf-8').trim()
      )
        .replace(os.homedir(), '~')
        .slice(0, 40);
    } catch {}

    const chatsDir = path.join(slugPath, 'chats');
    if (!fs.existsSync(chatsDir)) continue;

    let chatFiles: string[];
    try {
      chatFiles = fs.readdirSync(chatsDir).filter((f) => f.endsWith('.json'));
    } catch {
      continue;
    }

    for (const chatFile of chatFiles) {
      result.filesScanned++;
      onProgress?.(result.filesScanned);

      const sessionId = chatFile.replace(/\.json$/, '');

      let raw: string;
      try {
        raw = fs.readFileSync(path.join(chatsDir, chatFile), 'utf-8');
      } catch {
        continue;
      }

      const sessionCalls: Array<{
        toolName: string;
        input: Record<string, unknown>;
        timestamp: string;
      }> = [];

      let session: GeminiSessionFile;
      try {
        session = JSON.parse(raw) as GeminiSessionFile;
      } catch {
        continue;
      }

      result.sessions++;

      for (const msg of session.messages ?? []) {
        onLine?.();
        // ── User prompt DLP scan ─────────────────────────────────────────
        if (msg.type === 'user') {
          const content = msg.content;
          const text = Array.isArray(content)
            ? content.map((c) => c.text ?? '').join('\n')
            : typeof content === 'string'
              ? content
              : '';
          if (text) {
            const dlpMatch = scanArgs({ text });
            if (dlpMatch) {
              const isDupe = result.dlpFindings.some(
                (f) =>
                  f.patternName === dlpMatch.patternName &&
                  f.redactedSample === dlpMatch.redactedSample &&
                  f.project === projLabel
              );
              if (!isDupe) {
                result.dlpFindings.push({
                  patternName: dlpMatch.patternName,
                  redactedSample: dlpMatch.redactedSample,
                  toolName: 'user-prompt',
                  timestamp: msg.timestamp ?? '',
                  project: projLabel,
                  sessionId,
                  agent: 'gemini',
                });
              }
            }
          }
          continue;
        }

        if (msg.type !== 'gemini') continue;

        if (startDate && msg.timestamp && new Date(msg.timestamp) < startDate) continue;

        if (msg.timestamp) {
          if (!result.firstDate || msg.timestamp < result.firstDate)
            result.firstDate = msg.timestamp;
          if (!result.lastDate || msg.timestamp > result.lastDate) result.lastDate = msg.timestamp;
        }

        const tokens = msg.tokens;
        const model = msg.model;
        if (tokens && model) {
          const p = geminiModelPrice(model);
          if (p) {
            const nonCached = Math.max(0, tokens.input - tokens.cached);
            result.totalCostUSD += nonCached * p.i + tokens.cached * p.cr + tokens.output * p.o;
          }
        }

        for (const tc of msg.toolCalls ?? []) {
          result.totalToolCalls++;
          const toolName = tc.name ?? '';
          const toolNameLower = toolName.toLowerCase();
          const input = tc.args ?? {};

          sessionCalls.push({ toolName, input, timestamp: msg.timestamp ?? '' });

          if (toolNameLower === 'run_shell_command' || toolNameLower === 'shell') {
            result.bashCalls++;
          }

          const rawCmd = String(input.command ?? '').trimStart();
          if (/^node9\s+(scan|explain|report|tail|dlp|status|sessions|audit)\b/.test(rawCmd))
            continue;

          const dlpMatch = scanArgs(input);
          if (dlpMatch) {
            const isDupe = result.dlpFindings.some(
              (f) =>
                f.patternName === dlpMatch.patternName &&
                f.redactedSample === dlpMatch.redactedSample &&
                f.project === projLabel
            );
            if (!isDupe) {
              result.dlpFindings.push({
                patternName: dlpMatch.patternName,
                redactedSample: dlpMatch.redactedSample,
                toolName,
                timestamp: msg.timestamp ?? '',
                project: projLabel,
                sessionId,
                agent: 'gemini',
              });
            }
          }

          let ruleMatched = false;
          for (const source of ruleSources) {
            const { rule } = source;
            if (rule.verdict === 'allow') continue;
            if (rule.tool && !matchesPattern(toolNameLower, rule.tool)) continue;
            if (!evaluateSmartConditions(input, rule)) continue;

            const inputPreview = preview(input, 120);
            const isDupe = result.findings.some(
              (f) =>
                f.source.rule.name === rule.name &&
                preview(f.input, 120) === inputPreview &&
                f.project === projLabel
            );
            if (!isDupe) {
              result.findings.push({
                source,
                toolName,
                input,
                timestamp: msg.timestamp ?? '',
                project: projLabel,
                sessionId,
                agent: 'gemini',
              });
            }
            ruleMatched = true;
            break;
          }

          // ── AST shell exec detection (catches eval/bash -c with remote download)
          const isShellTool = ['bash', 'execute_bash', 'run_shell_command', 'shell'].includes(
            toolNameLower
          );
          if (!ruleMatched && isShellTool) {
            const shellVerdict = detectDangerousShellExec(String(input.command ?? ''));
            if (shellVerdict) {
              const astRule: SmartRule = {
                name: `ast:bash-safe:${shellVerdict}-shell-exec-remote`,
                tool: 'bash',
                conditions: [],
                verdict: shellVerdict,
                reason: `Shell execution of remote download detected by AST analysis (bash-safe)`,
              };
              const inputPreview = preview(input, 120);
              const isDupe = result.findings.some(
                (f) =>
                  f.source.rule.name === astRule.name &&
                  preview(f.input, 120) === inputPreview &&
                  f.project === projLabel
              );
              if (!isDupe) {
                result.findings.push({
                  source: {
                    shieldName: 'bash-safe',
                    shieldLabel: 'bash-safe (AST)',
                    sourceType: 'shield',
                    rule: astRule,
                  },
                  toolName,
                  input,
                  timestamp: msg.timestamp ?? '',
                  project: projLabel,
                  sessionId,
                  agent: 'gemini',
                });
              }
            }
          }
        }
      }
      result.loopFindings.push(...detectLoops(sessionCalls, projLabel, sessionId, 'gemini'));
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Codex history scanner
// ---------------------------------------------------------------------------

export function scanCodexHistory(
  startDate: Date | null,
  onProgress?: (done: number) => void,
  onLine?: () => void
): ScanResult {
  const sessionsBase = path.join(os.homedir(), '.codex', 'sessions');
  const result: ScanResult = {
    filesScanned: 0,
    sessions: 0,
    totalToolCalls: 0,
    bashCalls: 0,
    findings: [],
    dlpFindings: [],
    loopFindings: [],
    totalCostUSD: 0,
    firstDate: null,
    lastDate: null,
    sessionsWithEarlySecrets: 0,
  };

  if (!fs.existsSync(sessionsBase)) return result;

  // Collect all .jsonl files under YYYY/MM/DD structure
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
    return result;
  }

  const ruleSources = buildRuleSources();

  for (const filePath of jsonlFiles) {
    result.filesScanned++;
    onProgress?.(result.filesScanned);

    let lines: string[];
    try {
      lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    } catch {
      continue;
    }

    let sessionId = '';
    let startTime = '';
    let projLabel = '';
    result.sessions++;

    const sessionCalls: Array<{
      toolName: string;
      input: Record<string, unknown>;
      timestamp: string;
    }> = [];

    // Track last cumulative token count for cost
    let lastTotalInput = 0;
    let lastTotalCached = 0;
    let lastTotalOutput = 0;

    for (const line of lines) {
      if (!line.trim()) continue;
      onLine?.();
      let entry: { type: string; timestamp?: string; payload?: Record<string, unknown> };
      try {
        entry = JSON.parse(line) as typeof entry;
      } catch {
        continue;
      }

      const payload = (entry.payload ?? {}) as Record<string, unknown>;

      if (entry.type === 'session_meta') {
        sessionId = String(payload['id'] ?? filePath);
        startTime = String(payload['timestamp'] ?? '');
        const cwd = String(payload['cwd'] ?? '');
        projLabel = stripTerminalEscapes(cwd.replace(os.homedir(), '~')).slice(0, 40);
        continue;
      }

      if (entry.type === 'event_msg' && payload['type'] === 'token_count') {
        const info = payload['info'] as Record<string, unknown> | null;
        const usage = (info?.['total_token_usage'] ?? {}) as Record<string, number>;
        lastTotalInput = usage['input_tokens'] ?? lastTotalInput;
        lastTotalCached = usage['cached_input_tokens'] ?? lastTotalCached;
        lastTotalOutput = usage['output_tokens'] ?? lastTotalOutput;
        continue;
      }

      // ── User prompt DLP scan ─────────────────────────────────────────────
      if (entry.type === 'event_msg' && payload['type'] === 'user_message') {
        const text = String(payload['message'] ?? '');
        if (text) {
          const dlpMatch = scanArgs({ text });
          if (dlpMatch) {
            const isDupe = result.dlpFindings.some(
              (f) =>
                f.patternName === dlpMatch.patternName &&
                f.redactedSample === dlpMatch.redactedSample &&
                f.project === projLabel
            );
            if (!isDupe) {
              result.dlpFindings.push({
                patternName: dlpMatch.patternName,
                redactedSample: dlpMatch.redactedSample,
                toolName: 'user-prompt',
                timestamp: entry.timestamp ?? startTime,
                project: projLabel,
                sessionId,
                agent: 'codex',
              });
            }
          }
        }
        continue;
      }

      if (entry.type !== 'response_item') continue;
      if (payload['type'] !== 'function_call') continue;

      const ts = startTime;
      if (startDate && ts && new Date(ts) < startDate) continue;

      if (ts) {
        if (!result.firstDate || ts < result.firstDate) result.firstDate = ts;
        if (!result.lastDate || ts > result.lastDate) result.lastDate = ts;
      }

      result.totalToolCalls++;
      const toolName = String(payload['name'] ?? '');
      const toolNameLower = toolName.toLowerCase();

      let input: Record<string, unknown> = {};
      try {
        input = JSON.parse(String(payload['arguments'] ?? '{}')) as Record<string, unknown>;
      } catch {}

      // Codex uses 'cmd' — normalise to 'command' so existing rules fire correctly
      if ('cmd' in input && !('command' in input)) {
        input = { ...input, command: input['cmd'] };
      }

      sessionCalls.push({ toolName, input, timestamp: ts });

      if (toolNameLower === 'exec_command' || toolNameLower === 'shell') {
        result.bashCalls++;
      }

      const rawCmd = String(input['command'] ?? '').trimStart();
      if (/^node9\s+(scan|explain|report|tail|dlp|status|sessions|audit)\b/.test(rawCmd)) continue;

      const dlpMatch = scanArgs(input);
      if (dlpMatch) {
        const isDupe = result.dlpFindings.some(
          (f) =>
            f.patternName === dlpMatch.patternName &&
            f.redactedSample === dlpMatch.redactedSample &&
            f.project === projLabel
        );
        if (!isDupe) {
          result.dlpFindings.push({
            patternName: dlpMatch.patternName,
            redactedSample: dlpMatch.redactedSample,
            toolName,
            timestamp: ts,
            project: projLabel,
            sessionId,
            agent: 'codex',
          });
        }
      }

      let ruleMatched = false;
      for (const source of ruleSources) {
        const { rule } = source;
        if (rule.verdict === 'allow') continue;
        if (
          rule.tool &&
          !matchesPattern(toolNameLower === 'exec_command' ? 'bash' : toolNameLower, rule.tool)
        )
          continue;
        if (!evaluateSmartConditions(input, rule)) continue;

        const inputPreview = preview(input, 120);
        const isDupe = result.findings.some(
          (f) =>
            f.source.rule.name === rule.name &&
            preview(f.input, 120) === inputPreview &&
            f.project === projLabel
        );
        if (!isDupe) {
          result.findings.push({
            source,
            toolName,
            input,
            timestamp: ts,
            project: projLabel,
            sessionId,
            agent: 'codex',
          });
        }
        ruleMatched = true;
        break;
      }

      if (!ruleMatched && (toolNameLower === 'exec_command' || toolNameLower === 'shell')) {
        const shellVerdict = detectDangerousShellExec(String(input['command'] ?? ''));
        if (shellVerdict) {
          const astRule: SmartRule = {
            name: `ast:bash-safe:${shellVerdict}-shell-exec-remote`,
            tool: 'bash',
            conditions: [],
            verdict: shellVerdict,
            reason: `Shell execution of remote download detected by AST analysis (bash-safe)`,
          };
          const inputPreview = preview(input, 120);
          const isDupe = result.findings.some(
            (f) =>
              f.source.rule.name === astRule.name &&
              preview(f.input, 120) === inputPreview &&
              f.project === projLabel
          );
          if (!isDupe) {
            result.findings.push({
              source: {
                shieldName: 'bash-safe',
                shieldLabel: 'bash-safe (AST)',
                sourceType: 'shield',
                rule: astRule,
              },
              toolName,
              input,
              timestamp: ts,
              project: projLabel,
              sessionId,
              agent: 'codex',
            });
          }
        }
      }
    }

    // Accumulate session cost using GPT-4o pricing as proxy for codex-1/GPT-5
    const nonCached = Math.max(0, lastTotalInput - lastTotalCached);
    result.totalCostUSD += nonCached * 5e-6 + lastTotalCached * 2.5e-6 + lastTotalOutput * 15e-6;

    result.loopFindings.push(...detectLoops(sessionCalls, projLabel, sessionId, 'codex'));
  }

  return result;
}

function scanShellConfig(): DlpFinding[] {
  const home = os.homedir();
  const configFiles = ['.zshrc', '.bashrc', '.bash_profile', '.profile'].map((f) =>
    path.join(home, f)
  );
  const findings: DlpFinding[] = [];

  for (const filePath of configFiles) {
    if (!fs.existsSync(filePath)) continue;
    let lines: string[];
    try {
      lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    } catch {
      continue;
    }
    const shortPath = filePath.replace(home, '~');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const dlpMatch = scanArgs({ text: trimmed });
      if (!dlpMatch) continue;
      const isDupe = findings.some(
        (f) =>
          f.patternName === dlpMatch.patternName &&
          f.redactedSample === dlpMatch.redactedSample &&
          f.project === shortPath
      );
      if (!isDupe) {
        findings.push({
          patternName: dlpMatch.patternName,
          redactedSample: dlpMatch.redactedSample,
          toolName: 'shell-config',
          timestamp: '',
          project: shortPath,
          sessionId: '',
          agent: 'shell',
        });
      }
    }
  }
  return findings;
}

function mergeScans(a: ScanResult, b: ScanResult): ScanResult {
  const dates = [a.firstDate, b.firstDate].filter(Boolean) as string[];
  const lastDates = [a.lastDate, b.lastDate].filter(Boolean) as string[];
  return {
    filesScanned: a.filesScanned + b.filesScanned,
    sessions: a.sessions + b.sessions,
    totalToolCalls: a.totalToolCalls + b.totalToolCalls,
    bashCalls: a.bashCalls + b.bashCalls,
    findings: [...a.findings, ...b.findings],
    dlpFindings: [...a.dlpFindings, ...b.dlpFindings],
    loopFindings: [...a.loopFindings, ...b.loopFindings],
    totalCostUSD: a.totalCostUSD + b.totalCostUSD,
    firstDate: dates.length ? dates.sort()[0] : null,
    lastDate: lastDates.length ? lastDates.sort().at(-1)! : null,
    sessionsWithEarlySecrets: a.sessionsWithEarlySecrets + b.sessionsWithEarlySecrets,
  };
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

function verdictIcon(verdict: string): string {
  return verdict === 'block' ? '🛑' : '👁 ';
}

function printFindingRow(
  f: FindingRef,
  drillDown: boolean,
  showSessionId: boolean,
  previewWidth: number
): void {
  const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
  const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
  const agentBadge =
    f.agent === 'gemini'
      ? chalk.blue('[Gemini]  ')
      : f.agent === 'codex'
        ? chalk.magenta('[Codex]   ')
        : chalk.cyan('[Claude]  ');
  // FindingRef.command is already the preview; fullCommand is the untruncated form.
  let cmdText: string;
  if (drillDown) {
    cmdText = f.fullCommand;
  } else {
    cmdText = f.command;
    if (cmdText.length > previewWidth) cmdText = cmdText.slice(0, previewWidth - 1) + '…';
  }
  const cmd = chalk.gray(cmdText);
  const sessionSuffix =
    showSessionId && f.sessionId ? chalk.dim(`  → ${f.sessionId.slice(0, 8)}`) : '';
  console.log(`      ${ts}${proj}${agentBadge}${cmd}${sessionSuffix}`);
}

function printRuleGroup(
  rule: RuleGroup,
  topN: number,
  drillDown: boolean,
  previewWidth: number
): void {
  const findings = rule.findings;
  const ruleCount = findings.length;
  const countBadge = ruleCount > 1 ? chalk.white(` ×${ruleCount}`) : '';
  const icon = verdictIcon(rule.verdict);
  console.log(
    '    ' +
      icon +
      '  ' +
      chalk.white(rule.name) +
      countBadge +
      (rule.reason ? chalk.dim(`  — ${rule.reason}`) : '')
  );

  const shown = drillDown ? findings : findings.slice(0, topN);
  for (const f of shown) {
    printFindingRow(f, drillDown, drillDown, previewWidth);
  }
  if (!drillDown && findings.length > topN) {
    console.log(
      chalk.dim(`      … and ${findings.length - topN} more  (--drill-down for full list)`)
    );
  }
}

// ---------------------------------------------------------------------------
// Compact scorecard renderer (--compact)
// ---------------------------------------------------------------------------

/**
 * Strip the verdict prefix and shield namespace from a rule name and
 * format it for display in a compact callout.
 *   "shield:k8s:block-helm-uninstall" → "helm uninstall"
 *   "block-read-aws"                  → "read aws"
 *   "review-force-push"               → "force-push"
 */
function compactRuleLabel(name: string): string {
  // Strip shield: prefix (and any nested shield label)
  let label = name.replace(/^shield:[^:]+:/, '');
  // Strip verdict prefix
  label = label.replace(/^(block|review|allow)-/, '');
  // Light cleanup — collapse double-dashes if any
  return label.replace(/-+/g, '-');
}

interface CompactInput {
  scan: ScanResult;
  summary: ScanSummary;
  blast: {
    reachable: BlastFinding[];
    envFindings: Array<{ key: string; patternName: string }>;
    score: number;
  };
  blastExposures: number;
  blockedCount: number;
  reviewCount: number;
}

function renderCompactScorecard(input: CompactInput): void {
  const { scan, summary, blast, blastExposures, blockedCount, reviewCount } = input;
  const totalRisky = scan.findings.length + scan.dlpFindings.length;

  // ── Header ────────────────────────────────────────────────────────────
  const dateRange =
    scan.firstDate && scan.lastDate ? `${fmtTs(scan.firstDate)} – ${fmtTs(scan.lastDate)}` : '';
  console.log(
    chalk.bold('🛡  Node9 Scan') +
      chalk.dim('  ·  ') +
      chalk.white(num(scan.sessions)) +
      chalk.dim(' sessions  ·  ') +
      chalk.white(num(scan.totalToolCalls)) +
      chalk.dim(' tool calls') +
      (dateRange ? chalk.dim('  ·  ' + dateRange) : '')
  );
  console.log('');

  // ── Score + risky count ──────────────────────────────────────────────
  const scoreColor = blast.score >= 80 ? chalk.green : blast.score >= 50 ? chalk.yellow : chalk.red;
  const scoreSeverity = blast.score >= 80 ? 'Good' : blast.score >= 50 ? 'At Risk' : 'Critical';
  console.log(
    chalk.bold('Security Score: ') +
      scoreColor.bold(`${blast.score}/100`) +
      chalk.dim('  ·  ') +
      scoreColor(scoreSeverity)
  );
  if (scan.totalCostUSD > 0) {
    console.log(
      chalk.bold(fmtCost(scan.totalCostUSD)) +
        chalk.dim(' AI spend  ·  ') +
        chalk.bold(`${totalRisky}`) +
        chalk.dim(` risky operation${totalRisky !== 1 ? 's' : ''}`)
    );
  }
  console.log('');

  // ── Per-category lines with callouts ─────────────────────────────────
  if (scan.dlpFindings.length > 0) {
    const patternCounts = new Map<string, number>();
    for (const f of scan.dlpFindings) {
      patternCounts.set(f.patternName, (patternCounts.get(f.patternName) ?? 0) + 1);
    }
    const topPatterns = [...patternCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([name, count]) => (count > 1 ? `${name} ×${count}` : name))
      .join(', ');
    console.log(
      chalk.red('🔑  ') +
        chalk.red.bold(String(scan.dlpFindings.length).padEnd(4)) +
        chalk.dim('credential leak'.padEnd(20)) +
        chalk.dim(`(${topPatterns})`)
    );
  }

  if (blockedCount > 0) {
    const blockedRules: Array<{ name: string; count: number }> = [];
    for (const section of summary.sections) {
      for (const rule of section.rules) {
        if (rule.verdict === 'block') {
          blockedRules.push({ name: rule.name, count: rule.findings.length });
        }
      }
    }
    const topBlocked = blockedRules
      .sort((a, b) => b.count - a.count)
      .slice(0, 3)
      .map((r) =>
        r.count > 1 ? `${compactRuleLabel(r.name)} ×${r.count}` : compactRuleLabel(r.name)
      )
      .join(', ');
    console.log(
      chalk.red('🛑  ') +
        chalk.red.bold(String(blockedCount).padEnd(4)) +
        chalk.dim('would have blocked'.padEnd(20)) +
        chalk.dim(`(${topBlocked})`)
    );
  }

  if (scan.loopFindings.length > 0) {
    const wastedCalls = scan.loopFindings.reduce((s, l) => s + Math.max(0, l.count - 1), 0);
    const wastePct =
      scan.totalToolCalls > 0 ? Math.round((wastedCalls / scan.totalToolCalls) * 100) : 0;
    const wasteParts: string[] = [];
    if (wastePct > 0) wasteParts.push(`${wastePct}% wasted`);
    if (summary.loopWastedUSD > 0) wasteParts.push('~' + fmtCost(summary.loopWastedUSD));
    const wasteSummary = wasteParts.length ? `(${wasteParts.join('  ·  ')})` : '';
    console.log(
      chalk.yellow('🔁  ') +
        chalk.yellow.bold(String(scan.loopFindings.length).padEnd(4)) +
        chalk.dim('agent loops'.padEnd(20)) +
        chalk.dim(wasteSummary)
    );
  }

  if (reviewCount > 0) {
    const reviewRules: Array<{ name: string; count: number }> = [];
    for (const section of summary.sections) {
      for (const rule of section.rules) {
        if (rule.verdict !== 'block') {
          reviewRules.push({ name: rule.name, count: rule.findings.length });
        }
      }
    }
    const topReview = reviewRules
      .sort((a, b) => b.count - a.count)
      .slice(0, 3)
      .map((r) =>
        r.count > 1 ? `${compactRuleLabel(r.name)} ×${r.count}` : compactRuleLabel(r.name)
      )
      .join(', ');
    console.log(
      chalk.yellow('👁  ') +
        chalk.yellow.bold(String(reviewCount).padEnd(4)) +
        chalk.dim('flagged for review'.padEnd(20)) +
        chalk.dim(`(${topReview})`)
    );
  }
  console.log('');

  // ── Blast radius (one-line categorical summary) ──────────────────────
  if (blastExposures > 0) {
    const categories = new Set<string>();
    for (const r of blast.reachable) {
      const lower = r.label.toLowerCase();
      if (lower.includes('ssh')) categories.add('ssh');
      else if (lower.includes('aws')) categories.add('aws');
      else if (lower.includes('gcloud') || lower.includes('gcp')) categories.add('gcp');
      else if (lower.includes('docker')) categories.add('docker');
      else if (lower.includes('netrc')) categories.add('netrc');
      else if (lower.includes('kube')) categories.add('k8s');
      else if (lower.includes('npmrc')) categories.add('npm');
      else categories.add('other');
    }
    if (blast.envFindings.length > 0) categories.add('env');
    const catList = [...categories].slice(0, 6).join(' × ');
    console.log(
      chalk.red('🔭  ') +
        chalk.dim('Blast radius'.padEnd(24)) +
        chalk.dim(`${catList} (${blastExposures} exposure${blastExposures !== 1 ? 's' : ''})`)
    );
    console.log('');
  }

  // ── CTA ──────────────────────────────────────────────────────────────
  console.log(
    chalk.dim('→  ') +
      chalk.cyan('npx node9-ai scan') +
      chalk.dim('       run this on your machine')
  );
  console.log(chalk.dim('→  github.com/node9-ai/node9-proxy'));
  console.log('');
}

// ---------------------------------------------------------------------------
// Narrative scorecard renderer (--narrative)
// ---------------------------------------------------------------------------
//
// Severity classification + friendly labels live in @node9/policy-engine
// so the SaaS Report endpoint and this CLI scorecard agree on tiering.
// Local re-aliases preserve the original names used throughout the
// renderer functions below.

const classifyRuleSeverity = engineClassifyRuleSeverity;
const narrativeRuleLabel = engineNarrativeRuleLabel;

interface BucketEntry {
  label: string;
  count: number;
}

function renderNarrativeScorecard(input: CompactInput): void {
  const { scan, summary, blast, blastExposures } = input;

  const critical: BucketEntry[] = [];
  const high: BucketEntry[] = [];
  const medium: BucketEntry[] = [];

  // ── DLP findings → critical ─────────────────────────────────────────
  if (scan.dlpFindings.length > 0) {
    const patterns = new Map<string, number>();
    for (const f of scan.dlpFindings) {
      patterns.set(f.patternName, (patterns.get(f.patternName) ?? 0) + 1);
    }
    const top = [...patterns.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([name, n]) => (n > 1 ? `${name} ×${n}` : name))
      .join(', ');
    critical.push({
      label: `${scan.dlpFindings.length} credential leak${scan.dlpFindings.length !== 1 ? 's' : ''} (${top})`,
      count: scan.dlpFindings.length,
    });
  }

  // ── Rules grouped by name → bucket per severity ─────────────────────
  for (const section of summary.sections) {
    for (const rule of section.rules) {
      const sev = classifyRuleSeverity(rule.name, rule.verdict);
      const label = narrativeRuleLabel(rule.name);
      const count = rule.findings.length;
      const display = count > 1 ? `${label} ×${count}` : label;
      const entry = { label: display, count };
      if (sev === 'critical') critical.push(entry);
      else if (sev === 'high') high.push(entry);
      else medium.push(entry);
    }
  }

  // ── Blast radius → high ─────────────────────────────────────────────
  if (blastExposures > 0) {
    high.push({
      label: `${blastExposures} credential file${blastExposures !== 1 ? 's' : ''} reachable on disk`,
      count: blastExposures,
    });
  }

  // ── Loops → medium ──────────────────────────────────────────────────
  if (scan.loopFindings.length > 0) {
    const wastedCalls = scan.loopFindings.reduce((s, l) => s + Math.max(0, l.count - 1), 0);
    const wastePct =
      scan.totalToolCalls > 0 ? Math.round((wastedCalls / scan.totalToolCalls) * 100) : 0;
    const cost = summary.loopWastedUSD > 0 ? `, ~${fmtCost(summary.loopWastedUSD)} wasted` : '';
    medium.push({
      label: `${scan.loopFindings.length} agent loops (${wastePct}% of calls${cost})`,
      count: scan.loopFindings.length,
    });
  }

  const sortByCount = (a: BucketEntry, b: BucketEntry) => b.count - a.count;
  critical.sort(sortByCount);
  high.sort(sortByCount);
  medium.sort(sortByCount);

  const criticalCount = critical.reduce((s, e) => s + e.count, 0);
  const highCount = high.reduce((s, e) => s + e.count, 0);
  const mediumCount = medium.reduce((s, e) => s + e.count, 0);

  // ── Header ─────────────────────────────────────────────────────────
  const dateRange =
    scan.firstDate && scan.lastDate ? `${fmtTs(scan.firstDate)} – ${fmtTs(scan.lastDate)}` : '';
  console.log(
    chalk.bold('🛡  Node9 Scan') +
      chalk.dim('  ·  ') +
      chalk.white(num(scan.sessions)) +
      chalk.dim(' sessions') +
      (scan.totalCostUSD > 0
        ? chalk.dim('  ·  ') + chalk.bold(fmtCost(scan.totalCostUSD)) + chalk.dim(' spend')
        : '') +
      (dateRange ? chalk.dim('  ·  ' + dateRange) : '')
  );
  console.log('');

  // ── Score ──────────────────────────────────────────────────────────
  const scoreColor = blast.score >= 80 ? chalk.green : blast.score >= 50 ? chalk.yellow : chalk.red;
  const scoreSeverity = blast.score >= 80 ? 'Good' : blast.score >= 50 ? 'At Risk' : 'Critical';
  console.log(
    (blast.score < 50 ? chalk.red.bold('⚠  ') : '') +
      chalk.bold('Security Score: ') +
      scoreColor.bold(`${blast.score}/100`) +
      chalk.dim('  ·  ') +
      scoreColor(scoreSeverity)
  );
  console.log('');

  // ── Buckets ────────────────────────────────────────────────────────
  if (criticalCount > 0) {
    console.log(
      chalk.red.bold('  🔴  CRITICAL  ') +
        chalk.red(`${criticalCount} finding${criticalCount !== 1 ? 's' : ''}`)
    );
    for (const entry of critical.slice(0, 5)) {
      console.log(chalk.dim('     • ') + chalk.red(entry.label));
    }
    if (critical.length > 5) {
      const remaining = critical.length - 5;
      console.log(chalk.dim(`     • … and ${remaining} more`));
    }
    console.log('');
  }

  if (highCount > 0) {
    console.log(
      chalk.yellow.bold('  🟡  HIGH       ') +
        chalk.yellow(`${highCount} finding${highCount !== 1 ? 's' : ''}`)
    );
    for (const entry of high.slice(0, 5)) {
      console.log(chalk.dim('     • ') + chalk.yellow(entry.label));
    }
    if (high.length > 5) {
      const remaining = high.length - 5;
      console.log(chalk.dim(`     • … and ${remaining} more`));
    }
    console.log('');
  }

  if (mediumCount > 0) {
    console.log(
      chalk.bold('  🟢  MEDIUM     ') +
        chalk.dim(`${mediumCount} finding${mediumCount !== 1 ? 's' : ''}`)
    );
    for (const entry of medium.slice(0, 5)) {
      console.log(chalk.dim('     • ') + chalk.dim(entry.label));
    }
    if (medium.length > 5) {
      const remaining = medium.length - 5;
      console.log(chalk.dim(`     • … and ${remaining} more`));
    }
    console.log('');
  }

  // ── CTA ────────────────────────────────────────────────────────────
  console.log(
    chalk.dim('→  ') +
      chalk.cyan('npx node9-ai scan') +
      chalk.dim('       run this on your machine')
  );
  console.log(chalk.dim('→  github.com/node9-ai/node9-proxy'));
  console.log('');
}

// ---------------------------------------------------------------------------
// Registered command
// ---------------------------------------------------------------------------

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Forecast: scan agent history and show what node9 would catch if installed')
    .option('--all', 'Scan all history (default: last 30 days)')
    .option('--days <n>', 'Scan last N days of history', '30')
    .option('--top <n>', 'Max findings to show per rule (default: 5)', '5')
    .option('--drill-down', 'Show all findings with full commands and session IDs')
    .option('--compact', 'Compact one-screen scorecard — for screenshots and sharing')
    .option('--narrative', 'Severity-grouped report — for video / dramatic sharing')
    .action(
      async (options: {
        all?: boolean;
        days: string;
        top: string;
        drillDown?: boolean;
        compact?: boolean;
        narrative?: boolean;
      }) => {
        const drillDown = options.drillDown ?? false;
        const topN = drillDown ? Infinity : Math.max(1, parseInt(options.top, 10) || 5);
        const previewWidth = 70;
        const startDate = options.all
          ? null
          : (() => {
              const d = new Date();
              d.setDate(d.getDate() - (parseInt(options.days, 10) || 30));
              d.setHours(0, 0, 0, 0);
              return d;
            })();

        // "Wired" = node9 hooks are actually installed in at least one agent's
        // settings file (~/.claude/settings.json, ~/.gemini/settings.json, etc.).
        // This is the real signal that future sessions are protected — checking
        // for ~/.node9/audit.log alone falsely treats npx users as installed
        // after their first run.
        const isWired = getAgentsStatus().some((a) => a.wired);

        // Compact / narrative modes print their own self-contained scorecard —
        // suppress the verbose preamble (banner + "scanning..." line) so the
        // output starts cleanly at the scorecard for screenshot / video use.
        const screenshotMode = options.compact || options.narrative;
        if (!screenshotMode) {
          console.log('');
          if (!isWired) {
            console.log(
              chalk.bold('🛡  node9') + chalk.dim('  —  security layer for AI coding agents')
            );
            console.log(
              chalk.dim('   Intercepts dangerous tool calls before they execute. No config needed.')
            );
            console.log('');
          }
          console.log(
            chalk.cyan.bold('🔍  Scanning your AI history') +
              chalk.dim('  — what would node9 have caught?')
          );
          console.log('');
        }

        const useTTY = process.stdout.isTTY === true && process.env.NODE9_WRAPPER !== '1';
        if (!useTTY && !screenshotMode) {
          process.stdout.write(
            '  ' + chalk.dim('Scanning your history — this may take a moment...\n')
          );
        }

        const totalFiles = countScanFiles();
        let filesScanned = 0;
        let linesScanned = 0;
        let lastRender = 0;
        const onProgress = (done: number) => {
          filesScanned = done;
          if (useTTY) renderProgressBar(filesScanned, totalFiles, linesScanned);
          lastRender = Date.now();
        };
        const onLine = () => {
          linesScanned++;
          const now = Date.now();
          if (useTTY && now - lastRender >= 80) {
            lastRender = now;
            renderProgressBar(filesScanned, totalFiles, linesScanned);
          }
        };
        if (useTTY) renderProgressBar(0, totalFiles, 0);
        const claudeScan = scanClaudeHistory(startDate, onProgress, onLine);
        const geminiScan = scanGeminiHistory(
          startDate,
          (done) => onProgress(claudeScan.filesScanned + done),
          onLine
        );
        const codexScan = scanCodexHistory(
          startDate,
          (done) => onProgress(claudeScan.filesScanned + geminiScan.filesScanned + done),
          onLine
        );
        const scan = mergeScans(mergeScans(claudeScan, geminiScan), codexScan);
        scan.dlpFindings.push(...scanShellConfig());
        const summary = buildScanSummary([
          { id: 'claude', label: 'Claude', icon: '🤖', scan: claudeScan },
          { id: 'gemini', label: 'Gemini', icon: '♊', scan: geminiScan },
          { id: 'codex', label: 'Codex', icon: '🔮', scan: codexScan },
        ]);
        if (useTTY) process.stdout.write('\r' + ' '.repeat(60) + '\r');

        if (scan.filesScanned === 0) {
          console.log(chalk.yellow('  No session history found.'));
          console.log(
            chalk.gray(
              '  Supported: Claude Code (~/.claude/projects/) · Gemini CLI (~/.gemini/tmp/)\n'
            )
          );
          return;
        }

        // ── Header ────────────────────────────────────────────────────────────
        const rangeLabel = options.all
          ? chalk.dim('all time')
          : chalk.dim(`last ${options.days ?? 30} days`);
        const dateRange =
          scan.firstDate && scan.lastDate
            ? chalk.dim(`  ${fmtTs(scan.firstDate)} – ${fmtTs(scan.lastDate)}`)
            : '';

        const breakdownParts: string[] = [];
        if (claudeScan.sessions > 0)
          breakdownParts.push(chalk.cyan(String(claudeScan.sessions)) + chalk.dim(' Claude'));
        if (geminiScan.sessions > 0)
          breakdownParts.push(chalk.blue(String(geminiScan.sessions)) + chalk.dim(' Gemini'));
        if (codexScan.sessions > 0)
          breakdownParts.push(chalk.magenta(String(codexScan.sessions)) + chalk.dim(' Codex'));
        const sessionBreakdown =
          breakdownParts.length > 1
            ? chalk.dim('(') + breakdownParts.join(chalk.dim(' · ')) + chalk.dim(')')
            : '';

        // Suppress in compact / narrative modes — they render their own
        // header line.
        if (!screenshotMode) {
          console.log(
            '  ' +
              chalk.white(num(scan.sessions)) +
              chalk.dim(' sessions  ') +
              sessionBreakdown +
              (sessionBreakdown ? '  ' : '') +
              chalk.white(num(scan.totalToolCalls)) +
              chalk.dim(' tool calls  ') +
              chalk.white(num(scan.bashCalls)) +
              chalk.dim(' bash commands  ') +
              rangeLabel +
              dateRange
          );
          console.log('');
        }

        // ── Group findings by sourceType + shieldName ─────────────────────────
        const totalFindings = scan.findings.length;
        const blockedCount = scan.findings.filter((f) => f.source.rule.verdict === 'block').length;
        const reviewCount = totalFindings - blockedCount;

        // Run blast scan up front so the Security Score can lead the report.
        // Used both in the top hero block and the detailed Blast Radius section
        // at the end of the output.
        const blast = runBlast();
        const blastExposures = blast.reachable.length + blast.envFindings.length;

        // ── Compact scorecard mode ──────────────────────────────────────────
        // One-screen output for sharing on Reddit / Twitter / blog posts.
        // Skips the detailed per-finding rendering — only the headline numbers,
        // top callouts per category, blast summary, and CTA.
        if (options.compact) {
          renderCompactScorecard({
            scan,
            summary,
            blast,
            blastExposures,
            blockedCount,
            reviewCount,
          });
          return;
        }

        // ── Narrative scorecard mode ───────────────────────────────────────
        // Severity-grouped report for video / dramatic sharing. Same data,
        // different organization: Critical / High / Medium tiers instead of
        // by-category. More punch for screencast use.
        if (options.narrative) {
          renderNarrativeScorecard({
            scan,
            summary,
            blast,
            blastExposures,
            blockedCount,
            reviewCount,
          });
          return;
        }

        if (totalFindings === 0 && scan.dlpFindings.length === 0) {
          console.log(chalk.green('  ✅ No risky operations found in your history.'));
          console.log(
            chalk.dim(
              '  node9 is still worth running — it monitors every tool call in real time.\n'
            )
          );
        } else {
          // ── Hero block ─────────────────────────────────────────────────────
          // Score-led headline — the dramatic line readers need to see in the
          // first 5 lines, not buried at the bottom. The detailed per-section
          // breakdowns below provide the rest.
          const totalRisky = totalFindings + scan.dlpFindings.length;
          const scoreSeverity =
            blast.score >= 80
              ? chalk.green('Good')
              : blast.score >= 50
                ? chalk.yellow('At Risk')
                : chalk.red.bold('Critical');
          const scoreColor =
            blast.score >= 80 ? chalk.green : blast.score >= 50 ? chalk.yellow : chalk.red;
          console.log(
            '  ' +
              (blast.score < 50 ? chalk.red.bold('⚠  ') : '') +
              chalk.bold('Security Score ') +
              scoreColor.bold(`${blast.score}/100`) +
              '  ' +
              scoreSeverity +
              chalk.dim('  ·  ') +
              (totalRisky > 0
                ? chalk.red.bold(`${totalRisky} risky operation${totalRisky !== 1 ? 's' : ''}`)
                : chalk.green('No risky operations'))
          );

          // ── Compact stat card — one line, scannable ────────────────────────
          const cardParts: string[] = [];
          if (scan.dlpFindings.length > 0) {
            cardParts.push(
              chalk.red('🔑 ') +
                chalk.red.bold(String(scan.dlpFindings.length)) +
                chalk.dim(` leak${scan.dlpFindings.length !== 1 ? 's' : ''}`)
            );
          }
          if (blockedCount > 0) {
            cardParts.push(
              chalk.red('🛑 ') + chalk.red.bold(String(blockedCount)) + chalk.dim(' blocked')
            );
          }
          if (scan.loopFindings.length > 0) {
            const wastedCalls = scan.loopFindings.reduce((s, l) => s + Math.max(0, l.count - 1), 0);
            const wastePct =
              scan.totalToolCalls > 0 ? Math.round((wastedCalls / scan.totalToolCalls) * 100) : 0;
            const wasteSuffix = wastePct > 0 ? chalk.dim(` (${wastePct}% wasted)`) : '';
            cardParts.push(
              chalk.yellow('🔁 ') +
                chalk.yellow.bold(String(scan.loopFindings.length)) +
                chalk.dim(' loops') +
                wasteSuffix
            );
          }
          if (reviewCount > 0) {
            cardParts.push(
              chalk.yellow('👁 ') + chalk.yellow.bold(String(reviewCount)) + chalk.dim(' flagged')
            );
          }
          if (blastExposures > 0) {
            cardParts.push(
              chalk.red('🔭 ') + chalk.red.bold(String(blastExposures)) + chalk.dim(' exposures')
            );
          }
          if (cardParts.length > 0) {
            console.log('  ' + cardParts.join(chalk.dim('   ')));
          }

          // Spend summary on its own line — useful for power users, not the
          // headline. (The score + count above is the hook.)
          if (scan.totalCostUSD > 0) {
            console.log(
              '  ' +
                chalk.dim('AI spend  ') +
                chalk.bold(fmtCost(scan.totalCostUSD)) +
                (summary.loopWastedUSD > 0
                  ? chalk.dim('   ·   wasted on loops  ') +
                    chalk.yellow('~' + fmtCost(summary.loopWastedUSD))
                  : '')
            );
          }
          if (scan.dlpFindings.length > 0 && scan.sessionsWithEarlySecrets > 0) {
            console.log(
              '  ' +
                chalk.dim(
                  `${scan.sessionsWithEarlySecrets} session${scan.sessionsWithEarlySecrets !== 1 ? 's' : ''} loaded secrets before first edit`
                )
            );
          }
          console.log('');

          // ── Credential Leaks — first, most alarming ───────────────────────
          if (scan.dlpFindings.length > 0) {
            console.log('  ' + chalk.dim('─'.repeat(70)));
            console.log(
              '  ' +
                chalk.red.bold('🔑  Credential Leaks') +
                chalk.dim('  ·  ') +
                chalk.red(
                  `${num(scan.dlpFindings.length)} secret${scan.dlpFindings.length !== 1 ? 's' : ''} found in plain text`
                )
            );
            // Confidence decay: surface recurring patterns + recent findings
            // first, dim stale ones. Same data, just re-prioritized.
            const sortedDlp = sortDlpFindingsByPriority(scan.dlpFindings);
            const recurringPatterns = buildRecurringPatternSet(scan.dlpFindings);
            const shownDlp = drillDown ? sortedDlp : sortedDlp.slice(0, topN);
            for (const f of shownDlp) {
              const stale = isStaleFinding(f.timestamp);
              const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
              const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
              const agentBadge =
                f.agent === 'gemini'
                  ? chalk.blue('[Gemini]  ')
                  : f.agent === 'codex'
                    ? chalk.magenta('[Codex]   ')
                    : f.agent === 'shell'
                      ? chalk.yellow('[Shell]   ')
                      : chalk.cyan('[Claude]  ');
              const sessionSuffix = f.sessionId ? chalk.dim(`  → ${f.sessionId.slice(0, 8)}`) : '';
              const recurringBadge = recurringPatterns.has(f.patternName)
                ? chalk.red.bold(' ⚠️ recurring ')
                : '';
              const patternDisplay = stale ? chalk.dim(f.patternName) : chalk.yellow(f.patternName);
              const sampleDisplay = stale
                ? chalk.dim(f.redactedSample)
                : chalk.gray(f.redactedSample);
              const entryBadge = chalk.dim(`  [${entryPathLabel(f.toolName)}]`);
              const leadIcon = stale ? chalk.dim('🚨') : '🚨';
              console.log(
                `    ${leadIcon} ${ts}${proj}${agentBadge}` +
                  patternDisplay +
                  recurringBadge +
                  chalk.dim('  ') +
                  sampleDisplay +
                  entryBadge +
                  sessionSuffix
              );
            }
            if (!drillDown && scan.dlpFindings.length > topN) {
              console.log(
                chalk.dim(
                  `    … and ${scan.dlpFindings.length - topN} more  (--drill-down for full list)`
                )
              );
            }
            console.log('');
          }

          // ── Blocked operations — consolidated across all rule sources ─────
          const blockedRuleSections = summary.sections
            .map((s) => ({ ...s, rules: s.rules.filter((r) => r.verdict === 'block') }))
            .filter((s) => s.rules.length > 0);
          if (blockedRuleSections.length > 0) {
            console.log('  ' + chalk.dim('─'.repeat(70)));
            console.log(
              '  ' +
                chalk.red.bold('🛑  Blocked') +
                chalk.dim('  ·  ') +
                chalk.red(
                  `${blockedCount} operation${blockedCount !== 1 ? 's' : ''} node9 would have stopped`
                )
            );
            for (const section of blockedRuleSections) {
              for (const rule of section.rules) {
                printRuleGroup(rule, topN, drillDown, previewWidth);
              }
            }
            console.log('');
          }

          // ── Agent Loops ────────────────────────────────────────────────────
          if (scan.loopFindings.length > 0) {
            console.log('  ' + chalk.dim('─'.repeat(70)));
            const loopCostLabel =
              summary.loopWastedUSD > 0
                ? chalk.dim('  ·  ') +
                  chalk.yellow('~' + fmtCost(summary.loopWastedUSD) + ' wasted')
                : '';
            console.log(
              '  ' +
                chalk.yellow.bold('🔁  Agent Loops') +
                chalk.dim('  ·  ') +
                chalk.yellow(
                  `${num(scan.loopFindings.length)} repeated pattern${scan.loopFindings.length !== 1 ? 's' : ''} found`
                ) +
                loopCostLabel
            );
            const shownLoops = drillDown ? scan.loopFindings : scan.loopFindings.slice(0, topN);
            for (const f of shownLoops) {
              const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
              const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
              const agentBadge =
                f.agent === 'gemini'
                  ? chalk.blue('[Gemini]  ')
                  : f.agent === 'codex'
                    ? chalk.magenta('[Codex]   ')
                    : chalk.cyan('[Claude]  ');
              const sessionSuffix = f.sessionId ? chalk.dim(`  → ${f.sessionId.slice(0, 8)}`) : '';
              console.log(
                `    ${ts}${proj}${agentBadge}` +
                  chalk.yellow(f.toolName) +
                  chalk.dim(`  ×${f.count}  `) +
                  chalk.gray(f.commandPreview) +
                  sessionSuffix
              );
            }
            if (!drillDown && scan.loopFindings.length > topN) {
              console.log(
                chalk.dim(
                  `    … and ${scan.loopFindings.length - topN} more  (--drill-down for full list)`
                )
              );
            }

            // ── Most stuck tools (top 3 by wasted-call share) ──────────────
            // Aggregate wasted calls (count - 1 per finding) by toolName, so
            // a heavy user can see at a glance which tool is burning their
            // tokens. Hidden when total waste is trivial (<5) to avoid noise.
            const stuckTools = computeStuckTools(scan.loopFindings);
            if (stuckTools.length > 0) {
              console.log('');
              console.log('  ' + chalk.dim('Most stuck tools:'));
              for (const t of stuckTools) {
                console.log(
                  chalk.dim('    ') +
                    chalk.yellow(t.toolName.padEnd(8)) +
                    chalk.dim('  ') +
                    chalk.dim(`×${t.waste} repeats`.padEnd(14)) +
                    chalk.dim(`  (${t.pct}%)`)
                );
              }
            }

            console.log('');
          }

          // ── Flagged for review — review-verdict rules only ─────────────────
          for (const section of summary.sections) {
            const reviewRules = section.rules.filter((r) => r.verdict !== 'block');
            if (reviewRules.length === 0) continue;
            const enableHint = section.shieldKey
              ? chalk.dim(`  →  node9 shield enable ${section.shieldKey}`)
              : '';
            console.log('  ' + chalk.dim('─'.repeat(70)));
            console.log(
              '  ' +
                chalk.bold(section.label) +
                (section.subtitle ? chalk.dim(`  ·  ${section.subtitle}`) : '') +
                '  ' +
                chalk.yellow(`${section.reviewCount} review`) +
                enableHint
            );
            for (const rule of reviewRules) {
              printRuleGroup(rule, topN, drillDown, previewWidth);
            }
            console.log('');
          }

          // ── Inactive Shields — upsell, always last ─────────────────────────
          const activeShieldIds = new Set(
            summary.sections
              .filter((s) => s.sourceType === 'shield' && s.shieldKey)
              .map((s) => s.shieldKey!)
          );
          const emptyShields = Object.keys(SHIELDS)
            .filter((n) => !activeShieldIds.has(n))
            .sort();
          if (emptyShields.length > 0) {
            console.log('  ' + chalk.dim('─'.repeat(70)));
            console.log(
              '  ' + chalk.bold('🛡  Inactive Shields') + chalk.dim('  ·  enable for more coverage')
            );
            console.log('  ' + chalk.dim(emptyShields.join(' · ')));
            console.log('  ' + chalk.dim('→  node9 shield enable <name>  to activate'));
            console.log('');
          }
        }

        // ── Blast Radius detail ───────────────────────────────────────────────
        // Note: Security Score itself is shown in the hero block at the top.
        // This section is the per-file detail of what's exposed.
        if (blast.reachable.length > 0 || blast.envFindings.length > 0) {
          console.log('  ' + chalk.dim('─'.repeat(70)));
          console.log(
            '  ' +
              chalk.bold('🔭  Blast Radius') +
              chalk.dim(
                `  ·  ${blastExposures} exposure${blastExposures !== 1 ? 's' : ''} an AI agent can reach right now`
              )
          );
          console.log('');
          if (blast.reachable.length > 0) {
            for (const p of blast.reachable) {
              console.log(
                '    ' +
                  chalk.red('✗  ') +
                  chalk.yellow(p.label.padEnd(38)) +
                  chalk.dim(p.description)
              );
            }
          }
          if (blast.envFindings.length > 0) {
            for (const f of blast.envFindings) {
              console.log(
                '    ' +
                  chalk.red('✗  ') +
                  chalk.yellow(f.key.padEnd(38)) +
                  chalk.dim(f.patternName + ' in environment')
              );
            }
          }
          console.log('');
          console.log(
            chalk.dim(
              '  → Run `node9 shield enable project-jail` to block agent access to these files.'
            )
          );
          console.log('');
        }

        // ── CTA ───────────────────────────────────────────────────────────────
        if (isWired) {
          console.log(chalk.green('  ✅ node9 is active — your future sessions are protected.'));
          console.log(
            chalk.dim('  Run ') +
              chalk.cyan('node9 report') +
              chalk.dim(' to see live protection stats.')
          );
          if (drillDown) {
            console.log(
              chalk.dim('  Run ') +
                chalk.cyan('node9 sessions --detail <session-id>') +
                chalk.dim(' to see the full conversation for any session above.')
            );
          } else {
            console.log(
              chalk.dim('  Run ') +
                chalk.cyan('node9 scan --drill-down') +
                chalk.dim(' to see full commands and session IDs.')
            );
          }
        } else {
          const riskySummary = totalFindings + scan.dlpFindings.length;
          if (riskySummary > 0) {
            console.log(
              chalk.yellow.bold(
                `  ⚡ ${riskySummary} operation${riskySummary !== 1 ? 's' : ''} ran unprotected.`
              ) + chalk.dim(' node9 would have caught them.')
            );
            console.log('');
          }
          console.log(chalk.bold('  Enable real-time protection:'));
          console.log('');
          console.log(
            '    ' +
              chalk.cyan('npm install -g @node9/proxy') +
              chalk.dim('  &&  ') +
              chalk.cyan('node9 init --recommended')
          );
          console.log('');
          console.log(
            chalk.dim(
              '  Hooks into Claude Code automatically. Every tool call checked before it runs.'
            )
          );
          console.log('  ' + chalk.dim('→ ') + chalk.underline('https://node9.ai'));
        }
        console.log('');

        if (!isTestingMode()) {
          if (isWired) {
            const url = `http://${DAEMON_HOST}:${DAEMON_PORT}/?openscan=1`;
            if (isDaemonRunning()) {
              const internalToken = getInternalToken();
              if (internalToken) {
                try {
                  const pushSummary = buildScanSummary([
                    { id: 'claude', label: 'Claude', icon: '🤖', scan: claudeScan },
                    { id: 'gemini', label: 'Gemini', icon: '♊', scan: geminiScan },
                    { id: 'codex', label: 'Codex', icon: '🔮', scan: codexScan },
                  ]);
                  await fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/scan/push`, {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      'x-node9-internal': internalToken,
                    },
                    body: JSON.stringify({ status: 'complete', summary: pushSummary }),
                    signal: AbortSignal.timeout(3000),
                  });
                  // Note: no longer auto-opens the browser. The terminal scan
                  // output is the canonical artifact; users who want the
                  // browser dashboard can run `node9 daemon start --openui`.
                } catch {
                  // fire-and-forget
                }
              }
            }
            if (isDaemonRunning()) {
              console.log('  ' + chalk.cyan('🌐 View in browser:') + '  ' + chalk.underline(url));
            } else {
              console.log(
                '  ' +
                  chalk.dim('📊 To view in browser, start the daemon:  ') +
                  chalk.cyan('node9 daemon --background')
              );
            }
            console.log('');
          }
          // When not wired, the install CTA above is the next step — no browser hint.
        }
      }
    );
}
