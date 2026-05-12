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
import { DEFAULT_CONFIG } from '../../config';
import {
  evaluateSmartConditions,
  matchesPattern,
  detectDangerousShellExec,
} from '../../policy/index';
import { analyzeFsOperation, AST_FS_REGEX_RULES } from '@node9/policy-engine';
import { scanArgs } from '../../dlp';
import type { SmartRule } from '../../core';
import {
  classifyRuleSeverity as engineClassifyRuleSeverity,
  narrativeRuleLabel as engineNarrativeRuleLabel,
} from '@node9/policy-engine';
// isDaemonRunning / getInternalToken / DAEMON_PORT / DAEMON_HOST /
// isTestingMode imports removed — only used by the browser auto-push
// scan flow (retired v3).
import {
  buildScanSummary,
  type FindingRef,
  type RuleGroup,
  type ScanSummary,
} from '../../scan-summary';
import { getAgentsStatus } from '../../setup';
import { runBlast, type BlastFinding } from './blast';
import {
  boxPanel,
  classifyScore,
  computeLoopWaste,
  relativeDate,
  rollupByShield,
  topDlpPatterns,
  topRulesByVerdict,
} from '../render/scan-derive';
import { PROTECTIVE_SHIELD_DISCOUNTS } from '../../protection';
import stringWidth from 'string-width';
import { buildScanJson } from '../render/scan-json';
import {
  appendScanHistory,
  computeScanDelta,
  readPreviousScan,
  type ScanHistoryRecord,
} from '../render/scan-history';

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
  /**
   * Distinguishes a true cyclic agent loop (`'loop'`) from sustained iteration
   * on the same target across a session (`'long-iteration'`).
   *
   * Heuristic: time span between the first and last call in the group.
   *   - < LOOP_TIMESPAN_THRESHOLD_MS  → 'loop' (bursty, agent stuck)
   *   - ≥ LOOP_TIMESPAN_THRESHOLD_MS  → 'long-iteration' (deep work, not waste)
   *
   * Only `'loop'` findings count toward the wasted-spend total. Long iteration
   * shows up in a separate "high-iteration files" bucket so deep work isn't
   * framed as money burned.
   *
   * Optional for backwards compatibility; missing implies 'loop' (legacy data).
   */
  kind?: 'loop' | 'long-iteration';
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

// Node9 emits its own DLP verdicts in this struct shape (live block alerts and
// scanArgs() return values). When a tool_result block contains both a token and
// node9's own output schema, the token is virtually always test/debug input the
// user fed into the engine — not a real exfiltration. Skipping these prevents
// node9 from re-detecting its own redactor output weeks later in scan reports.
const SELF_OUTPUT_MARKERS = [
  /redactedSample:\s*['"]/,
  /patternName:\s*['"]/,
  /\bseverity:\s*['"](?:block|review|allow)['"]/,
  /NODE9 SECURITY ALERT/,
];

export function isNode9SelfOutput(text: string): boolean {
  // Two or more markers in a single tool_result block is high-confidence
  // node9 self-output. One marker alone could be coincidence (e.g. a docs
  // grep). Two together (patternName + redactedSample, etc.) is essentially
  // unique to node9's emit format.
  let hits = 0;
  for (const re of SELF_OUTPUT_MARKERS) {
    if (re.test(text)) hits++;
    if (hits >= 2) return true;
  }
  return false;
}

// Token shapes that are clearly test/example fixtures rather than real secrets.
// These appear in tutorials, regex docs, gitleaks rules, and node9's own debug
// scripts. Demoting them to skip avoids polluting credential-leak counts.
const FIXTURE_TOKEN_PATTERNS: RegExp[] = [
  /(.)\1{5,}/, // 6+ repeated characters (aaaaaa, 000000)
  /(?:EXAMPLE|FAKE|DUMMY|PLACEHOLDER|XXXXX)/i,
  /abcdefghijklmn/i, // long alpha sequence — fixture, not entropy
  /1234567890/, // long digit sequence — fixture, not entropy
  /qwerty/i,
];

export function looksLikeFixtureToken(sample: string): boolean {
  for (const re of FIXTURE_TOKEN_PATTERNS) {
    if (re.test(sample)) return true;
  }
  return false;
}

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
// Time span between first and last call in a group above which we classify as
// "long iteration" (sustained deep work) rather than "agent loop" (bursty stuck
// behavior). 10 minutes is empirically chosen: real agent loops typically
// resolve in seconds-to-minutes, while iteration on a feature spans hours.
const LOOP_TIMESPAN_THRESHOLD_MS = 10 * 60 * 1000;
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

// AST_FS_REGEX_RULES lives in @node9/policy-engine so the live hook and the
// CLI scan share one source of truth (see shell/index.ts).

/**
 * Run analyzeFsOperation on a bash command and, if it returns a verdict,
 * append a synthetic finding to `result.findings`. Returns true when a
 * verdict was emitted (so the caller can mark the call ruleMatched).
 *
 * Used by all three agent scan paths (claude/gemini/codex) so the AST-based
 * fs-op rules fire identically regardless of which agent emitted the call.
 */
/**
 * Per-walker dedup index. The walkers used to call result.findings.some(...)
 * and result.dlpFindings.some(...) inside their per-line loops to suppress
 * duplicate entries — a linear scan that grew O(N) with every emit. With
 * 5 k-10 k findings across a busy ~/.claude/projects, the per-line cost
 * climbed to ~O(N²) and the [2] view took minutes to populate.
 *
 * Replaced with two String Sets keyed by the same tuple the .some()
 * callbacks compared on (rule.name|preview|project for findings; pattern|
 * sample|project for DLP). Set.has is O(1); the walk is now linear in the
 * number of input entries instead of quadratic in the output size.
 */
interface ScanDedup {
  findingsKeys: Set<string>;
  dlpKeys: Set<string>;
}

function emptyScanDedup(): ScanDedup {
  return { findingsKeys: new Set(), dlpKeys: new Set() };
}

function findingKey(ruleName: string | undefined, inputPreview: string, projLabel: string): string {
  return `${ruleName ?? '<unnamed>'}|${inputPreview}|${projLabel}`;
}

function dlpKey(patternName: string, redactedSample: string, projLabel: string): string {
  return `${patternName}|${redactedSample}|${projLabel}`;
}

function pushFsOpAstFinding(
  command: string,
  toolName: string,
  input: Record<string, unknown>,
  timestamp: string,
  projLabel: string,
  sessionId: string,
  agent: 'claude' | 'gemini' | 'codex',
  result: ScanResult,
  dedup: ScanDedup
): boolean {
  const fsVerdict = analyzeFsOperation(command);
  if (!fsVerdict) return false;
  const synthRule: SmartRule = {
    name: fsVerdict.ruleName,
    tool: 'bash',
    conditions: [],
    verdict: fsVerdict.verdict,
    reason: fsVerdict.reason,
  };
  const isShieldRule = fsVerdict.ruleName.startsWith('shield:');
  const synthSource = isShieldRule
    ? {
        shieldName: 'project-jail',
        shieldLabel: 'project-jail (AST)',
        sourceType: 'shield' as const,
        rule: synthRule,
      }
    : {
        shieldName: '',
        shieldLabel: 'default (AST)',
        sourceType: 'default' as const,
        rule: synthRule,
      };
  const inputPreview = preview(input, 120);
  const k = findingKey(synthRule.name, inputPreview, projLabel);
  if (!dedup.findingsKeys.has(k)) {
    dedup.findingsKeys.add(k);
    result.findings.push({
      source: synthSource,
      toolName,
      input,
      timestamp,
      project: projLabel,
      sessionId,
      agent,
    });
  }
  return true;
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

export function detectLoops(
  calls: Array<{ toolName: string; input: Record<string, unknown>; timestamp: string }>,
  project: string,
  sessionId: string,
  agent: 'claude' | 'gemini' | 'codex'
): LoopFinding[] {
  const counts = new Map<
    string,
    {
      count: number;
      timestamp: string;
      firstTs: number | null;
      lastTs: number | null;
      input: Record<string, unknown>;
      toolName: string;
    }
  >();
  for (const call of calls) {
    const tl = call.toolName.toLowerCase();
    if (!LOOP_TOOLS.has(tl)) continue;
    const key = tl + '\0' + preview(call.input, 200);
    const entry = counts.get(key) ?? {
      count: 0,
      timestamp: call.timestamp,
      firstTs: null,
      lastTs: null,
      input: call.input,
      toolName: call.toolName,
    };
    entry.count++;
    const t = call.timestamp ? Date.parse(call.timestamp) : NaN;
    if (!Number.isNaN(t)) {
      if (entry.firstTs === null || t < entry.firstTs) entry.firstTs = t;
      if (entry.lastTs === null || t > entry.lastTs) entry.lastTs = t;
    }
    counts.set(key, entry);
  }
  const findings: LoopFinding[] = [];
  for (const [, entry] of counts) {
    if (entry.count >= LOOP_THRESHOLD) {
      const span =
        entry.firstTs !== null && entry.lastTs !== null ? entry.lastTs - entry.firstTs : 0;
      const kind: 'loop' | 'long-iteration' =
        span >= LOOP_TIMESPAN_THRESHOLD_MS ? 'long-iteration' : 'loop';
      findings.push({
        toolName: entry.toolName,
        commandPreview: preview(entry.input, 80),
        count: entry.count,
        timestamp: entry.timestamp,
        project,
        sessionId,
        agent,
        kind,
      });
    }
  }
  return findings.sort((a, b) => b.count - a.count);
}

// ---------------------------------------------------------------------------
// Build the rule set for scan
// ---------------------------------------------------------------------------

export function buildRuleSources(): RuleSource[] {
  const sources: RuleSource[] = [];

  // 1. All shields (builtin + user-installed)
  for (const [shieldName, shield] of Object.entries(SHIELDS)) {
    for (const rule of shield.smartRules) {
      sources.push({ shieldName, shieldLabel: shieldName, sourceType: 'shield', rule });
    }
  }

  // 2. Default built-in rules only — sourced directly from DEFAULT_CONFIG.
  //
  // Scan is a pre-install forecast: it answers "what would node9 catch
  // if you installed it with default protection?". Two consequences:
  //
  // 1. User-custom rules from node9.config.json and cloud-synced rules
  //    are skipped entirely. A fresh user doesn't have those, so
  //    surfacing them would misrepresent what node9 itself catches.
  // 2. Defaults are loaded from DEFAULT_CONFIG directly, not from the
  //    user-merged getConfig() result. Otherwise a user who modified
  //    a default rule (different verdict, extra condition) would see
  //    their MODIFIED version fired against history — not the canonical
  //    default. Forecast must reflect the out-of-the-box defaults.
  //
  // Installed users who want to see their OWN rule fires (including
  // customized defaults) use `node9 report`, which reads the audit log.
  //
  // (Decision locked 2026-05-12 — see scan-redesign discussion.)
  for (const rule of DEFAULT_CONFIG.policy.smartRules) {
    if (!rule.name) continue;
    if (rule.name.startsWith('shield:')) continue;
    sources.push({
      shieldName: 'default',
      shieldLabel: 'Default Rules',
      sourceType: 'default',
      rule,
    });
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

/**
 * Per-project body of scanClaudeHistory, extracted so both the sync walker
 * (used by `node9 scan` CLI) and the async chunked variant (used by the
 * dashboard's startScanWalk) can share identical logic. Mutates `result`.
 *
 * The three early-returns mirror the original outer-loop `continue`s:
 * not-a-directory, stat failure, and readdir failure all skip the project
 * silently — same forgiving behavior the CLI has shipped with for months.
 */
/**
 * Per-file body of the Claude scan walker. Extracted so both the sync
 * processClaudeProject and the async processClaudeProjectAsync can share
 * the actual analysis work — the only difference between them is whether
 * they yield to the event loop between files.
 *
 * Yielding per file (instead of per project) drops the q-quit lag during
 * an in-flight [2] walk from ~1 s (one project of work) to ~10-30 ms
 * (one file of work).
 */
function processClaudeFile(
  file: string,
  projPath: string,
  projLabel: string,
  ruleSources: RuleSource[],
  startDate: Date | null,
  result: ScanResult,
  dedup: ScanDedup,
  onProgress?: (done: number) => void,
  onLine?: () => void
): void {
  result.filesScanned++;
  result.sessions++;
  onProgress?.(result.filesScanned);

  const sessionId = file.replace(/\.jsonl$/, '');

  let raw: string;
  try {
    raw = fs.readFileSync(path.join(projPath, file), 'utf-8');
  } catch {
    return;
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
      if (!result.lastDate || entry.timestamp > result.lastDate) result.lastDate = entry.timestamp;
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
            const k = dlpKey(dlpMatch.patternName, dlpMatch.redactedSample, projLabel);
            if (!dedup.dlpKeys.has(k)) {
              dedup.dlpKeys.add(k);
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
          const filePath = block.tool_use_id ? toolUseFilePaths.get(block.tool_use_id) : undefined;
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
          // Skip tool_result blocks that are clearly node9's own output
          // (DLP verdict struct, security alert text). Otherwise the
          // scanner re-detects its own redactor output as a "leak".
          if (isNode9SelfOutput(resultText)) continue;
          const dlpMatch = scanArgs({ text: resultText });
          if (dlpMatch) {
            // Demote test-fixture-shape tokens — these are tutorial
            // examples, regex docs, or debug fixtures, not real secrets.
            if (looksLikeFixtureToken(dlpMatch.redactedSample)) continue;
            if (firstDlpTs === null) firstDlpTs = entry.timestamp ?? null;
            const k = dlpKey(dlpMatch.patternName, dlpMatch.redactedSample, projLabel);
            if (!dedup.dlpKeys.has(k)) {
              dedup.dlpKeys.add(k);
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
      if (/^node9\s+(scan|explain|report|tail|dlp|status|sessions|audit)\b/.test(rawCmd)) continue;

      // ── DLP scan ───────────────────────────────────────────────────
      // Skip code files — Edit/Write pass full source in old_string/new_string
      // which contains auth patterns that are not real secrets.
      const inputFilePath = typeof input.file_path === 'string' ? input.file_path : '';
      const inputFileExt = inputFilePath ? path.extname(inputFilePath).toLowerCase() : '';
      if (CODE_EXTENSIONS.has(inputFileExt)) continue;

      const dlpMatch = scanArgs(input);
      if (dlpMatch) {
        if (firstDlpTs === null) firstDlpTs = entry.timestamp ?? null;
        const k = dlpKey(dlpMatch.patternName, dlpMatch.redactedSample, projLabel);
        if (!dedup.dlpKeys.has(k)) {
          dedup.dlpKeys.add(k);
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

      // ── AST filesystem-operation detection ─────────────────────────
      // Runs FIRST so AST-resolved verdicts win over the regex rules,
      // which can FP on JSON args, heredocs, and chained commands.
      let astFsMatched = false;
      const astRanForBash = toolNameLower === 'bash' || toolNameLower === 'execute_bash';
      if (astRanForBash) {
        astFsMatched = pushFsOpAstFinding(
          String(input.command ?? ''),
          toolName,
          input,
          entry.timestamp ?? '',
          projLabel,
          sessionId,
          'claude',
          result,
          dedup
        );
      }

      // ── Smart rule matching ────────────────────────────────────────
      let ruleMatched = astFsMatched;
      for (const source of ruleSources) {
        const { rule } = source;

        if (rule.verdict === 'allow') continue;
        if (rule.tool && !matchesPattern(toolNameLower, rule.tool)) continue;
        // Suppress regex rules that AST already covers (correctly).
        if (astRanForBash && rule.name && AST_FS_REGEX_RULES.has(rule.name)) continue;
        if (!evaluateSmartConditions(input, rule)) continue;

        const inputPreview = preview(input, 120);
        const k = findingKey(rule.name, inputPreview, projLabel);
        if (!dedup.findingsKeys.has(k)) {
          dedup.findingsKeys.add(k);
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
          const k = findingKey(astRule.name, inputPreview, projLabel);
          if (!dedup.findingsKeys.has(k)) {
            dedup.findingsKeys.add(k);
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

/**
 * Sync wrapper used by the CLI (`node9 scan`) and the daemon. Walks every
 * project under ~/.claude/projects, applying processClaudeFile per session.
 */
function processClaudeProject(
  proj: string,
  projectsDir: string,
  ruleSources: RuleSource[],
  startDate: Date | null,
  result: ScanResult,
  dedup: ScanDedup,
  onProgress?: (done: number) => void,
  onLine?: () => void
): void {
  const projPath = path.join(projectsDir, proj);
  try {
    if (!fs.statSync(projPath).isDirectory()) return;
  } catch {
    return;
  }

  const projLabel = stripTerminalEscapes(decodeURIComponent(proj).replace(os.homedir(), '~')).slice(
    0,
    40
  );

  let files: string[];
  try {
    files = fs.readdirSync(projPath).filter((f) => f.endsWith('.jsonl') && !f.startsWith('agent-'));
  } catch {
    return;
  }

  for (const file of files) {
    processClaudeFile(
      file,
      projPath,
      projLabel,
      ruleSources,
      startDate,
      result,
      dedup,
      onProgress,
      onLine
    );
  }
}

/**
 * Async variant used by the dashboard. Mirrors processClaudeProject but
 * awaits yieldTick() between FILES (not projects) so the event loop's
 * Poll phase can dispatch stdin keypresses (q / Ctrl+C / view switch)
 * with at most one file of latency (~10-30 ms) instead of one project
 * (~100-500 ms).
 */
async function processClaudeProjectAsync(
  proj: string,
  projectsDir: string,
  ruleSources: RuleSource[],
  startDate: Date | null,
  result: ScanResult,
  dedup: ScanDedup,
  onProgress?: (done: number) => void,
  onLine?: () => void
): Promise<void> {
  const projPath = path.join(projectsDir, proj);
  try {
    if (!fs.statSync(projPath).isDirectory()) return;
  } catch {
    return;
  }

  const projLabel = stripTerminalEscapes(decodeURIComponent(proj).replace(os.homedir(), '~')).slice(
    0,
    40
  );

  let files: string[];
  try {
    files = fs.readdirSync(projPath).filter((f) => f.endsWith('.jsonl') && !f.startsWith('agent-'));
  } catch {
    return;
  }

  for (const file of files) {
    processClaudeFile(
      file,
      projPath,
      projLabel,
      ruleSources,
      startDate,
      result,
      dedup,
      onProgress,
      onLine
    );
    await yieldTick();
  }
}

/** Promise that resolves on the next event-loop tick. The async walker
 *  awaits this between projects so ink can repaint the loading state. */
function yieldTick(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

function emptyClaudeScan(): ScanResult {
  return {
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
}

export function scanClaudeHistory(
  startDate: Date | null,
  onProgress?: (done: number) => void,
  onLine?: () => void
): ScanResult {
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  const result = emptyClaudeScan();

  if (!fs.existsSync(projectsDir)) return result;

  let projDirs: string[];
  try {
    projDirs = fs.readdirSync(projectsDir);
  } catch {
    return result;
  }

  const ruleSources = buildRuleSources();
  const dedup = emptyScanDedup();

  for (const proj of projDirs) {
    processClaudeProject(
      proj,
      projectsDir,
      ruleSources,
      startDate,
      result,
      dedup,
      onProgress,
      onLine
    );
  }

  return result;
}

/**
 * Async variant of scanClaudeHistory used by the dashboard. Yields to the
 * event loop between projects so the UI can repaint and process keypresses
 * (q / Ctrl+C / view switch) while the walk is in flight. The CLI keeps
 * using the sync version above — a print-and-exit flow has no UI to keep
 * responsive and pays no benefit from chunking.
 */
export async function scanClaudeHistoryAsync(
  startDate: Date | null,
  onProgress?: (done: number) => void,
  onLine?: () => void
): Promise<ScanResult> {
  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  const result = emptyClaudeScan();

  if (!fs.existsSync(projectsDir)) return result;

  let projDirs: string[];
  try {
    projDirs = fs.readdirSync(projectsDir);
  } catch {
    return result;
  }

  const ruleSources = buildRuleSources();
  const dedup = emptyScanDedup();

  for (const proj of projDirs) {
    await processClaudeProjectAsync(
      proj,
      projectsDir,
      ruleSources,
      startDate,
      result,
      dedup,
      onProgress,
      onLine
    );
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
  const dedup = emptyScanDedup();

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
              const k = dlpKey(dlpMatch.patternName, dlpMatch.redactedSample, projLabel);
              if (!dedup.dlpKeys.has(k)) {
                dedup.dlpKeys.add(k);
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
            const k = dlpKey(dlpMatch.patternName, dlpMatch.redactedSample, projLabel);
            if (!dedup.dlpKeys.has(k)) {
              dedup.dlpKeys.add(k);
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

          // ── AST filesystem-operation detection (gemini) ────────────────
          let astFsMatched = false;
          const astRanForBash = toolNameLower === 'run_shell_command' || toolNameLower === 'shell';
          if (astRanForBash) {
            astFsMatched = pushFsOpAstFinding(
              String(input.command ?? ''),
              toolName,
              input,
              msg.timestamp ?? '',
              projLabel,
              sessionId,
              'gemini',
              result,
              dedup
            );
          }

          let ruleMatched = astFsMatched;
          for (const source of ruleSources) {
            const { rule } = source;
            if (rule.verdict === 'allow') continue;
            if (rule.tool && !matchesPattern(toolNameLower, rule.tool)) continue;
            if (astRanForBash && rule.name && AST_FS_REGEX_RULES.has(rule.name)) continue;
            if (!evaluateSmartConditions(input, rule)) continue;

            const inputPreview = preview(input, 120);
            const k = findingKey(rule.name, inputPreview, projLabel);
            if (!dedup.findingsKeys.has(k)) {
              dedup.findingsKeys.add(k);
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
              const k = findingKey(astRule.name, inputPreview, projLabel);
              if (!dedup.findingsKeys.has(k)) {
                dedup.findingsKeys.add(k);
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
  const dedup = emptyScanDedup();

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
            const k = dlpKey(dlpMatch.patternName, dlpMatch.redactedSample, projLabel);
            if (!dedup.dlpKeys.has(k)) {
              dedup.dlpKeys.add(k);
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
        const k = dlpKey(dlpMatch.patternName, dlpMatch.redactedSample, projLabel);
        if (!dedup.dlpKeys.has(k)) {
          dedup.dlpKeys.add(k);
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

      // ── AST filesystem-operation detection (codex) ─────────────────────
      let astFsMatched = false;
      const astRanForBash = toolNameLower === 'exec_command' || toolNameLower === 'bash';
      if (astRanForBash) {
        astFsMatched = pushFsOpAstFinding(
          String(input['command'] ?? ''),
          toolName,
          input,
          ts,
          projLabel,
          sessionId,
          'codex',
          result,
          dedup
        );
      }

      let ruleMatched = astFsMatched;
      for (const source of ruleSources) {
        const { rule } = source;
        if (rule.verdict === 'allow') continue;
        if (
          rule.tool &&
          !matchesPattern(toolNameLower === 'exec_command' ? 'bash' : toolNameLower, rule.tool)
        )
          continue;
        if (astRanForBash && rule.name && AST_FS_REGEX_RULES.has(rule.name)) continue;
        if (!evaluateSmartConditions(input, rule)) continue;

        const inputPreview = preview(input, 120);
        const k = findingKey(rule.name, inputPreview, projLabel);
        if (!dedup.findingsKeys.has(k)) {
          dedup.findingsKeys.add(k);
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
          const k = findingKey(astRule.name, inputPreview, projLabel);
          if (!dedup.findingsKeys.has(k)) {
            dedup.findingsKeys.add(k);
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
  const seen = new Set<string>();

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
      const k = dlpKey(dlpMatch.patternName, dlpMatch.redactedSample, shortPath);
      if (!seen.has(k)) {
        seen.add(k);
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

export function printFindingRow(
  f: FindingRef,
  drillDown: boolean,
  showSessionId: boolean,
  previewWidth: number
): void {
  // Older findings are dimmed across the row so a wall of recent + ancient
  // hits has clear visual hierarchy. Matches the existing DLP treatment
  // (see Credential Leaks section) so all finding rows look symmetric.
  const stale = isStaleFinding(f.timestamp);
  const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
  const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
  const agentLabel =
    f.agent === 'gemini' ? '[Gemini]  ' : f.agent === 'codex' ? '[Codex]   ' : '[Claude]  ';
  const agentBadge = stale
    ? chalk.dim(agentLabel)
    : f.agent === 'gemini'
      ? chalk.blue(agentLabel)
      : f.agent === 'codex'
        ? chalk.magenta(agentLabel)
        : chalk.cyan(agentLabel);
  // FindingRef.command is already the preview; fullCommand is the untruncated form.
  let cmdText: string;
  if (drillDown) {
    cmdText = f.fullCommand;
  } else {
    cmdText = f.command;
    if (cmdText.length > previewWidth) cmdText = cmdText.slice(0, previewWidth - 1) + '…';
  }
  const cmd = stale ? chalk.dim(cmdText) : chalk.gray(cmdText);
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

export interface CompactInput {
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

export function renderCompactScorecard(input: CompactInput): void {
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
  const score = classifyScore(blast.score);
  console.log(
    chalk.bold('Security Score: ') +
      score.color.bold(`${blast.score}/100`) +
      chalk.dim('  ·  ') +
      score.color(score.label)
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
    const topPatterns = topDlpPatterns(scan.dlpFindings, 3)
      .map((p) => (p.count > 1 ? `${p.name} ×${p.count}` : p.name))
      .join(', ');
    console.log(
      chalk.red('🔑  ') +
        chalk.red.bold(String(scan.dlpFindings.length).padEnd(4)) +
        chalk.dim('credential leak'.padEnd(20)) +
        chalk.dim(`(${topPatterns})`)
    );
  }

  if (blockedCount > 0) {
    const topBlocked = topRulesByVerdict(summary.sections, 'block', 3)
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

  // Loops vs long-iteration: real cyclic loops indicate stuck behavior and
  // count toward wasted spend. Long iterations are sustained deep work on the
  // same target across many minutes — they look identical to a regex group-by
  // but are not waste, so we render them as a separate, lower-emphasis line.
  const realLoops = scan.loopFindings.filter((l) => l.kind !== 'long-iteration');
  const longIterations = scan.loopFindings.filter((l) => l.kind === 'long-iteration');

  if (realLoops.length > 0) {
    const { wastePct } = computeLoopWaste(realLoops, scan.totalToolCalls);
    const wasteParts: string[] = [];
    if (wastePct > 0) wasteParts.push(`${wastePct}% wasted`);
    if (summary.loopWastedUSD > 0) wasteParts.push('~' + fmtCost(summary.loopWastedUSD));
    const wasteSummary = wasteParts.length ? `(${wasteParts.join('  ·  ')})` : '';
    console.log(
      chalk.yellow('🔁  ') +
        chalk.yellow.bold(String(realLoops.length).padEnd(4)) +
        chalk.dim('agent loops'.padEnd(20)) +
        chalk.dim(wasteSummary)
    );
  }
  if (longIterations.length > 0) {
    console.log(
      chalk.dim('📂  ') +
        chalk.dim.bold(String(longIterations.length).padEnd(4)) +
        chalk.dim('long iterations'.padEnd(20)) +
        chalk.dim('(deep work — not waste)')
    );
  }

  if (reviewCount > 0) {
    const topReview = topRulesByVerdict(summary.sections, 'review', 3)
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

export function renderNarrativeScorecard(input: CompactInput): void {
  const { scan, summary, blast, blastExposures } = input;

  const critical: BucketEntry[] = [];
  const high: BucketEntry[] = [];
  const medium: BucketEntry[] = [];

  // ── DLP findings → critical ─────────────────────────────────────────
  if (scan.dlpFindings.length > 0) {
    const top = topDlpPatterns(scan.dlpFindings, 3)
      .map((p) => (p.count > 1 ? `${p.name} ×${p.count}` : p.name))
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
    const { wastePct } = computeLoopWaste(scan.loopFindings, scan.totalToolCalls);
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
  const score = classifyScore(blast.score);
  console.log(
    (score.band === 'critical' ? chalk.red.bold('⚠  ') : '') +
      chalk.bold('Security Score: ') +
      score.color.bold(`${blast.score}/100`) +
      chalk.dim('  ·  ') +
      score.color(score.label)
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
// Panel scorecard renderer (default mode, no flag)
// ---------------------------------------------------------------------------
//
// The default `node9 scan` output. Designed as the polished forecast
// the user opens to act on — concise, scannable, with a SHIELDS panel
// that converts hits into a "+N pts if you enable X" recommendation.
//
// Mental model: 7 box-drawn panels stacked vertically.
//   1. TOP FINDINGS      4 auto-derived bullets ranking severity
//   2. LEAKS             5 most recent credential exposures
//   3. BLOCKED           per-rule counts that node9 would have stopped
//   4. REVIEW QUEUE      per-rule counts that node9 would have flagged
//   5. AGENT LOOPS       efficiency breakdown by tool + top stuck files
//   6. BLAST RADIUS      paths an AI could reach on disk right now
//   7. SHIELDS           recommendations w/ score deltas
//
// Empty categories are skipped (no "0 leaks" filler rows). The hero
// block (score line + stat card + spend) is emitted by the caller
// before this function runs — we only render the panels themselves.
//
// `--drill-down` bypasses this renderer and uses the legacy verbose
// inline section render in the action handler (which now shows the
// same data with full per-finding examples + session IDs).

/** Pair of "rendered chalk-wrapped string" + "visible width" used to
 *  compose lines for boxPanel. Width is the Unicode-correct visible
 *  cell count, not JS .length — emojis like 👁 / 🛡 are surrogate
 *  pairs (length 2) but render as either 1 OR 2 cells depending on
 *  the terminal's emoji presentation. Mismatched assumptions = right
 *  border drifts. We use string-width to get the actual cell count. */
type Line = { rendered: string; width: number };

/** Build a Line from `[plain, formatter?]` segments. Each formatter
 *  wraps its segment with chalk (or any string → string fn); width
 *  is the sum of stringWidth() across plain segments — handles
 *  emojis, CJK characters, combining marks correctly. */
function mkLine(...parts: Array<[string, ((s: string) => string)?]>): Line {
  let rendered = '';
  let width = 0;
  for (const [text, fmt] of parts) {
    rendered += fmt ? fmt(text) : text;
    width += stringWidth(text);
  }
  return { rendered, width };
}

/** Helper: shorten a long rule name to fit a fixed column. Strips the
 *  `shield:<name>:` prefix that's already implied by the origin column,
 *  then truncates if still over `width`. Keeps the right edge of the
 *  column visually clean. */
function shortRule(name: string, width: number): string {
  const stripped = name.replace(/^shield:[^:]+:/, '');
  if (stripped.length <= width) return stripped.padEnd(width);
  return stripped.slice(0, width - 1) + '…';
}

export function renderPanelScorecard(input: CompactInput, now: Date = new Date()): void {
  const { scan, summary, blast, blastExposures, blockedCount, reviewCount } = input;

  // ── TOP FINDINGS ─────────────────────────────────────────────────────
  // Auto-derived: pick the highest-impact one fact per category. Each
  // bullet's wording is the SHORTEST sentence that answers "what should
  // I act on?" — relative dates, top patterns inline.
  const topLines: Line[] = [];
  if (scan.dlpFindings.length > 0) {
    const latest = scan.dlpFindings[0];
    const rel = relativeDate(latest.timestamp, now);
    const noun = `credential leak${scan.dlpFindings.length !== 1 ? 's' : ''}`;
    topLines.push(
      mkLine(
        ['🚨 ', chalk.red],
        [`${scan.dlpFindings.length} ${noun} in tool input  `, chalk.bold],
        [`(latest: ${rel} ago, ${latest.patternName})`, chalk.dim]
      )
    );
  }
  if (blockedCount > 0) {
    // Keep TOP FINDINGS to a single line per category — only top 2
    // blocked rule names fit comfortably on an 80-col terminal after
    // the leading "🛑 N ops node9 would have blocked  (...)" framing.
    const topBlocked = topRulesByVerdict(summary.sections, 'block', 2)
      .map((r) =>
        r.count > 1
          ? `${shortRule(r.name, 20).trimEnd()} ×${r.count}`
          : shortRule(r.name, 20).trimEnd()
      )
      .join(', ');
    topLines.push(
      mkLine(
        ['🛑 ', chalk.red],
        [`${blockedCount} ops node9 would have blocked  `, chalk.bold],
        [`(${topBlocked})`, chalk.dim]
      )
    );
  }
  if (scan.loopFindings.length > 0) {
    const { wastePct } = computeLoopWaste(scan.loopFindings, scan.totalToolCalls);
    // Surface the dominant tool name inline — more useful than
    // "repeated patterns" filler and lets the line fit in 72 cols.
    const byTool = new Map<string, number>();
    for (const f of scan.loopFindings) {
      byTool.set(f.toolName, (byTool.get(f.toolName) ?? 0) + Math.max(0, f.count - 1));
    }
    const top = [...byTool.entries()].sort((a, b) => b[1] - a[1])[0];
    const wasteSuffix = wastePct > 0 ? `, ${wastePct}% wasted` : '';
    const detail = top ? `(${top[0]} dominates${wasteSuffix})` : '';
    topLines.push(
      mkLine(
        ['🔁 ', chalk.yellow],
        [`${scan.loopFindings.length} agent loops detected  `, chalk.bold],
        [detail, chalk.dim]
      )
    );
  }
  if (blastExposures > 0) {
    const exposed = Math.max(0, 100 - blast.score);
    const pjDiscount = PROTECTIVE_SHIELD_DISCOUNTS['project-jail'] ?? 0;
    const pjBonus = Math.round(exposed * pjDiscount);
    const cta = pjBonus > 0 ? `  → enable project-jail (+${pjBonus} pts)` : '';
    topLines.push(
      mkLine(
        ['🔭 ', chalk.red],
        [`${blastExposures} secrets reachable on disk`, chalk.bold],
        [cta, chalk.dim]
      )
    );
  }
  if (topLines.length > 0) {
    for (const ln of boxPanel('TOP FINDINGS', topLines)) console.log('  ' + ln);
    console.log('');
  }

  // ── LEAKS panel ─────────────────────────────────────────────────────
  // Top 5 most recent. Sorted desc by timestamp via the summary builder.
  if (summary.leaks.length > 0) {
    const leakLines: Line[] = [];
    for (const leak of summary.leaks.slice(0, 5)) {
      const rel = relativeDate(leak.timestamp, now);
      // Layout: <rel-date>  <pattern>      <redacted>           <[tool]>      <agent>
      // Project column dropped — most leaks come from the same project
      // and the column otherwise pushed rows past the right border on
      // an 80-col terminal. The full project is still in --drill-down.
      leakLines.push(
        mkLine(
          [rel.padStart(4) + '  ', chalk.dim],
          [leak.patternName.padEnd(14), chalk.red.bold],
          [' '],
          [leak.redactedSample.padEnd(20), chalk.red],
          [' '],
          [`[${leak.toolName}]`.padEnd(15), chalk.dim],
          [' '],
          [leak.agent, chalk.dim]
        )
      );
    }
    const remaining = summary.leaks.length - 5;
    if (remaining > 0) {
      leakLines.push(mkLine([`… +${remaining} more`, chalk.dim]));
    }
    const title = `LEAKS  ·  ${summary.leaks.length} secret${summary.leaks.length !== 1 ? 's' : ''} in plain text`;
    for (const ln of boxPanel(title, leakLines)) console.log('  ' + ln);
    console.log('');
  }

  // ── BLOCKED panel ───────────────────────────────────────────────────
  // Per-rule counts attributable to block-verdict findings. Origin column
  // shows whether the rule is a built-in default or comes from a shield.
  if (blockedCount > 0) {
    const blockedLines: Line[] = [];
    const ruleEntries = topRulesByVerdict(summary.sections, 'block', 12);
    for (const r of ruleEntries) {
      const origin = originForRule(r.name, summary.sections);
      blockedLines.push(
        mkLine(
          ['✗ ', chalk.red],
          [shortRule(r.name, 24), chalk.bold],
          [' ×' + String(r.count).padEnd(4), chalk.bold],
          [' '],
          [origin, chalk.dim]
        )
      );
    }
    const title = `BLOCKED  ·  ${blockedCount} ops node9 would have stopped`;
    for (const ln of boxPanel(title, blockedLines)) console.log('  ' + ln);
    console.log('');
  }

  // ── REVIEW QUEUE panel ──────────────────────────────────────────────
  // Same as BLOCKED but for review-verdict rules. User-config rules
  // are pre-stripped from summary.sections by buildRuleSources, so the
  // origin column only ever shows `default` or `needs shield:X`.
  if (reviewCount > 0) {
    const reviewLines: Line[] = [];
    const ruleEntries = topRulesByVerdict(summary.sections, 'review', 12);
    for (const r of ruleEntries) {
      const origin = originForRule(r.name, summary.sections);
      reviewLines.push(
        mkLine(
          // VS-16 (U+FE0F) forces emoji-presentation so string-width
          // returns 2 cells (matching how modern terminals actually
          // render it). Without VS-16 string-width says 1 cell — and
          // the right border drifts off. Same applies to 🛡 / ⚠ below.
          ['👁️  ', chalk.yellow],
          [shortRule(r.name, 24), chalk.bold],
          [' ×' + String(r.count).padEnd(4), chalk.bold],
          [' '],
          [origin, chalk.dim]
        )
      );
    }
    const title = `REVIEW QUEUE  ·  ${reviewCount} ops flagged for approval`;
    for (const ln of boxPanel(title, reviewLines)) console.log('  ' + ln);
    console.log('');
  }

  // ── AGENT LOOPS panel ───────────────────────────────────────────────
  // Efficiency, not severity. Split off from REVIEW so the eye isn't
  // confused about what "needs approval" vs "is wasteful but harmless".
  if (scan.loopFindings.length > 0) {
    const { wastePct } = computeLoopWaste(scan.loopFindings, scan.totalToolCalls);

    // Group loop findings by toolName to compute the breakdown.
    const byTool = new Map<string, number>();
    let totalRepeats = 0;
    for (const f of scan.loopFindings) {
      const repeats = Math.max(0, f.count - 1);
      byTool.set(f.toolName, (byTool.get(f.toolName) ?? 0) + repeats);
      totalRepeats += repeats;
    }
    const toolEntries = [...byTool.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
    const loopLines: Line[] = [];
    for (const [tool, repeats] of toolEntries) {
      const pct = totalRepeats > 0 ? Math.round((repeats / totalRepeats) * 100) : 0;
      loopLines.push(
        mkLine(
          [tool.padEnd(10), chalk.bold],
          [`×${num(repeats)} repeats`.padEnd(16)],
          [`(${pct}%)`, chalk.dim]
        )
      );
    }

    // Top stuck files: most-repeated single LoopFinding rows.
    const topStuck = [...scan.loopFindings].sort((a, b) => b.count - a.count).slice(0, 3);
    if (topStuck.length > 0) {
      loopLines.push(mkLine([''])); // blank separator inside box
      loopLines.push(mkLine(['Top stuck patterns:', chalk.dim]));
      for (const f of topStuck) {
        // Width budget: panel inner 72, prefix "×NNNN " = 7, leaving 65
        // for the target path/command. Use basename when the path is
        // longer to keep the row stable.
        const raw = f.commandPreview || f.toolName;
        const target = raw.length > 60 ? '…' + raw.slice(raw.length - 59) : raw.padEnd(60);
        loopLines.push(mkLine([`×${num(f.count).padEnd(4)} `, chalk.bold], [target, chalk.dim]));
      }
    }

    const wasteSuffix = wastePct > 0 ? `  ·  ${wastePct}% wasted` : '';
    const title = `AGENT LOOPS  ·  ${scan.loopFindings.length} repeated patterns${wasteSuffix}`;
    for (const ln of boxPanel(title, loopLines)) console.log('  ' + ln);
    // Earlier the "N repeated calls (~N × cost-per-iteration)" line
    // printed below the panel, but it sat outside the frame and read
    // as orphaned. The wastePct + breakdown rows already convey the
    // magnitude inside the box — dropped on 2026-05-12.
    console.log('');
  }

  // ── BLAST RADIUS panel ─────────────────────────────────────────────
  if (blast.reachable.length > 0 || blast.envFindings.length > 0) {
    const blastLines: Line[] = [];
    // Inner width = PANEL_WIDTH (76) - 4 borders/padding = 72. Reserve
    // 3 for the ✗ + 2 spaces and 36 for the label, leaving 33 for the
    // description. Strip the em-dash suffix so the description fits
    // without ugly mid-word truncation ("grants SSH acc…" was the
    // common case before this change — the descriptions in blast.ts
    // intentionally pack a noun phrase + explanation separated by '—',
    // and only the noun phrase is needed here).
    const DESC_W = 33;
    for (const r of blast.reachable.slice(0, 8)) {
      const trimmed = r.description.split(' — ')[0].split(/—|--/)[0].trim();
      const desc = trimmed.length > DESC_W ? trimmed.slice(0, DESC_W - 1) + '…' : trimmed;
      blastLines.push(mkLine(['✗  ', chalk.red], [r.label.padEnd(36)], [desc, chalk.dim]));
    }
    for (const e of blast.envFindings.slice(0, 3)) {
      blastLines.push(
        mkLine(['⚠️  ', chalk.yellow], [`${e.key} `], [`(${e.patternName})`, chalk.dim])
      );
    }
    const totalExposed = blast.reachable.length + blast.envFindings.length;
    if (totalExposed > 8) {
      blastLines.push(mkLine([`… +${totalExposed - 8} more`, chalk.dim]));
    }
    const title = `BLAST RADIUS  ·  ${totalExposed} path${totalExposed !== 1 ? 's' : ''} reachable right now`;
    for (const ln of boxPanel(title, blastLines)) console.log('  ' + ln);
    console.log('');
  }

  // ── SHIELDS panel — the action recommendation ─────────────────────
  // Per-shield "would catch N ops" with a score delta for protective
  // shields (project-jail today; future protective shields auto-extend
  // via PROTECTIVE_SHIELD_DISCOUNTS).
  const shieldImpacts = rollupByShield(summary.sections);
  const exposed = Math.max(0, 100 - blast.score);
  const shieldLines: Line[] = [];

  // Sort: protective shields with score impact first, then by hit count.
  const ranked = [...shieldImpacts].sort((a, b) => {
    const aDiscount = PROTECTIVE_SHIELD_DISCOUNTS[a.shieldName] ?? 0;
    const bDiscount = PROTECTIVE_SHIELD_DISCOUNTS[b.shieldName] ?? 0;
    if (aDiscount !== bDiscount) return bDiscount - aDiscount;
    return b.totalCatches - a.totalCatches;
  });

  for (const impact of ranked) {
    if (impact.totalCatches === 0) continue; // hit shields only — zero-hits go to footer
    const discount = PROTECTIVE_SHIELD_DISCOUNTS[impact.shieldName] ?? 0;
    const bonus = Math.round(exposed * discount);
    const icon = discount > 0 ? '🛡️  ' : '☐   ';
    const wouldCatch = `would catch ${impact.totalCatches} op${impact.totalCatches !== 1 ? 's' : ''}`;
    const deltaSuffix =
      bonus > 0 ? `  →  +${bonus} pts  (${blast.score} → ${blast.score + bonus})` : '';
    shieldLines.push(
      mkLine(
        [icon, discount > 0 ? chalk.cyan : chalk.dim],
        [impact.shieldName.padEnd(14), chalk.bold],
        [wouldCatch.padEnd(22), chalk.dim],
        [deltaSuffix, bonus > 0 ? chalk.green.bold : chalk.dim]
      )
    );
    // Top rule descriptions on a sub-line.
    if (impact.topRuleLabels.length > 0) {
      const rules = impact.topRuleLabels.join(', ');
      shieldLines.push(mkLine(['      ', chalk.dim], [rules, chalk.dim]));
    }
  }

  // Zero-hit builtin shields on a single collapsed line — acknowledges
  // they exist without bloating the panel.
  const hitShieldSet = new Set(
    shieldImpacts.filter((i) => i.totalCatches > 0).map((i) => i.shieldName)
  );
  const zeroHitBuiltins = Object.keys(SHIELDS)
    .filter((name) => !hitShieldSet.has(name))
    .sort();
  if (zeroHitBuiltins.length > 0) {
    shieldLines.push(mkLine([''])); // blank separator
    shieldLines.push(mkLine([zeroHitBuiltins.join(' · '), chalk.dim]));
    shieldLines.push(mkLine(['      no hits in your history — install proactively', chalk.dim]));
  }

  // Final CTA line inside the panel: highest-impact recommendation.
  const topRec = ranked.find(
    (r) => r.totalCatches > 0 && (PROTECTIVE_SHIELD_DISCOUNTS[r.shieldName] ?? 0) > 0
  );
  if (topRec) {
    const bonus = Math.round(exposed * (PROTECTIVE_SHIELD_DISCOUNTS[topRec.shieldName] ?? 0));
    const cta = `→ node9 shield enable ${topRec.shieldName}   (start here — +${bonus} pts)`;
    shieldLines.push(mkLine([''])); // blank separator
    shieldLines.push(mkLine([cta, chalk.cyan]));
  }

  if (shieldLines.length > 0) {
    const title = 'SHIELDS  ·  install node9 + enable these to catch what we found';
    for (const ln of boxPanel(title, shieldLines)) console.log('  ' + ln);
    console.log('');
  }
}

/** Find which origin tag (e.g. `default` or `needs shield:project-jail`)
 *  applies to a given rule name. The lookup walks the summary sections
 *  to find which one owns the rule. Used by BLOCKED + REVIEW QUEUE
 *  panels to render the rightmost origin column. */
function originForRule(
  ruleName: string,
  sections: ReadonlyArray<ScanSummary['sections'][number]>
): string {
  for (const section of sections) {
    if (section.rules.some((r) => r.name === ruleName)) {
      if (section.sourceType === 'default') return 'default';
      if (section.sourceType === 'shield') return `needs shield:${section.shieldKey ?? section.id}`;
    }
  }
  return '';
}

// ---------------------------------------------------------------------------
// Registered command
// ---------------------------------------------------------------------------

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Forecast: scan agent history and show what node9 would catch if installed')
    .option('--all', 'Scan all history (default: last 90 days)')
    .option('--days <n>', 'Scan last N days of history', '90')
    .option('--top <n>', 'Max findings to show per rule (default: 5)', '5')
    .option('--drill-down', 'Show all findings with full commands and session IDs')
    .option('--compact', 'Compact one-screen scorecard — for screenshots and sharing')
    .option('--narrative', 'Severity-grouped report — for video / dramatic sharing')
    .option(
      '--json',
      'Emit machine-readable JSON to stdout (suppresses banner, progress, and renderer)'
    )
    .option(
      '--upload-history',
      'Upload aggregate counts from existing JSONL sessions to the SaaS dashboard. ' +
        'Defaults to last 3 months; override with --since. Idempotent (safe to re-run).'
    )
    .option(
      '--since <window>',
      'Backfill window: 3m | 6m | 1y | YYYY-MM-DD. Only used with --upload-history.',
      '3m'
    )
    .action(
      async (options: {
        all?: boolean;
        days: string;
        top: string;
        drillDown?: boolean;
        compact?: boolean;
        narrative?: boolean;
        json?: boolean;
        uploadHistory?: boolean;
        since?: string;
      }) => {
        // --json is mutually exclusive with the human-output modes.
        // Fail fast so a script doesn't silently get the wrong shape.
        if (options.json && (options.compact || options.narrative || options.uploadHistory)) {
          console.error(
            'error: --json cannot be combined with --compact, --narrative, or --upload-history'
          );
          process.exit(1);
        }

        // Backfill path — separate from the normal "show me a forecast"
        // mode. Doesn't render the full report, just walks JSONLs and
        // posts to the SaaS.
        if (options.uploadHistory) {
          const { runUploadHistory } = await import('../../scan-upload-history.js');
          await runUploadHistory({ since: options.since ?? '3m' });
          return;
        }
        const drillDown = options.drillDown ?? false;
        const topN = drillDown ? Infinity : Math.max(1, parseInt(options.top, 10) || 5);
        const previewWidth = 70;
        const startDate = options.all
          ? null
          : (() => {
              const d = new Date();
              d.setDate(d.getDate() - (parseInt(options.days, 10) || 90));
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
        // --json suppresses everything outside the final JSON envelope so
        // stdout is parseable.
        const screenshotMode = options.compact || options.narrative;
        const quiet = screenshotMode || options.json;
        if (!quiet) {
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

        const useTTY =
          process.stdout.isTTY === true && process.env.NODE9_WRAPPER !== '1' && !options.json;
        if (!useTTY && !quiet) {
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

        if (scan.filesScanned === 0 && !options.json) {
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
          : chalk.dim(`last ${options.days ?? 90} days`);
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

        // Suppress in compact / narrative / json modes — they either render
        // their own header line or emit no preamble at all.
        if (!quiet) {
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

        // ── JSON output mode ────────────────────────────────────────────────
        // Emits one valid JSON object to stdout and returns. All preamble and
        // progress writes were already gated above so stdout is clean. For
        // CI gates, scripting, and external integrations.
        if (options.json) {
          const envelope = buildScanJson({
            scan,
            summary,
            blast,
            isWired,
            generatedAt: new Date().toISOString(),
          });
          process.stdout.write(JSON.stringify(envelope, null, 2) + '\n');
          return;
        }

        // ── Trend tracking ──────────────────────────────────────────────────
        // Only the default human-facing mode appends to scan-history.json
        // and shows a delta. Compact / narrative modes are deterministic
        // screenshot artifacts; --json already returned above. Fail-soft:
        // any history I/O error is swallowed inside the helpers.
        let scanDelta: ReturnType<typeof computeScanDelta> = null;
        if (!screenshotMode) {
          const previous = readPreviousScan();
          const currentRecord: ScanHistoryRecord = {
            timestamp: new Date().toISOString(),
            score: blast.score,
            blocked: blockedCount,
            review: reviewCount,
            leaks: scan.dlpFindings.length,
            loops: scan.loopFindings.length,
            totalCalls: scan.totalToolCalls,
          };
          appendScanHistory(currentRecord);
          scanDelta = computeScanDelta(currentRecord, previous);
        }

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
          const score = classifyScore(blast.score);
          const severityDisplay =
            score.band === 'critical' ? chalk.red.bold(score.label) : score.color(score.label);
          // Trend suffix vs the user's last scan (if any). Higher score =
          // safer, so a positive scoreDelta is good (green ▲); negative is
          // bad (red ▼). Hidden when no prior data or unchanged same-day.
          const trendSuffix = (() => {
            if (!scanDelta) return '';
            const { scoreDelta, daysAgo } = scanDelta;
            if (scoreDelta === 0) return '';
            const arrow =
              scoreDelta > 0
                ? chalk.green(`▲${scoreDelta}`)
                : chalk.red(`▼${Math.abs(scoreDelta)}`);
            const since =
              daysAgo === 0 ? 'today' : daysAgo === 1 ? 'yesterday' : `${daysAgo} days ago`;
            return chalk.dim('  ·  ') + arrow + chalk.dim(` since ${since}`);
          })();
          console.log(
            '  ' +
              (score.band === 'critical' ? chalk.red.bold('⚠  ') : '') +
              chalk.bold('Security Score ') +
              score.color.bold(`${blast.score}/100`) +
              '  ' +
              severityDisplay +
              trendSuffix +
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
            const { wastePct } = computeLoopWaste(scan.loopFindings, scan.totalToolCalls);
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
          // "N sessions loaded secrets before first edit" — only show
          // in --drill-down. The signal is noisy and misleading at the
          // headline level (it counts sessions that READ secrets, not
          // sessions that LEAKED them) and we already pulled the
          // equivalent callout from monitor for the same reason.
          if (drillDown && scan.dlpFindings.length > 0 && scan.sessionsWithEarlySecrets > 0) {
            console.log(
              '  ' +
                chalk.dim(
                  `${scan.sessionsWithEarlySecrets} session${scan.sessionsWithEarlySecrets !== 1 ? 's' : ''} loaded secrets before first edit`
                )
            );
          }
          console.log('');

          // ── Default-mode panel scorecard ─────────────────────────────────
          // The polished forecast view (~7 boxed panels) replaces the old
          // 9-section verbose layout below for users who don't opt into
          // --drill-down. The verbose layout still serves --drill-down so
          // forensic detail is one flag away.
          //
          // NODE9_SCAN_INK=1 env flag opts into the new Ink-rendered
          // panel scorecard (in active migration). Default path
          // remains the chalk-based renderPanelScorecard until the
          // migration completes — see scan-redesign plan, commit #1.
          if (!drillDown) {
            const useInk = process.env.NODE9_SCAN_INK === '1';
            // Commits #1-6 migrated all 6 panels to the Ink scorecard.
            // As of commit #7, the Ink path renders the complete
            // scorecard and the chalk renderPanelScorecard is the
            // strict fallback for users who haven't opted in. Commit
            // #8 deletes the chalk path entirely.
            //
            // Ink load: ink/react are ESM with top-level await, so
            // they can't be require()'d from this CJS bundle. We
            // load from a separate scan-ink ESM bundle via the same
            // `new Function('id', 'return import(id)')` indirection
            // that `node9 monitor` uses for dashboard.mjs.
            if (useInk) {
              const scanInkPath = path.join(__dirname, 'scan-ink.mjs');
              const dynamicImport = new Function('id', 'return import(id)') as (
                id: string
              ) => Promise<{
                renderScanScorecardInk: (input: CompactInput) => void;
              }>;
              const mod = await dynamicImport(`file://${scanInkPath}`);
              mod.renderScanScorecardInk({
                scan,
                summary,
                blast,
                blastExposures,
                blockedCount,
                reviewCount,
              });
            } else {
              renderPanelScorecard({
                scan,
                summary,
                blast,
                blastExposures,
                blockedCount,
                reviewCount,
              });
            }
            // Footer CTAs — distinct from the legacy footer at end of
            // verbose render. Points to monitor (live dashboard) and
            // drill-down (forensic deep-dive) — NOT `node9 report`
            // which is a different command for installed users.
            const cta = isWired ? '✅ node9 is active' : '→ install node9 to enable protection';
            console.log('  ' + chalk.green(cta));
            console.log(
              '  ' +
                chalk.dim('→ ') +
                chalk.cyan('node9 monitor') +
                chalk.dim('              live dashboard')
            );
            console.log(
              '  ' +
                chalk.dim('→ ') +
                chalk.cyan('node9 scan --drill-down') +
                chalk.dim('    full commands + session IDs')
            );
            console.log('');
            return;
          }

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
              // Symmetric with printFindingRow: dim stale loops across the row
              // so old churn fades behind anything from this week.
              const stale = isStaleFinding(f.timestamp);
              const ts = f.timestamp ? chalk.dim(fmtTs(f.timestamp) + '  ') : '';
              const proj = chalk.dim(f.project.slice(0, 22).padEnd(22) + '  ');
              const agentLabel =
                f.agent === 'gemini'
                  ? '[Gemini]  '
                  : f.agent === 'codex'
                    ? '[Codex]   '
                    : '[Claude]  ';
              const agentBadge = stale
                ? chalk.dim(agentLabel)
                : f.agent === 'gemini'
                  ? chalk.blue(agentLabel)
                  : f.agent === 'codex'
                    ? chalk.magenta(agentLabel)
                    : chalk.cyan(agentLabel);
              const toolDisplay = stale ? chalk.dim(f.toolName) : chalk.yellow(f.toolName);
              const cmdDisplay = stale ? chalk.dim(f.commandPreview) : chalk.gray(f.commandPreview);
              const sessionSuffix = f.sessionId ? chalk.dim(`  → ${f.sessionId.slice(0, 8)}`) : '';
              console.log(
                `    ${ts}${proj}${agentBadge}` +
                  toolDisplay +
                  chalk.dim(`  ×${f.count}  `) +
                  cmdDisplay +
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

        // Browser dashboard view + auto-push to /scan/push retired in
        // v3 sprint. Terminal scan output (above) is the only artifact.
        // For richer cross-machine views, point users at the SaaS
        // dashboard via `node9 sessions` or the audit log.
      }
    );
}
