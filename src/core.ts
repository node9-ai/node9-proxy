// src/core.ts
import chalk from 'chalk';
import { confirm } from '@inquirer/prompts';
import fs from 'fs';
import path from 'path';
import os from 'os';
import net from 'net';
import { randomUUID } from 'crypto';
import { spawnSync } from 'child_process';
import pm from 'picomatch';
import safeRegex from 'safe-regex2';
import { parse } from 'sh-syntax';
import { askNativePopup, sendDesktopNotification } from './ui/native';
import { computeRiskMetadata, RiskMetadata } from './context-sniper';
import { sanitizeConfig } from './config-schema';
import { readActiveShields, getShield } from './shields';
import { scanArgs, scanFilePath, type DlpMatch } from './dlp';

// ── Feature file paths ────────────────────────────────────────────────────────
const PAUSED_FILE = path.join(os.homedir(), '.node9', 'PAUSED');
const TRUST_FILE = path.join(os.homedir(), '.node9', 'trust.json');
const LOCAL_AUDIT_LOG = path.join(os.homedir(), '.node9', 'audit.log');
const HOOK_DEBUG_LOG = path.join(os.homedir(), '.node9', 'hook-debug.log');

interface PauseState {
  expiry: number;
  duration: string;
}
interface TrustEntry {
  tool: string;
  expiry: number;
}
interface TrustFile {
  entries: TrustEntry[];
}

// ── Global Pause helpers ──────────────────────────────────────────────────────

export function checkPause(): { paused: boolean; expiresAt?: number; duration?: string } {
  try {
    if (!fs.existsSync(PAUSED_FILE)) return { paused: false };
    const state = JSON.parse(fs.readFileSync(PAUSED_FILE, 'utf-8')) as PauseState;
    if (state.expiry > 0 && Date.now() >= state.expiry) {
      try {
        fs.unlinkSync(PAUSED_FILE);
      } catch {}
      return { paused: false };
    }
    return { paused: true, expiresAt: state.expiry, duration: state.duration };
  } catch {
    return { paused: false };
  }
}

function atomicWriteSync(filePath: string, data: string, options?: fs.WriteFileOptions): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${filePath}.${os.hostname()}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, data, options);
  fs.renameSync(tmpPath, filePath);
}

export function pauseNode9(durationMs: number, durationStr: string): void {
  const state: PauseState = { expiry: Date.now() + durationMs, duration: durationStr };
  atomicWriteSync(PAUSED_FILE, JSON.stringify(state, null, 2)); // Upgraded to atomic
}

export function resumeNode9(): void {
  try {
    if (fs.existsSync(PAUSED_FILE)) fs.unlinkSync(PAUSED_FILE);
  } catch {}
}

// ── Regex Cache & ReDoS Protection ───────────────────────────────────────────
const MAX_REGEX_LENGTH = 100;
const REGEX_CACHE_MAX = 500;
const regexCache = new Map<string, RegExp>();

/**
 * Validates a user-supplied regex pattern against known ReDoS vectors.
 * Returns null if valid, or an error string describing the problem.
 */
export function validateRegex(pattern: string): string | null {
  if (!pattern) return 'Pattern is required';
  if (pattern.length > MAX_REGEX_LENGTH) return `Pattern exceeds max length of ${MAX_REGEX_LENGTH}`;

  // Compile check first — rejects structurally invalid patterns (unbalanced parens,
  // bad escapes, etc.) before they reach safe-regex2, which may misanalyse them.
  try {
    new RegExp(pattern);
  } catch (e) {
    return `Invalid regex syntax: ${(e as Error).message}`;
  }

  // Quantified backreferences — safe-regex2 does not analyse backreferences,
  // so we keep this explicit guard: \1+ \2* \1{2,} can cause catastrophic backtracking.
  // \d+ matches multi-digit group numbers (\10, \11, …) correctly.
  if (/\\\d+[*+{]/.test(pattern)) return 'Quantified backreferences are forbidden (ReDoS risk)';

  // ReDoS check via safe-regex2 — proper NFA analysis, replaces the previous
  // hand-rolled heuristics which had false positives ((GET|POST)+) and false
  // negatives ((x|xx)*). safe-regex2 correctly handles both cases.
  if (!safeRegex(pattern)) return 'Pattern rejected: potential ReDoS vulnerability detected';

  return null;
}

/**
 * Compiles a regex with validation and LRU caching.
 * Returns null if the pattern is invalid or dangerous.
 */
export function getCompiledRegex(pattern: string, flags = ''): RegExp | null {
  // Validate flags before anything else — invalid flags (e.g. 'z') would throw
  // inside new RegExp() and could leak debug info; reject them explicitly.
  if (flags && !/^[gimsuy]+$/.test(flags)) {
    if (process.env.NODE9_DEBUG === '1') console.error(`[Node9] Invalid regex flags: "${flags}"`);
    return null;
  }
  const key = `${pattern}\0${flags}`;
  if (regexCache.has(key)) {
    // LRU bump: move to insertion-order end
    const cached = regexCache.get(key)!;
    regexCache.delete(key);
    regexCache.set(key, cached);
    return cached;
  }

  const err = validateRegex(pattern);
  if (err) {
    if (process.env.NODE9_DEBUG === '1')
      console.error(`[Node9] Regex blocked: ${err} — pattern: "${pattern}"`);
    return null;
  }

  try {
    const re = new RegExp(pattern, flags);
    if (regexCache.size >= REGEX_CACHE_MAX) {
      const oldest = regexCache.keys().next().value;
      if (oldest) regexCache.delete(oldest);
    }
    regexCache.set(key, re);
    return re;
  } catch (e) {
    if (process.env.NODE9_DEBUG === '1') console.error(`[Node9] Regex compile failed:`, e);
    return null;
  }
}

// ── Trust Session helpers ─────────────────────────────────────────────────────

function getActiveTrustSession(toolName: string): boolean {
  try {
    if (!fs.existsSync(TRUST_FILE)) return false;
    const trust = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8')) as TrustFile;
    const now = Date.now();
    const active = trust.entries.filter((e) => e.expiry > now);
    if (active.length !== trust.entries.length) {
      fs.writeFileSync(TRUST_FILE, JSON.stringify({ entries: active }, null, 2));
    }
    return active.some((e) => e.tool === toolName || matchesPattern(toolName, e.tool));
  } catch {
    return false;
  }
}

export function writeTrustSession(toolName: string, durationMs: number): void {
  try {
    let trust: TrustFile = { entries: [] };

    // 1. Try to read existing trust state
    try {
      if (fs.existsSync(TRUST_FILE)) {
        trust = JSON.parse(fs.readFileSync(TRUST_FILE, 'utf-8')) as TrustFile;
      }
    } catch {
      // If the file is corrupt, start with a fresh object
    }

    // 2. Filter out the specific tool (to overwrite) and remove any expired entries
    const now = Date.now();
    trust.entries = trust.entries.filter((e) => e.tool !== toolName && e.expiry > now);

    // 3. Add the new time-boxed entry
    trust.entries.push({ tool: toolName, expiry: now + durationMs });

    // 4. Perform the ATOMIC write
    atomicWriteSync(TRUST_FILE, JSON.stringify(trust, null, 2));
  } catch (err) {
    // Silent fail: Node9 should never crash an AI agent session due to a file error
    if (process.env.NODE9_DEBUG === '1') {
      console.error('[Node9 Trust Error]:', err);
    }
  }
}

function appendToLog(logPath: string, entry: object): void {
  try {
    const dir = path.dirname(logPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');
  } catch {}
}

function appendHookDebug(
  toolName: string,
  args: unknown,
  meta?: { agent?: string; mcpServer?: string }
): void {
  const safeArgs = args ? JSON.parse(redactSecrets(JSON.stringify(args))) : {};
  appendToLog(HOOK_DEBUG_LOG, {
    ts: new Date().toISOString(),
    tool: toolName,
    args: safeArgs,
    agent: meta?.agent,
    mcpServer: meta?.mcpServer,
    hostname: os.hostname(),
    cwd: process.cwd(),
  });
}

function appendLocalAudit(
  toolName: string,
  args: unknown,
  decision: 'allow' | 'deny',
  checkedBy: string,
  meta?: { agent?: string; mcpServer?: string }
): void {
  const safeArgs = args ? JSON.parse(redactSecrets(JSON.stringify(args))) : {};
  appendToLog(LOCAL_AUDIT_LOG, {
    ts: new Date().toISOString(),
    tool: toolName,
    args: safeArgs,
    decision,
    checkedBy,
    agent: meta?.agent,
    mcpServer: meta?.mcpServer,
    hostname: os.hostname(),
  });
}

function tokenize(toolName: string): string[] {
  return toolName
    .toLowerCase()
    .split(/[_.\-\s]+/)
    .filter(Boolean);
}

function matchesPattern(text: string, patterns: string[] | string): boolean {
  const p = Array.isArray(patterns) ? patterns : [patterns];
  if (p.length === 0) return false;
  const isMatch = pm(p, { nocase: true, dot: true });
  const target = text.toLowerCase();
  const directMatch = isMatch(target);
  if (directMatch) return true;
  const withoutDotSlash = text.replace(/^\.\//, '');
  return isMatch(withoutDotSlash) || isMatch(`./${withoutDotSlash}`);
}

function getNestedValue(obj: unknown, path: string): unknown {
  if (!obj || typeof obj !== 'object') return null;
  return path
    .split('.')
    .reduce<unknown>((prev, curr) => (prev as Record<string, unknown>)?.[curr], obj);
}

// ── SMART RULES EVALUATOR ─────────────────────────────────────────────────────

export interface SmartCondition {
  field: string;
  op:
    | 'matches'
    | 'notMatches'
    | 'contains'
    | 'notContains'
    | 'exists'
    | 'notExists'
    | 'matchesGlob'
    | 'notMatchesGlob';
  value?: string;
  flags?: string;
}

export interface SmartRule {
  name?: string;
  tool: string;
  conditions: SmartCondition[];
  conditionMode?: 'all' | 'any';
  verdict: 'allow' | 'review' | 'block';
  reason?: string;
}

/**
 * Returns true if a snapshot should be taken for this tool call.
 * Checks: tool name match → ignorePaths → onlyPaths (if specified).
 */
export function shouldSnapshot(toolName: string, args: unknown, config: Config): boolean {
  if (!config.settings.enableUndo) return false;

  const snap = config.policy.snapshot;
  if (!snap.tools.includes(toolName.toLowerCase())) return false;

  const a = args && typeof args === 'object' ? (args as Record<string, unknown>) : {};
  const filePath = String(a.file_path ?? a.path ?? a.filename ?? '');

  if (filePath) {
    if (snap.ignorePaths.length && pm(snap.ignorePaths)(filePath)) return false;
    if (snap.onlyPaths.length && !pm(snap.onlyPaths)(filePath)) return false;
  }

  return true;
}

export function evaluateSmartConditions(args: unknown, rule: SmartRule): boolean {
  if (!rule.conditions || rule.conditions.length === 0) return true;
  const mode = rule.conditionMode ?? 'all';

  const results = rule.conditions.map((cond) => {
    const rawVal = getNestedValue(args, cond.field);
    // Normalize whitespace so multi-space SQL doesn't bypass regex checks
    const val =
      rawVal !== null && rawVal !== undefined ? String(rawVal).replace(/\s+/g, ' ').trim() : null;

    switch (cond.op) {
      case 'exists':
        return val !== null && val !== '';
      case 'notExists':
        return val === null || val === '';
      case 'contains':
        return val !== null && cond.value ? val.includes(cond.value) : false;
      case 'notContains':
        return val !== null && cond.value ? !val.includes(cond.value) : true;
      case 'matches': {
        if (val === null || !cond.value) return false;
        const reM = getCompiledRegex(cond.value, cond.flags ?? '');
        if (!reM) return false; // invalid/dangerous pattern → fail closed
        return reM.test(val);
      }
      case 'notMatches': {
        if (!cond.value) return false; // no pattern → fail closed
        if (val === null) return true; // field absent → condition passes (preserve original)
        const reN = getCompiledRegex(cond.value, cond.flags ?? '');
        if (!reN) return false; // invalid/dangerous pattern → fail closed
        return !reN.test(val);
      }
      case 'matchesGlob':
        return val !== null && cond.value ? pm.isMatch(val, cond.value) : false;
      case 'notMatchesGlob':
        // Both absent field AND missing pattern → fail closed.
        // For a security tool, fail-closed is the safer default: an attacker
        // omitting a field must not satisfy a notMatchesGlob allow rule.
        // Rule authors who need "pass when field absent" should add an explicit
        // 'notExists' condition paired with 'notMatchesGlob'.
        return val !== null && cond.value ? !pm.isMatch(val, cond.value) : false;
      default:
        return false;
    }
  });

  return mode === 'any' ? results.some((r) => r) : results.every((r) => r);
}

function extractShellCommand(
  toolName: string,
  args: unknown,
  toolInspection: Record<string, string>
): string | null {
  const patterns = Object.keys(toolInspection);
  const matchingPattern = patterns.find((p) => matchesPattern(toolName, p));
  if (!matchingPattern) return null;
  const fieldPath = toolInspection[matchingPattern];
  const value = getNestedValue(args, fieldPath);
  return typeof value === 'string' ? value : null;
}

/** Returns true when a tool's inspected field is SQL (sql or query). */
function isSqlTool(toolName: string, toolInspection: Record<string, string>): boolean {
  const patterns = Object.keys(toolInspection);
  const matchingPattern = patterns.find((p) => matchesPattern(toolName, p));
  if (!matchingPattern) return false;
  const fieldName = toolInspection[matchingPattern];
  return fieldName === 'sql' || fieldName === 'query';
}

// SQL DML keywords — safe in a scoped context (WHERE clause present).
// Filtered from tokens so user dangerousWords like "delete"/"update" don't
// re-trigger after the WHERE-clause check has already passed.
const SQL_DML_KEYWORDS = new Set(['select', 'insert', 'update', 'delete', 'merge', 'upsert']);

/**
 * Checks a SQL string for dangerous unscoped mutations.
 * Returns a reason string if dangerous, null if safe.
 */
export function checkDangerousSql(sql: string): string | null {
  const norm = sql.replace(/\s+/g, ' ').trim().toLowerCase();
  const hasWhere = /\bwhere\b/.test(norm);

  if (/^delete\s+from\s+\S+/.test(norm) && !hasWhere)
    return 'DELETE without WHERE — full table wipe';

  if (/^update\s+\S+\s+set\s+/.test(norm) && !hasWhere)
    return 'UPDATE without WHERE — updates every row';

  return null;
}

interface AstNode {
  type: string;
  Args?: { Parts?: { Value?: string }[] }[];
  [key: string]: unknown;
}

async function analyzeShellCommand(
  command: string
): Promise<{ actions: string[]; paths: string[]; allTokens: string[] }> {
  const actions: string[] = [];
  const paths: string[] = [];
  const allTokens: string[] = [];

  const addToken = (token: string) => {
    const lower = token.toLowerCase();
    allTokens.push(lower);
    if (lower.includes('/')) {
      const segments = lower.split('/').filter(Boolean);
      allTokens.push(...segments);
    }
    if (lower.startsWith('-')) {
      allTokens.push(lower.replace(/^-+/, ''));
    }
  };

  try {
    const ast = await parse(command);
    const walk = (node: AstNode | null) => {
      if (!node) return;
      if (node.type === 'CallExpr') {
        const parts = (node.Args || [])
          .map((arg) => {
            return (arg.Parts || []).map((p) => p.Value || '').join('');
          })
          .filter((s: string) => s.length > 0);

        if (parts.length > 0) {
          actions.push(parts[0].toLowerCase());
          parts.forEach((p: string) => addToken(p));
          parts.slice(1).forEach((p: string) => {
            if (!p.startsWith('-')) paths.push(p);
          });
        }
      }
      for (const key in node) {
        if (key === 'Parent') continue;
        const val = node[key];
        if (Array.isArray(val)) {
          val.forEach((child: unknown) => {
            if (child && typeof child === 'object' && 'type' in child) {
              walk(child as AstNode);
            }
          });
        } else if (val && typeof val === 'object' && 'type' in val) {
          walk(val as AstNode);
        }
      }
    };
    walk(ast as unknown as AstNode);
  } catch {
    // Fallback
  }

  if (allTokens.length === 0) {
    const normalized = command.replace(/\\(.)/g, '$1');
    const sanitized = normalized.replace(/["'<>]/g, ' ');
    const segments = sanitized.split(/[|;&]|\$\(|\)|`/);
    segments.forEach((segment) => {
      const tokens = segment.trim().split(/\s+/).filter(Boolean);
      if (tokens.length > 0) {
        const action = tokens[0].toLowerCase();
        if (!actions.includes(action)) actions.push(action);
        tokens.forEach((t) => {
          addToken(t);
          if (t !== tokens[0] && !t.startsWith('-')) {
            if (!paths.includes(t)) paths.push(t);
          }
        });
      }
    });
  }
  return { actions, paths, allTokens };
}

export function redactSecrets(text: string): string {
  if (!text) return text;
  let redacted = text;

  // Refined Patterns: Only redact when attached to a known label to avoid masking hashes/paths
  redacted = redacted.replace(
    /(authorization:\s*(?:bearer|basic)\s+)[a-zA-Z0-9._\-\/\\=]+/gi,
    '$1********'
  );
  redacted = redacted.replace(
    /(api[_-]?key|secret|password|token)([:=]\s*['"]?)[a-zA-Z0-9._\-]{8,}/gi,
    '$1$2********'
  );

  return redacted;
}

interface EnvironmentConfig {
  requireApproval?: boolean;
}

interface Config {
  version?: string;
  settings: {
    mode: string;
    autoStartDaemon?: boolean;
    enableUndo?: boolean;
    enableHookLogDebug?: boolean;
    approvalTimeoutMs?: number;
    flightRecorder?: boolean;
    approvers: { native: boolean; browser: boolean; cloud: boolean; terminal: boolean };
    environment?: string;
  };
  policy: {
    sandboxPaths: string[];
    dangerousWords: string[];
    ignoredTools: string[];
    toolInspection: Record<string, string>;
    smartRules: SmartRule[];
    snapshot: {
      tools: string[];
      onlyPaths: string[];
      ignorePaths: string[];
    };
    dlp: {
      enabled: boolean;
      scanIgnoredTools: boolean;
    };
  };
  environments: Record<string, EnvironmentConfig>;
}

// Default Enterprise Posture
/*
export const DANGEROUS_WORDS = [
  'delete',
  'drop',
  'remove',
  'terminate',
  'refund',
  'write',
  'update',
  'destroy',
  'rm',
  'rmdir',
  'purge',
  'format',
];
*/
// Intentionally minimal — only words that are catastrophic AND never appear
// in legitimate code/content. Everything else is handled by smart rules,
// which can scope to specific tool fields and avoid false positives.
export const DANGEROUS_WORDS = [
  'mkfs', // formats/wipes a filesystem partition
  'shred', // permanently overwrites file contents (unrecoverable)
];

// 2. The Master Default Config
export const DEFAULT_CONFIG: Config = {
  version: '1.0',
  settings: {
    mode: 'audit',
    autoStartDaemon: true,
    enableUndo: true, // 🔥 ALWAYS TRUE BY DEFAULT for the safety net
    enableHookLogDebug: true,
    approvalTimeoutMs: 30000, // 30-second auto-deny timeout
    flightRecorder: true,
    approvers: { native: true, browser: true, cloud: false, terminal: true },
  },
  policy: {
    sandboxPaths: ['/tmp/**', '**/sandbox/**', '**/test-results/**'],
    dangerousWords: DANGEROUS_WORDS,
    ignoredTools: [
      'list_*',
      'get_*',
      'read_*',
      'describe_*',
      'read',
      'glob',
      'grep',
      'ls',
      'notebookread',
      'notebookedit',
      'webfetch',
      'websearch',
      'exitplanmode',
      'askuserquestion',
      'agent',
      'task*',
      'toolsearch',
      'mcp__ide__*',
      'getDiagnostics',
    ],
    toolInspection: {
      bash: 'command',
      shell: 'command',
      run_shell_command: 'command',
      'terminal.execute': 'command',
      'postgres:query': 'sql',
    },
    snapshot: {
      tools: [
        'str_replace_based_edit_tool',
        'write_file',
        'edit_file',
        'create_file',
        'edit',
        'replace',
      ],
      onlyPaths: [],
      ignorePaths: ['**/node_modules/**', 'dist/**', 'build/**', '.next/**', '**/*.log'],
    },
    smartRules: [
      // ── rm safety (critical — always evaluated first) ──────────────────────
      {
        name: 'block-rm-rf-home',
        tool: 'bash',
        conditionMode: 'all',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: 'rm\\b.*(-[rRfF]*[rR][rRfF]*|--recursive)',
          },
          {
            field: 'command',
            op: 'matches',
            value: '(~|\\/root(\\/|$)|\\$HOME|\\/home\\/)',
          },
        ],
        verdict: 'block',
        reason: 'Recursive delete of home directory is irreversible',
      },
      // ── SQL safety ────────────────────────────────────────────────────────
      {
        name: 'no-delete-without-where',
        tool: '*',
        conditions: [
          { field: 'sql', op: 'matches', value: '^(DELETE|UPDATE)\\s', flags: 'i' },
          { field: 'sql', op: 'notMatches', value: '\\bWHERE\\b', flags: 'i' },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'DELETE/UPDATE without WHERE clause — would affect every row in the table',
      },
      {
        name: 'review-drop-truncate-shell',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '\\b(DROP|TRUNCATE)\\s+(TABLE|DATABASE|SCHEMA|INDEX)',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'SQL DDL destructive statement inside a shell command',
      },
      // ── Git safety ────────────────────────────────────────────────────────
      {
        name: 'block-force-push',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '^\\s*git\\b.*\\bpush\\b.*(--force|--force-with-lease|-f\\b)',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'block',
        reason: 'Force push overwrites remote history and cannot be undone',
      },
      {
        name: 'review-git-push',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '^\\s*git\\b.*\\bpush\\b(?!.*(-f\\b|--force|--force-with-lease))',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'git push sends changes to a shared remote',
      },
      {
        name: 'review-git-destructive',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value:
              '^\\s*git\\b.*(reset\\s+--hard|clean\\s+-[fdxX]|\\brebase\\b|tag\\s+-d|branch\\s+-[dD])',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'Destructive git operation — discards history or working-tree changes',
      },
      // ── Shell safety ──────────────────────────────────────────────────────
      {
        name: 'review-sudo',
        tool: 'bash',
        conditions: [{ field: 'command', op: 'matches', value: '^\\s*sudo\\s', flags: 'i' }],
        conditionMode: 'all',
        verdict: 'review',
        reason: 'Command requires elevated privileges',
      },
      {
        name: 'review-curl-pipe-shell',
        tool: 'bash',
        conditions: [
          {
            field: 'command',
            op: 'matches',
            value: '(curl|wget)[^|]*\\|\\s*(ba|z|da|fi|c|k)?sh',
            flags: 'i',
          },
        ],
        conditionMode: 'all',
        verdict: 'block',
        reason: 'Piping remote script into a shell is a supply-chain attack vector',
      },
    ],
    dlp: { enabled: true, scanIgnoredTools: true },
  },
  environments: {},
};

// Advisory rm rules — appended LAST in getConfig() so user-defined smart rules
// (project/global/shield) are evaluated first and can override them.
// tool: '*' so they cover bash, shell, run_shell_command, and Gemini's Shell.
// Pattern '(^|&&|\|\||;)\s*rm\b' matches rm as a shell command (including in chained
// commands like 'cat foo && rm bar') but avoids false-positives on 'docker rm'.
const ADVISORY_SMART_RULES: SmartRule[] = [
  {
    name: 'allow-rm-safe-paths',
    tool: '*',
    conditionMode: 'all',
    conditions: [
      { field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' },
      {
        field: 'command',
        op: 'matches',
        // Matches known-safe build artifact paths in the command.
        value:
          '(node_modules|\\bdist\\b|\\.next|\\bcoverage\\b|\\.cache|\\btmp\\b|\\btemp\\b|\\.DS_Store)(\\/|\\s|$)',
      },
    ],
    verdict: 'allow',
    reason: 'Deleting a known-safe build artifact path',
  },
  {
    name: 'review-rm',
    tool: '*',
    conditions: [{ field: 'command', op: 'matches', value: '(^|&&|\\|\\||;)\\s*rm\\b' }],
    verdict: 'review',
    reason: 'rm can permanently delete files — confirm the target path',
  },
];

let cachedConfig: Config | null = null;

export function _resetConfigCache(): void {
  cachedConfig = null;
}

/**
 * Reads settings from the global config (~/.node9/config.json) only.
 * Intentionally does NOT merge project config — these are machine-level
 * preferences, not project policies.
 */
export function getGlobalSettings(): {
  mode: string;
  autoStartDaemon: boolean;
  slackEnabled: boolean;
  enableTrustSessions: boolean;
  allowGlobalPause: boolean;
} {
  try {
    const globalConfigPath = path.join(os.homedir(), '.node9', 'config.json');
    if (fs.existsSync(globalConfigPath)) {
      const parsed = JSON.parse(fs.readFileSync(globalConfigPath, 'utf-8')) as Record<
        string,
        unknown
      >;
      const settings = (parsed.settings as Record<string, unknown>) || {};
      return {
        mode: (settings.mode as string) || 'audit',
        autoStartDaemon: settings.autoStartDaemon !== false,
        slackEnabled: settings.slackEnabled !== false,
        enableTrustSessions: settings.enableTrustSessions === true,
        allowGlobalPause: settings.allowGlobalPause !== false,
      };
    }
  } catch {}
  return {
    mode: 'audit',
    autoStartDaemon: true,
    slackEnabled: true,
    enableTrustSessions: false,
    allowGlobalPause: true,
  };
}

/**
 * Returns true when a Slack API key is stored AND Slack is enabled in config.
 * Slack is the approval authority when this is true.
 */
export function hasSlack(): boolean {
  const creds = getCredentials();
  if (!creds?.apiKey) return false;
  return getGlobalSettings().slackEnabled;
}

/**
 * Reads the internal token from the daemon PID file.
 * Used by notifyDaemonViewer / resolveViaDaemon so the Slack flow can
 * register and clear viewer-mode cards without needing the CSRF token.
 */
function getInternalToken(): string | null {
  try {
    const pidFile = path.join(os.homedir(), '.node9', 'daemon.pid');
    if (!fs.existsSync(pidFile)) return null;
    const data = JSON.parse(fs.readFileSync(pidFile, 'utf-8')) as Record<string, unknown>;
    process.kill(data.pid as number, 0); // verify alive
    return (data.internalToken as string) ?? null;
  } catch {
    return null;
  }
}

export async function evaluatePolicy(
  toolName: string,
  args?: unknown,
  agent?: string
): Promise<{
  decision: 'allow' | 'review' | 'block';
  blockedByLabel?: string;
  reason?: string;
  matchedField?: string;
  matchedWord?: string;
  tier?: 1 | 2 | 3 | 4 | 5 | 6 | 7;
  ruleName?: string;
}> {
  const config = getConfig();

  // 1. Ignored tools (Fast Path) - Always allow these first
  if (matchesPattern(toolName, config.policy.ignoredTools)) return { decision: 'allow' };

  // 2. Smart Rules — raw args matching before tokenization
  if (config.policy.smartRules.length > 0) {
    const matchedRule = config.policy.smartRules.find(
      (rule) => matchesPattern(toolName, rule.tool) && evaluateSmartConditions(args, rule)
    );
    if (matchedRule) {
      if (matchedRule.verdict === 'allow')
        return { decision: 'allow', ruleName: matchedRule.name ?? matchedRule.tool };
      return {
        decision: matchedRule.verdict,
        blockedByLabel: `Smart Rule: ${matchedRule.name ?? matchedRule.tool}`,
        reason: matchedRule.reason,
        tier: 2,
        ruleName: matchedRule.name ?? matchedRule.tool,
      };
    }
  }

  let allTokens: string[] = [];
  let pathTokens: string[] = [];

  // 2. Tokenize the input
  const shellCommand = extractShellCommand(toolName, args, config.policy.toolInspection);
  if (shellCommand) {
    const analyzed = await analyzeShellCommand(shellCommand);
    allTokens = analyzed.allTokens;
    pathTokens = analyzed.paths;

    // Inline arbitrary code execution is always a review
    const INLINE_EXEC_PATTERN = /^(python3?|bash|sh|zsh|perl|ruby|node|php|lua)\s+(-c|-e|-eval)\s/i;
    if (INLINE_EXEC_PATTERN.test(shellCommand.trim())) {
      return { decision: 'review', blockedByLabel: 'Node9 Standard (Inline Execution)', tier: 3 };
    }

    // Strip DML keywords from tokens so user dangerousWords like "delete"/"update"
    // don't re-flag a SQL query that already passed the smart rules check above.
    if (isSqlTool(toolName, config.policy.toolInspection)) {
      allTokens = allTokens.filter((t) => !SQL_DML_KEYWORDS.has(t.toLowerCase()));
    }
  } else {
    allTokens = tokenize(toolName);

    // Deep scan: if this tool isn't in toolInspection, scan all arg values for dangerous words
    if (args && typeof args === 'object') {
      const flattenedArgs = JSON.stringify(args).toLowerCase();
      const extraTokens = flattenedArgs.split(/[^a-zA-Z0-9]+/).filter((t) => t.length > 1);
      allTokens.push(...extraTokens);
    }
  }

  // ── 3. CONTEXTUAL RISK DOWNGRADE (PRD Section 3 / Phase 3) ──────────────
  // If the human is typing manually, we only block "Nuclear" actions.
  // If the human is typing manually, we only block "Total System Disaster" actions.
  const isManual = agent === 'Terminal';
  if (isManual) {
    const SYSTEM_DISASTER_COMMANDS = ['mkfs', 'shred', 'dd', 'drop', 'truncate', 'purge'];

    const hasSystemDisaster = allTokens.some((t) =>
      SYSTEM_DISASTER_COMMANDS.includes(t.toLowerCase())
    );

    // Catch the most famous disaster: rm -rf /
    const isRootWipe =
      allTokens.includes('rm') && (allTokens.includes('/') || allTokens.includes('/*'));

    if (hasSystemDisaster || isRootWipe) {
      // If it IS a system disaster, return review so the dev gets a
      // "Manual Nuclear Protection" popup as a final safety check.
      return { decision: 'review', blockedByLabel: 'Manual Nuclear Protection', tier: 3 };
    }

    // For everything else (docker, psql, rmdir, delete, rm),
    // we trust the human and auto-allow.
    return { decision: 'allow' };
  }

  // ── 4. Sandbox Check (Safe Zones) ───────────────────────────────────────
  if (pathTokens.length > 0 && config.policy.sandboxPaths.length > 0) {
    const allInSandbox = pathTokens.every((p) => matchesPattern(p, config.policy.sandboxPaths));
    if (allInSandbox) return { decision: 'allow' };
  }

  // ── 5. Dangerous Words Evaluation ───────────────────────────────────────
  let matchedDangerousWord: string | undefined;
  const isDangerous = allTokens.some((token) =>
    config.policy.dangerousWords.some((word) => {
      const w = word.toLowerCase();
      const hit =
        token === w ||
        (() => {
          try {
            return new RegExp(`\\b${w}\\b`, 'i').test(token);
          } catch {
            return false;
          }
        })();
      if (hit && !matchedDangerousWord) matchedDangerousWord = word;
      return hit;
    })
  );

  if (isDangerous) {
    // Find which specific field contained the dangerous word for the UI
    let matchedField: string | undefined;
    if (matchedDangerousWord && args && typeof args === 'object' && !Array.isArray(args)) {
      const obj = args as Record<string, unknown>;
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
          try {
            if (
              new RegExp(
                `\\b${matchedDangerousWord.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`,
                'i'
              ).test(value)
            ) {
              matchedField = key;
              break;
            }
          } catch {
            /* ignore */
          }
        }
      }
    }
    return {
      decision: 'review',
      blockedByLabel: `Project/Global Config — dangerous word: "${matchedDangerousWord}"`,
      matchedWord: matchedDangerousWord,
      matchedField,
      tier: 6,
    };
  }

  // ── 7. Strict Mode Fallback ─────────────────────────────────────────────
  if (config.settings.mode === 'strict') {
    const envConfig = getActiveEnvironment(config);
    if (envConfig?.requireApproval === false) return { decision: 'allow' };
    return { decision: 'review', blockedByLabel: 'Global Config (Strict Mode Active)', tier: 7 };
  }

  return { decision: 'allow' };
}

// ── explainPolicy ─────────────────────────────────────────────────────────────

export interface ExplainStep {
  name: string;
  outcome: 'checked' | 'allow' | 'review' | 'block' | 'skip';
  detail: string;
  isFinal?: boolean;
}

export interface WaterfallTier {
  tier: number;
  label: string;
  status: 'active' | 'missing' | 'env';
  path?: string;
  note?: string;
}

export interface ExplainResult {
  tool: string;
  args: unknown;
  waterfall: WaterfallTier[];
  steps: ExplainStep[];
  decision: 'allow' | 'review' | 'block';
  blockedByLabel?: string;
  matchedToken?: string;
}

export async function explainPolicy(toolName: string, args?: unknown): Promise<ExplainResult> {
  const steps: ExplainStep[] = [];

  const globalPath = path.join(os.homedir(), '.node9', 'config.json');
  const projectPath = path.join(process.cwd(), 'node9.config.json');
  const credsPath = path.join(os.homedir(), '.node9', 'credentials.json');

  // ── Waterfall tiers ───────────────────────────────────────────────────────
  const waterfall: WaterfallTier[] = [
    {
      tier: 1,
      label: 'Env vars',
      status: 'env',
      note: process.env.NODE9_MODE ? `NODE9_MODE=${process.env.NODE9_MODE}` : 'not set',
    },
    {
      tier: 2,
      label: 'Cloud policy',
      status: fs.existsSync(credsPath) ? 'active' : 'missing',
      note: fs.existsSync(credsPath)
        ? 'credentials found (not evaluated in explain mode)'
        : 'not connected — run: node9 login',
    },
    {
      tier: 3,
      label: 'Project config',
      status: fs.existsSync(projectPath) ? 'active' : 'missing',
      path: projectPath,
    },
    {
      tier: 4,
      label: 'Global config',
      status: fs.existsSync(globalPath) ? 'active' : 'missing',
      path: globalPath,
    },
    {
      tier: 5,
      label: 'Defaults',
      status: 'active',
      note: 'always active',
    },
  ];

  const config = getConfig();

  // ── 0. DLP Content Scanner ────────────────────────────────────────────────
  const wouldBeIgnored = matchesPattern(toolName, config.policy.ignoredTools);
  if (config.policy.dlp.enabled && (!wouldBeIgnored || config.policy.dlp.scanIgnoredTools)) {
    const argsObjE =
      args && typeof args === 'object' && !Array.isArray(args)
        ? (args as Record<string, unknown>)
        : {};
    const filePathE = String(argsObjE.file_path ?? argsObjE.path ?? argsObjE.filename ?? '');
    const dlpMatch =
      (filePathE ? scanFilePath(filePathE) : null) ?? (args !== undefined ? scanArgs(args) : null);
    if (dlpMatch) {
      steps.push({
        name: 'DLP Content Scanner',
        outcome: dlpMatch.severity === 'block' ? 'block' : 'review',
        detail: `🚨 ${dlpMatch.patternName} detected in ${dlpMatch.fieldPath} — sample: ${dlpMatch.redactedSample}`,
        isFinal: dlpMatch.severity === 'block',
      });
      if (dlpMatch.severity === 'block') {
        return { tool: toolName, args, waterfall, steps, decision: 'block' };
      }
    } else {
      steps.push({
        name: 'DLP Content Scanner',
        outcome: 'checked',
        detail: 'No sensitive credentials detected in args',
      });
    }
  }

  // ── 1. Ignored tools ──────────────────────────────────────────────────────
  if (wouldBeIgnored) {
    steps.push({
      name: 'Ignored tools',
      outcome: 'allow',
      detail: `"${toolName}" matches ignoredTools pattern → fast-path allow`,
      isFinal: true,
    });
    return { tool: toolName, args, waterfall, steps, decision: 'allow' };
  }
  steps.push({
    name: 'Ignored tools',
    outcome: 'checked',
    detail: `"${toolName}" not in ignoredTools list`,
  });

  // ── 2. Smart Rules ────────────────────────────────────────────────────────
  if (config.policy.smartRules.length > 0) {
    const matchedRule = config.policy.smartRules.find(
      (rule) => matchesPattern(toolName, rule.tool) && evaluateSmartConditions(args, rule)
    );
    if (matchedRule) {
      const label = `Smart Rule: ${matchedRule.name ?? matchedRule.tool}`;
      if (matchedRule.verdict === 'allow') {
        steps.push({
          name: 'Smart rules',
          outcome: 'allow',
          detail: `${label} → allow`,
          isFinal: true,
        });
        return { tool: toolName, args, waterfall, steps, decision: 'allow' };
      }
      steps.push({
        name: 'Smart rules',
        outcome: matchedRule.verdict,
        detail: `${label} → ${matchedRule.verdict}${matchedRule.reason ? `: ${matchedRule.reason}` : ''}`,
        isFinal: true,
      });
      return {
        tool: toolName,
        args,
        waterfall,
        steps,
        decision: matchedRule.verdict,
        blockedByLabel: label,
      };
    }
    steps.push({
      name: 'Smart rules',
      outcome: 'checked',
      detail: `No smart rule matched "${toolName}"`,
    });
  } else {
    steps.push({ name: 'Smart rules', outcome: 'skip', detail: 'No smart rules configured' });
  }

  // ── 3. Input parsing ──────────────────────────────────────────────────────
  let allTokens: string[] = [];
  let pathTokens: string[] = [];

  const shellCommand = extractShellCommand(toolName, args, config.policy.toolInspection);
  if (shellCommand) {
    const analyzed = await analyzeShellCommand(shellCommand);
    allTokens = analyzed.allTokens;
    pathTokens = analyzed.paths;

    const patterns = Object.keys(config.policy.toolInspection);
    const matchingPattern = patterns.find((p) => matchesPattern(toolName, p));
    const fieldName = matchingPattern ? config.policy.toolInspection[matchingPattern] : 'command';
    steps.push({
      name: 'Input parsing',
      outcome: 'checked',
      detail: `Shell command via toolInspection["${matchingPattern ?? toolName}"] → field "${fieldName}": "${shellCommand}"`,
    });

    // ── 3. Inline exec ────────────────────────────────────────────────────
    const INLINE_EXEC_PATTERN = /^(python3?|bash|sh|zsh|perl|ruby|node|php|lua)\s+(-c|-e|-eval)\s/i;
    if (INLINE_EXEC_PATTERN.test(shellCommand.trim())) {
      steps.push({
        name: 'Inline execution',
        outcome: 'review',
        detail: 'Inline code execution detected (e.g. "bash -c ...") — always requires review',
        isFinal: true,
      });
      return {
        tool: toolName,
        args,
        waterfall,
        steps,
        decision: 'review',
        blockedByLabel: 'Node9 Standard (Inline Execution)',
      };
    }
    steps.push({
      name: 'Inline execution',
      outcome: 'checked',
      detail: 'No inline execution pattern detected',
    });

    // ── 4. SQL DML keyword stripping ──────────────────────────────────────
    // SQL WHERE safety is handled by smart rules above. Here we only strip
    // DML keywords so dangerous-word checks don't re-flag a validated query.
    if (isSqlTool(toolName, config.policy.toolInspection)) {
      allTokens = allTokens.filter((t) => !SQL_DML_KEYWORDS.has(t.toLowerCase()));
      steps.push({
        name: 'SQL token stripping',
        outcome: 'checked',
        detail: 'DML keywords stripped from tokens (SQL safety handled by smart rules)',
      });
    }
  } else {
    allTokens = tokenize(toolName);
    let detail = `No toolInspection match for "${toolName}" — tokens: [${allTokens.join(', ')}]`;
    if (args && typeof args === 'object') {
      const flattenedArgs = JSON.stringify(args).toLowerCase();
      const extraTokens = flattenedArgs.split(/[^a-zA-Z0-9]+/).filter((t) => t.length > 1);
      allTokens.push(...extraTokens);
      const preview = extraTokens.slice(0, 8).join(', ') + (extraTokens.length > 8 ? '…' : '');
      detail += ` + deep scan of args: [${preview}]`;
    }
    steps.push({ name: 'Input parsing', outcome: 'checked', detail });
  }

  // ── 4. Tokens ─────────────────────────────────────────────────────────────
  const uniqueTokens = [...new Set(allTokens)];
  steps.push({
    name: 'Tokens scanned',
    outcome: 'checked',
    detail: `[${uniqueTokens.join(', ')}]`,
  });

  // ── 5. Sandbox paths ──────────────────────────────────────────────────────
  if (pathTokens.length > 0 && config.policy.sandboxPaths.length > 0) {
    const allInSandbox = pathTokens.every((p) => matchesPattern(p, config.policy.sandboxPaths));
    if (allInSandbox) {
      steps.push({
        name: 'Sandbox paths',
        outcome: 'allow',
        detail: `[${pathTokens.join(', ')}] all match sandbox patterns → auto-allow`,
        isFinal: true,
      });
      return { tool: toolName, args, waterfall, steps, decision: 'allow' };
    }
    const unmatched = pathTokens.filter((p) => !matchesPattern(p, config.policy.sandboxPaths));
    steps.push({
      name: 'Sandbox paths',
      outcome: 'checked',
      detail: `[${unmatched.join(', ')}] not in sandbox — not auto-allowed`,
    });
  } else {
    steps.push({
      name: 'Sandbox paths',
      outcome: 'skip',
      detail:
        pathTokens.length === 0 ? 'No path tokens found in input' : 'No sandbox paths configured',
    });
  }

  // ── 6. Dangerous words ────────────────────────────────────────────────────
  let matchedDangerousWord: string | undefined;
  const isDangerous = uniqueTokens.some((token) =>
    config.policy.dangerousWords.some((word) => {
      const w = word.toLowerCase();
      const hit =
        token === w ||
        (() => {
          try {
            return new RegExp(`\\b${w}\\b`, 'i').test(token);
          } catch {
            return false;
          }
        })();
      if (hit && !matchedDangerousWord) matchedDangerousWord = word;
      return hit;
    })
  );
  if (isDangerous) {
    steps.push({
      name: 'Dangerous words',
      outcome: 'review',
      detail: `"${matchedDangerousWord}" found in token list`,
      isFinal: true,
    });
    return {
      tool: toolName,
      args,
      waterfall,
      steps,
      decision: 'review',
      blockedByLabel: `Project/Global Config — dangerous word: "${matchedDangerousWord}"`,
      matchedToken: matchedDangerousWord,
    };
  }
  steps.push({
    name: 'Dangerous words',
    outcome: 'checked',
    detail: `No dangerous words matched`,
  });

  // ── 8. Strict mode ────────────────────────────────────────────────────────
  if (config.settings.mode === 'strict') {
    steps.push({
      name: 'Strict mode',
      outcome: 'review',
      detail: 'Mode is "strict" — all tools require approval unless explicitly allowed',
      isFinal: true,
    });
    return {
      tool: toolName,
      args,
      waterfall,
      steps,
      decision: 'review',
      blockedByLabel: 'Global Config (Strict Mode Active)',
    };
  }
  steps.push({
    name: 'Strict mode',
    outcome: 'skip',
    detail: `Mode is "${config.settings.mode}" — no catch-all review`,
  });

  return { tool: toolName, args, waterfall, steps, decision: 'allow' };
}

/** Returns true when toolName matches an ignoredTools pattern (fast-path, silent allow). */
export function isIgnoredTool(toolName: string): boolean {
  const config = getConfig();
  return matchesPattern(toolName, config.policy.ignoredTools);
}

const DAEMON_PORT = 7391;
const DAEMON_HOST = '127.0.0.1';

export function isDaemonRunning(): boolean {
  const pidFile = path.join(os.homedir(), '.node9', 'daemon.pid');

  if (fs.existsSync(pidFile)) {
    // PID file present — trust it: live PID → running, dead PID → not running
    try {
      const { pid, port } = JSON.parse(fs.readFileSync(pidFile, 'utf-8'));
      if (port !== DAEMON_PORT) return false;
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }

  // No PID file — port check catches orphaned daemons (PID file was lost)
  try {
    const r = spawnSync('ss', ['-Htnp', `sport = :${DAEMON_PORT}`], {
      encoding: 'utf8',
      timeout: 500,
    });
    return r.status === 0 && (r.stdout ?? '').includes(`:${DAEMON_PORT}`);
  } catch {
    return false;
  }
}

export function getPersistentDecision(toolName: string): 'allow' | 'deny' | null {
  try {
    const file = path.join(os.homedir(), '.node9', 'decisions.json');
    if (!fs.existsSync(file)) return null;
    const decisions = JSON.parse(fs.readFileSync(file, 'utf-8')) as Record<string, string>;
    const d = decisions[toolName];
    if (d === 'allow' || d === 'deny') return d;
  } catch {
    /* ignore */
  }
  return null;
}

async function askDaemon(
  toolName: string,
  args: unknown,
  meta?: { agent?: string; mcpServer?: string },
  signal?: AbortSignal,
  riskMetadata?: RiskMetadata,
  activityId?: string
): Promise<'allow' | 'deny' | 'abandoned'> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;

  // Custom abort logic for Node 18 compatibility
  const checkCtrl = new AbortController();
  const checkTimer = setTimeout(() => checkCtrl.abort(), 5000);
  const onAbort = () => checkCtrl.abort();
  if (signal) signal.addEventListener('abort', onAbort);

  try {
    const checkRes = await fetch(`${base}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolName,
        args,
        agent: meta?.agent,
        mcpServer: meta?.mcpServer,
        fromCLI: true,
        // Pass the flight-recorder ID so the daemon uses the same UUID for
        // activity-result as the CLI used for the pending activity event.
        // Without this, the two UUIDs never match and tail.ts never resolves
        // the pending item.
        activityId,
        ...(riskMetadata && { riskMetadata }),
      }),
      signal: checkCtrl.signal,
    });
    if (!checkRes.ok) throw new Error('Daemon fail');
    const { id } = (await checkRes.json()) as { id: string };

    const waitCtrl = new AbortController();
    const waitTimer = setTimeout(() => waitCtrl.abort(), 120_000);
    const onWaitAbort = () => waitCtrl.abort();
    if (signal) signal.addEventListener('abort', onWaitAbort);

    try {
      const waitRes = await fetch(`${base}/wait/${id}`, { signal: waitCtrl.signal });
      if (!waitRes.ok) return 'deny';
      const { decision } = (await waitRes.json()) as { decision: string };
      if (decision === 'allow') return 'allow';
      if (decision === 'abandoned') return 'abandoned';
      return 'deny';
    } finally {
      clearTimeout(waitTimer);
      if (signal) signal.removeEventListener('abort', onWaitAbort);
    }
  } finally {
    clearTimeout(checkTimer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

/** Register a viewer-mode card on the daemon (Slack is the real authority). */
async function notifyDaemonViewer(
  toolName: string,
  args: unknown,
  meta?: { agent?: string; mcpServer?: string },
  riskMetadata?: RiskMetadata
): Promise<string> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  const res = await fetch(`${base}/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      toolName,
      args,
      slackDelegated: true,
      agent: meta?.agent,
      mcpServer: meta?.mcpServer,
      ...(riskMetadata && { riskMetadata }),
    }),
    signal: AbortSignal.timeout(3000),
  });
  if (!res.ok) throw new Error('Daemon unreachable');
  const { id } = (await res.json()) as { id: string };
  return id;
}

/** Clear a viewer-mode card from the daemon once Slack has decided. */
async function resolveViaDaemon(
  id: string,
  decision: 'allow' | 'deny',
  internalToken: string
): Promise<void> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  await fetch(`${base}/resolve/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Node9-Internal': internalToken },
    body: JSON.stringify({ decision }),
    signal: AbortSignal.timeout(3000),
  });
}

/**
 * Authorization state machine — 6 states based on:
 *   hasSlack()      = credentials.json exists AND slackEnabled
 *   isDaemonRunning = local approval daemon on localhost:7391
 *   allowTerminalFallback = caller allows interactive Y/N
 *
 * State table:
 *  hasSlack | daemon | result
 *  -------- | ------ | ------
 *  true     | yes    | Slack authority + daemon viewer card
 *  true     | no     | Slack authority only (no browser)
 *  false    | yes    | Browser authority
 *  false    | no     | noApprovalMechanism  (CLI auto-starts daemon if autoStartDaemon=true)
 *  false    | no+TTY | terminal Y/N prompt  (when allowTerminalFallback=true)
 *  false    | no+noTTY | block
 */
export interface AuthResult {
  approved: boolean;
  reason?: string;
  noApprovalMechanism?: boolean;
  blockedByLabel?: string;
  blockedBy?:
    | 'team-policy'
    | 'persistent-deny'
    | 'local-config'
    | 'local-decision'
    | 'no-approval-mechanism'
    | 'timeout';
  changeHint?: string;
  checkedBy?:
    | 'cloud'
    | 'daemon'
    | 'terminal'
    | 'local-policy'
    | 'persistent'
    | 'trust'
    | 'paused'
    | 'audit';
}

// ── Flight Recorder — fire-and-forget socket notify ──────────────────────────
const ACTIVITY_SOCKET_PATH =
  process.platform === 'win32'
    ? '\\\\.\\pipe\\node9-activity'
    : path.join(os.tmpdir(), 'node9-activity.sock');

// Returns a Promise so callers can await socket flush before process.exit().
// Without await, process.exit(0) kills the socket mid-connect for fast-passing
// tools (Read, Glob, Grep, etc.), making them invisible in node9 tail.
function notifyActivity(data: {
  id: string;
  ts: number;
  tool: string;
  args?: unknown;
  status: string;
  label?: string;
}): Promise<void> {
  return new Promise<void>((resolve) => {
    try {
      const payload = JSON.stringify(data);
      const sock = net.createConnection(ACTIVITY_SOCKET_PATH);
      sock.on('connect', () => {
        // Attach listeners before calling end() so events fired synchronously
        // on the loopback socket are not missed.
        sock.on('close', resolve);
        sock.end(payload);
      });
      sock.on('error', resolve); // daemon not running — resolve immediately
    } catch {
      resolve();
    }
  });
}

export async function authorizeHeadless(
  toolName: string,
  args: unknown,
  allowTerminalFallback = false,
  meta?: { agent?: string; mcpServer?: string },
  options?: { calledFromDaemon?: boolean }
): Promise<AuthResult> {
  // Skip socket notification when called from daemon — daemon already broadcasts via SSE
  if (!options?.calledFromDaemon) {
    const actId = randomUUID();
    const actTs = Date.now();
    await notifyActivity({ id: actId, ts: actTs, tool: toolName, args, status: 'pending' });
    const result = await _authorizeHeadlessCore(toolName, args, allowTerminalFallback, meta, {
      ...options,
      activityId: actId,
    });
    // noApprovalMechanism means no channels were available — the CLI will retry
    // after auto-starting the daemon. Don't log a false 'block' to the flight
    // recorder; the retry call will produce the real result notification.
    if (!result.noApprovalMechanism) {
      await notifyActivity({
        id: actId,
        tool: toolName,
        ts: actTs,
        status: result.approved
          ? 'allow'
          : result.blockedByLabel?.includes('DLP')
            ? 'dlp'
            : 'block',
        label: result.blockedByLabel,
      });
    }
    return result;
  }
  return _authorizeHeadlessCore(toolName, args, allowTerminalFallback, meta, options);
}

async function _authorizeHeadlessCore(
  toolName: string,
  args: unknown,
  allowTerminalFallback = false,
  meta?: { agent?: string; mcpServer?: string },
  options?: { calledFromDaemon?: boolean; activityId?: string }
): Promise<AuthResult> {
  if (process.env.NODE9_PAUSED === '1') return { approved: true, checkedBy: 'paused' };
  const pauseState = checkPause();
  if (pauseState.paused) return { approved: true, checkedBy: 'paused' };

  const creds = getCredentials();
  const config = getConfig();

  // 1. Check if we are in any kind of test environment (Vitest, CI, or E2E)
  const isTestEnv = !!(
    process.env.VITEST ||
    process.env.NODE_ENV === 'test' ||
    process.env.CI ||
    process.env.NODE9_TESTING === '1'
  );

  // 2. Clone the config object!
  // This prevents us from accidentally mutating the global config cache.
  const approvers = {
    ...(config.settings.approvers || { native: true, browser: true, cloud: true, terminal: true }),
  };

  // 3. THE TEST SILENCER: Hard-disable all physical UIs in test/CI environments.
  // We leave 'cloud' untouched so your SaaS/Cloud tests can still manage it via mock configs.
  if (isTestEnv) {
    approvers.native = false;
    approvers.browser = false;
    approvers.terminal = false;
  }

  if (config.settings.enableHookLogDebug && !isTestEnv) {
    appendHookDebug(toolName, args, meta);
  }

  const isManual = meta?.agent === 'Terminal';

  let explainableLabel = 'Local Config';
  let policyMatchedField: string | undefined;
  let policyMatchedWord: string | undefined;
  let riskMetadata: RiskMetadata | undefined;

  // ── DLP CONTENT SCANNER ───────────────────────────────────────────────────
  // Runs before ignored-tool fast path and audit mode so that a leaked
  // credential is always caught — even for "safe" tools like web_search.
  if (
    config.policy.dlp.enabled &&
    (!isIgnoredTool(toolName) || config.policy.dlp.scanIgnoredTools)
  ) {
    // P1-1/P1-2: Check file path first (blocks read attempts before content is returned,
    // and resolves symlinks to prevent escape attacks).
    const argsObj =
      args && typeof args === 'object' && !Array.isArray(args)
        ? (args as Record<string, unknown>)
        : {};
    const filePath = String(argsObj.file_path ?? argsObj.path ?? argsObj.filename ?? '');
    const dlpMatch: DlpMatch | null = (filePath ? scanFilePath(filePath) : null) ?? scanArgs(args);
    if (dlpMatch) {
      const dlpReason =
        `🚨 DATA LOSS PREVENTION: ${dlpMatch.patternName} detected in ` +
        `field "${dlpMatch.fieldPath}" (${dlpMatch.redactedSample})`;
      if (dlpMatch.severity === 'block') {
        if (!isManual) appendLocalAudit(toolName, args, 'deny', 'dlp-block', meta);
        return {
          approved: false,
          reason: dlpReason,
          blockedBy: 'local-config',
          blockedByLabel: '🚨 Node9 DLP (Secret Detected)',
        };
      }
      // severity === 'review': fall through to the race engine with a DLP label.
      // Write an audit entry now so the DLP flag is traceable even if the race
      // engine later approves the call without recording why it was intercepted.
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'dlp-review-flagged', meta);
      explainableLabel = '🚨 Node9 DLP (Credential Review)';
    }
  }

  if (config.settings.mode === 'audit') {
    if (!isIgnoredTool(toolName)) {
      const policyResult = await evaluatePolicy(toolName, args, meta?.agent);
      if (policyResult.decision === 'review') {
        appendLocalAudit(toolName, args, 'allow', 'audit-mode', meta);
        // Must await — process.exit(0) follows immediately and kills any fire-and-forget fetch.
        // Only send to SaaS when cloud is enabled — respects privacy mode (cloud: false).
        if (approvers.cloud && creds?.apiKey) {
          await auditLocalAllow(toolName, args, 'audit-mode', creds, meta);
        }
        sendDesktopNotification(
          'Node9 Audit Mode',
          `Would have blocked "${toolName}" (${policyResult.blockedByLabel || 'Local Config'}) — running in audit mode`
        );
      }
    }
    return { approved: true, checkedBy: 'audit' };
  }

  // Fast Paths (Ignore, Trust, Policy Allow)
  if (!isIgnoredTool(toolName)) {
    if (getActiveTrustSession(toolName)) {
      if (approvers.cloud && creds?.apiKey)
        await auditLocalAllow(toolName, args, 'trust', creds, meta);
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'trust', meta);
      return { approved: true, checkedBy: 'trust' };
    }
    const policyResult = await evaluatePolicy(toolName, args, meta?.agent);
    if (policyResult.decision === 'allow') {
      if (approvers.cloud && creds?.apiKey)
        auditLocalAllow(toolName, args, 'local-policy', creds, meta);
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'local-policy', meta);
      return { approved: true, checkedBy: 'local-policy' };
    }

    // Hard block from smart rules — skip the race engine entirely
    if (policyResult.decision === 'block') {
      if (!isManual) appendLocalAudit(toolName, args, 'deny', 'smart-rule-block', meta);
      return {
        approved: false,
        reason: policyResult.reason ?? 'Action explicitly blocked by Smart Policy.',
        blockedBy: 'local-config',
        blockedByLabel: policyResult.blockedByLabel,
      };
    }

    explainableLabel = policyResult.blockedByLabel || 'Local Config';
    policyMatchedField = policyResult.matchedField;
    policyMatchedWord = policyResult.matchedWord;
    riskMetadata = computeRiskMetadata(
      args,
      policyResult.tier ?? 6,
      explainableLabel,
      policyMatchedField,
      policyMatchedWord,
      policyResult.ruleName
    );

    const persistent = getPersistentDecision(toolName);
    if (persistent === 'allow') {
      if (approvers.cloud && creds?.apiKey)
        await auditLocalAllow(toolName, args, 'persistent', creds, meta);
      if (!isManual) appendLocalAudit(toolName, args, 'allow', 'persistent', meta);
      return { approved: true, checkedBy: 'persistent' };
    }
    if (persistent === 'deny') {
      if (!isManual) appendLocalAudit(toolName, args, 'deny', 'persistent-deny', meta);
      return {
        approved: false,
        reason: `This tool ("${toolName}") is explicitly listed in your 'Always Deny' list.`,
        blockedBy: 'persistent-deny',
        blockedByLabel: 'Persistent User Rule',
      };
    }
  } else {
    // ignoredTools (read, glob, grep, ls…) fire on every agent operation — too
    // frequent and too noisy to send to the SaaS audit log.
    if (!isManual) appendLocalAudit(toolName, args, 'allow', 'ignored', meta);
    return { approved: true };
  }

  // ── THE HANDSHAKE (Phase 4.1: Remote Lock Check) ──────────────────────────
  let cloudRequestId: string | null = null;
  let isRemoteLocked = false;
  const cloudEnforced = approvers.cloud && !!creds?.apiKey;

  if (cloudEnforced) {
    try {
      const initResult = await initNode9SaaS(toolName, args, creds!, meta, riskMetadata);

      if (!initResult.pending) {
        // Shadow mode: allowed through, but warn the developer passively
        if (initResult.shadowMode) {
          console.error(
            chalk.yellow(
              `\n⚠️  Node9 Shadow Mode: Action allowed, but would have been blocked by company policy.`
            )
          );
          if (initResult.shadowReason) {
            console.error(chalk.dim(`   Reason: ${initResult.shadowReason}\n`));
          }
          return { approved: true, checkedBy: 'cloud' };
        }
        return {
          approved: !!initResult.approved,
          reason:
            initResult.reason ||
            (initResult.approved ? undefined : 'Action rejected by organization policy.'),
          checkedBy: initResult.approved ? 'cloud' : undefined,
          blockedBy: initResult.approved ? undefined : 'team-policy',
          blockedByLabel: 'Organization Policy (SaaS)',
        };
      }

      cloudRequestId = initResult.requestId || null;
      isRemoteLocked = !!initResult.remoteApprovalOnly; // 🔒 THE GOVERNANCE LOCK
      explainableLabel = 'Organization Policy (SaaS)';
    } catch (err: unknown) {
      const error = err as Error;
      const isAuthError = error.message.includes('401') || error.message.includes('403');
      const isNetworkError =
        error.message.includes('fetch') ||
        error.name === 'AbortError' ||
        error.message.includes('ECONNREFUSED');

      const reason = isAuthError
        ? 'Invalid or missing API key. Run `node9 login` to generate a key (must start with n9_live_).'
        : isNetworkError
          ? 'Could not reach the Node9 cloud. Check your network or API URL.'
          : error.message;

      console.error(
        chalk.yellow(`\n⚠️  Node9: Cloud API Handshake failed — ${reason}`) +
          chalk.dim(`\n   Falling back to local rules...\n`)
      );
    }
  }

  // ── TERMINAL STATUS ─────────────────────────────────────────────────────────
  // Print before the race so the message is guaranteed to show regardless of
  // which channel wins (cloud message was previously lost when native popup
  // resolved first and aborted the race before pollNode9SaaS could print it).
  // Skip when called from the daemon — the CLI already printed this message.
  if (!options?.calledFromDaemon) {
    if (cloudEnforced && cloudRequestId) {
      console.error(
        chalk.yellow('\n🛡️  Node9: Action suspended — waiting for Organization approval.')
      );
      console.error(
        chalk.cyan('   Dashboard  → ') + chalk.bold('Mission Control > Activity Feed\n')
      );
    } else if (!cloudEnforced) {
      const cloudOffReason = !creds?.apiKey
        ? 'no API key — run `node9 login` to connect'
        : 'privacy mode (cloud disabled)';
      console.error(
        chalk.dim(`\n🛡️  Node9: intercepted "${toolName}" — cloud off (${cloudOffReason})\n`)
      );
    }
  }

  // ── THE MULTI-CHANNEL RACE ENGINE ──────────────────────────────────────────
  const abortController = new AbortController();
  const { signal } = abortController;
  const racePromises: Promise<AuthResult>[] = [];

  // ⏱️ RACER 0: Approval Timeout
  const approvalTimeoutMs = config.settings.approvalTimeoutMs ?? 0;
  if (approvalTimeoutMs > 0) {
    racePromises.push(
      new Promise<AuthResult>((resolve, reject) => {
        const timer = setTimeout(() => {
          resolve({
            approved: false,
            reason: `No human response within ${approvalTimeoutMs / 1000}s — auto-denied by timeout policy.`,
            blockedBy: 'timeout',
            blockedByLabel: 'Approval Timeout',
          });
        }, approvalTimeoutMs);
        signal.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(new Error('Aborted'));
        });
      })
    );
  }

  let viewerId: string | null = null;
  const internalToken = getInternalToken();

  // 🏁 RACER 1: Cloud SaaS Channel (The Poller)
  if (cloudEnforced && cloudRequestId) {
    racePromises.push(
      (async () => {
        try {
          if (isDaemonRunning() && internalToken && !options?.calledFromDaemon) {
            viewerId = await notifyDaemonViewer(toolName, args, meta, riskMetadata).catch(
              () => null
            );
          }
          const cloudResult = await pollNode9SaaS(cloudRequestId, creds!, signal);

          return {
            approved: cloudResult.approved,
            reason: cloudResult.approved
              ? undefined
              : cloudResult.reason || 'Action rejected by organization administrator via Slack.',
            checkedBy: cloudResult.approved ? 'cloud' : undefined,
            blockedBy: cloudResult.approved ? undefined : 'team-policy',
            blockedByLabel: 'Organization Policy (SaaS)',
          };
        } catch (err: unknown) {
          const error = err as Error;
          if (error.name === 'AbortError' || error.message?.includes('Aborted')) throw err;
          throw err;
        }
      })()
    );
  }

  // 🏁 RACER 2: Native OS Popup
  // Skip when called from the daemon's background pipeline — the CLI already
  // launched this popup as part of its own race; firing it a second time from
  // the daemon would show a duplicate popup for the same request.
  if (approvers.native && !isManual && !options?.calledFromDaemon) {
    racePromises.push(
      (async () => {
        // Pass isRemoteLocked so the popup knows to hide the "Allow" button
        const decision = await askNativePopup(
          toolName,
          args,
          meta?.agent,
          explainableLabel,
          isRemoteLocked,
          signal,
          policyMatchedField,
          policyMatchedWord
        );

        if (decision === 'always_allow') {
          writeTrustSession(toolName, 3600000);
          return { approved: true, checkedBy: 'trust' };
        }

        const isApproved = decision === 'allow';
        return {
          approved: isApproved,
          reason: isApproved
            ? undefined
            : "The human user clicked 'Block' on the system dialog window.",
          checkedBy: isApproved ? 'daemon' : undefined,
          blockedBy: isApproved ? undefined : 'local-decision',
          blockedByLabel: 'User Decision (Native)',
        };
      })()
    );
  }

  // 🏁 RACER 3: Browser Dashboard
  // Skip when cloudEnforced — notifyDaemonViewer already created a viewer card on
  // the dashboard. Running askDaemon on top would create a second duplicate entry,
  // open a second browser tab, and fire a second daemon authorizeHeadless call.
  if (approvers.browser && isDaemonRunning() && !options?.calledFromDaemon && !cloudEnforced) {
    racePromises.push(
      (async () => {
        try {
          if (!approvers.native && !cloudEnforced) {
            console.error(
              chalk.yellow('\n🛡️  Node9: Action suspended — waiting for browser approval.')
            );
            console.error(chalk.cyan(`   URL → http://${DAEMON_HOST}:${DAEMON_PORT}/\n`));
          }

          const daemonDecision = await askDaemon(
            toolName,
            args,
            meta,
            signal,
            riskMetadata,
            options?.activityId
          );
          if (daemonDecision === 'abandoned') throw new Error('Abandoned');

          const isApproved = daemonDecision === 'allow';
          return {
            approved: isApproved,
            reason: isApproved
              ? undefined
              : 'The human user rejected this action via the Node9 Browser Dashboard.',
            checkedBy: isApproved ? 'daemon' : undefined,
            blockedBy: isApproved ? undefined : 'local-decision',
            blockedByLabel: 'User Decision (Browser)',
          };
        } catch (err) {
          throw err;
        }
      })()
    );
  }

  // 🏁 RACER 4: Terminal Prompt
  if (approvers.terminal && allowTerminalFallback && process.stdout.isTTY) {
    racePromises.push(
      (async () => {
        try {
          if (explainableLabel.includes('DLP')) {
            console.log(chalk.bgRed.white.bold(` 🚨 NODE9 DLP ALERT — CREDENTIAL DETECTED `));
            console.log(
              chalk.red.bold(`   A sensitive secret was detected in the tool arguments!`)
            );
          } else {
            console.log(chalk.bgRed.white.bold(` 🛑 NODE9 INTERCEPTOR `));
          }
          console.log(`${chalk.bold('Action:')} ${chalk.red(toolName)}`);
          console.log(`${chalk.bold('Flagged By:')} ${chalk.yellow(explainableLabel)}`);

          if (isRemoteLocked) {
            console.log(chalk.yellow(`⚡ LOCKED BY ADMIN POLICY: Waiting for Slack Approval...\n`));
            // If locked, we don't ask [Y/n]. We just keep the promise alive until the SaaS wins and aborts it.
            await new Promise((_, reject) => {
              signal.addEventListener('abort', () => reject(new Error('Aborted by SaaS')));
            });
          }

          const TIMEOUT_MS = 60_000;
          let timer: NodeJS.Timeout;
          const result = await new Promise<boolean>((resolve, reject) => {
            timer = setTimeout(() => reject(new Error('Terminal Timeout')), TIMEOUT_MS);
            confirm(
              { message: `Authorize? (auto-deny in ${TIMEOUT_MS / 1000}s)`, default: false },
              { signal }
            )
              .then(resolve)
              .catch(reject);
          });
          clearTimeout(timer!);

          return {
            approved: result,
            reason: result
              ? undefined
              : "The human user typed 'N' in the terminal to reject this action.",
            checkedBy: result ? 'terminal' : undefined,
            blockedBy: result ? undefined : 'local-decision',
            blockedByLabel: 'User Decision (Terminal)',
          };
        } catch (err: unknown) {
          const error = err as Error;
          if (
            error.name === 'AbortError' ||
            error.message?.includes('Prompt was canceled') ||
            error.message?.includes('Aborted by SaaS')
          )
            throw err;
          if (error.message === 'Terminal Timeout') {
            return {
              approved: false,
              reason: 'The terminal prompt timed out without a human response.',
              blockedBy: 'local-decision',
            };
          }
          throw err;
        }
      })()
    );
  }

  // 🏆 RESOLVE THE RACE
  if (racePromises.length === 0) {
    return {
      approved: false,
      noApprovalMechanism: true,
      reason:
        `NODE9 SECURITY INTERVENTION: Action blocked by automated policy [${explainableLabel}].\n` +
        `REASON: Action blocked because no approval channels are available. (Native/Browser UI is disabled in config, and this terminal is non-interactive).`,
      blockedBy: 'no-approval-mechanism',
      blockedByLabel: explainableLabel,
    };
  }

  const finalResult = await new Promise<AuthResult>((resolve) => {
    let resolved = false;
    let failures = 0;
    const total = racePromises.length;

    const finish = (res: AuthResult) => {
      if (!resolved) {
        resolved = true;
        abortController.abort(); // KILL THE LOSERS

        if (viewerId && internalToken) {
          resolveViaDaemon(viewerId, res.approved ? 'allow' : 'deny', internalToken).catch(
            () => null
          );
        }

        resolve(res);
      }
    };

    for (const p of racePromises) {
      p.then(finish).catch((err) => {
        if (
          err.name === 'AbortError' ||
          err.message?.includes('canceled') ||
          err.message?.includes('Aborted')
        )
          return;
        // 'Abandoned' means the browser dashboard closed without deciding.
        // Don't silently swallow it — that would leave the race promise hanging
        // forever when the browser racer is the only channel.
        if (err.message === 'Abandoned') {
          finish({
            approved: false,
            reason: 'Browser dashboard closed without making a decision.',
            blockedBy: 'local-decision',
            blockedByLabel: 'Browser Dashboard (Abandoned)',
          });
          return;
        }
        failures++;
        if (failures === total && !resolved) {
          finish({ approved: false, reason: 'All approval channels failed or disconnected.' });
        }
      });
    }
  });

  // If a LOCAL channel (native/browser/terminal) won while the cloud had a
  // pending request open, report the decision back to the SaaS so Mission
  // Control doesn't stay stuck on PENDING forever.
  // We await this (not fire-and-forget) because the CLI process may exit
  // immediately after this function returns, killing any in-flight fetch.
  if (cloudRequestId && creds && finalResult.checkedBy !== 'cloud') {
    await resolveNode9SaaS(cloudRequestId, creds, finalResult.approved);
  }

  if (!isManual) {
    appendLocalAudit(
      toolName,
      args,
      finalResult.approved ? 'allow' : 'deny',
      finalResult.checkedBy || finalResult.blockedBy || 'unknown',
      meta
    );
  }

  return finalResult;
}

/**
 * Returns the names of all saved profiles in ~/.node9/credentials.json.
 * Returns [] when the file doesn't exist or uses the legacy flat format.
 */
export function listCredentialProfiles(): string[] {
  try {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (!fs.existsSync(credPath)) return [];
    const creds = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;
    if (!creds.apiKey) return Object.keys(creds).filter((k) => typeof creds[k] === 'object');
  } catch {}
  return [];
}

export function getConfig(cwd?: string): Config {
  // When an explicit cwd is provided (hook commands passing payload.cwd), skip
  // the cache entirely — each project directory may have its own node9.config.json,
  // and we must not pollute the ambient cache used by the interactive CLI.
  if (!cwd && cachedConfig) return cachedConfig;

  const globalPath = path.join(os.homedir(), '.node9', 'config.json');
  // If cwd doesn't exist on disk, tryLoadConfig returns null and the project
  // config layer is simply skipped — global config + defaults are used instead.
  // This is intentional: a nonexistent cwd (e.g. deleted project, stale hook)
  // must not crash; it falls back gracefully to the global config.
  const projectPath = path.join(cwd ?? process.cwd(), 'node9.config.json');

  const globalConfig = tryLoadConfig(globalPath);
  const projectConfig = tryLoadConfig(projectPath);

  const mergedSettings = {
    ...DEFAULT_CONFIG.settings,
    approvers: { ...DEFAULT_CONFIG.settings.approvers },
  };
  const mergedPolicy = {
    sandboxPaths: [...DEFAULT_CONFIG.policy.sandboxPaths],
    dangerousWords: [...DEFAULT_CONFIG.policy.dangerousWords],
    ignoredTools: [...DEFAULT_CONFIG.policy.ignoredTools],
    toolInspection: { ...DEFAULT_CONFIG.policy.toolInspection },
    smartRules: [...DEFAULT_CONFIG.policy.smartRules],
    snapshot: {
      tools: [...DEFAULT_CONFIG.policy.snapshot.tools],
      onlyPaths: [...DEFAULT_CONFIG.policy.snapshot.onlyPaths],
      ignorePaths: [...DEFAULT_CONFIG.policy.snapshot.ignorePaths],
    },
    dlp: { ...DEFAULT_CONFIG.policy.dlp },
  };
  const mergedEnvironments: Record<string, EnvironmentConfig> = { ...DEFAULT_CONFIG.environments };

  const applyLayer = (source: Record<string, unknown> | null) => {
    if (!source) return;
    const s = (source.settings || {}) as Partial<Config['settings']>;
    const p = (source.policy || {}) as Partial<Config['policy']>;

    if (s.mode !== undefined) mergedSettings.mode = s.mode;
    if (s.autoStartDaemon !== undefined) mergedSettings.autoStartDaemon = s.autoStartDaemon;
    if (s.enableUndo !== undefined) mergedSettings.enableUndo = s.enableUndo;
    if (s.enableHookLogDebug !== undefined)
      mergedSettings.enableHookLogDebug = s.enableHookLogDebug;
    if (s.approvers) mergedSettings.approvers = { ...mergedSettings.approvers, ...s.approvers };
    if (s.approvalTimeoutMs !== undefined) mergedSettings.approvalTimeoutMs = s.approvalTimeoutMs;
    if (s.environment !== undefined) mergedSettings.environment = s.environment;

    if (p.sandboxPaths) mergedPolicy.sandboxPaths.push(...p.sandboxPaths);
    if (p.ignoredTools) mergedPolicy.ignoredTools.push(...p.ignoredTools);
    // This allows a project to relax global restrictions.
    if (p.dangerousWords) mergedPolicy.dangerousWords = [...p.dangerousWords];

    if (p.toolInspection)
      mergedPolicy.toolInspection = { ...mergedPolicy.toolInspection, ...p.toolInspection };
    if (p.smartRules) mergedPolicy.smartRules.push(...p.smartRules);
    if (p.snapshot) {
      const s = p.snapshot as Partial<Config['policy']['snapshot']>;
      if (s.tools) mergedPolicy.snapshot.tools.push(...s.tools);
      if (s.onlyPaths) mergedPolicy.snapshot.onlyPaths.push(...s.onlyPaths);
      if (s.ignorePaths) mergedPolicy.snapshot.ignorePaths.push(...s.ignorePaths);
    }
    if (p.dlp) {
      const d = p.dlp as Partial<Config['policy']['dlp']>;
      if (d.enabled !== undefined) mergedPolicy.dlp.enabled = d.enabled;
      if (d.scanIgnoredTools !== undefined) mergedPolicy.dlp.scanIgnoredTools = d.scanIgnoredTools;
    }

    const envs = (source.environments || {}) as Record<string, unknown>;
    for (const [envName, envConfig] of Object.entries(envs)) {
      if (envConfig && typeof envConfig === 'object') {
        const ec = envConfig as Record<string, unknown>;
        mergedEnvironments[envName] = {
          ...mergedEnvironments[envName],
          // Validate field types before merging — do not blindly spread user input
          ...(typeof ec.requireApproval === 'boolean'
            ? { requireApproval: ec.requireApproval }
            : {}),
        };
      }
    }
  };

  applyLayer(globalConfig);
  applyLayer(projectConfig);

  // ── Shield layer ──────────────────────────────────────────────────────────
  // Shields are applied after user config so they cannot be overridden locally.
  // Rules are sourced from the in-memory catalog, not from config.json — so
  // enabling a shield never mutates the user's config file.
  for (const shieldName of readActiveShields()) {
    const shield = getShield(shieldName);
    if (!shield) continue;
    // Deduplicate smartRules by name — prevents duplicates if the user also
    // has the same rule name in their config (shouldn't happen, but be safe).
    const existingRuleNames = new Set(mergedPolicy.smartRules.map((r) => r.name));
    for (const rule of shield.smartRules) {
      if (!existingRuleNames.has(rule.name)) mergedPolicy.smartRules.push(rule);
    }
    const existingWords = new Set(mergedPolicy.dangerousWords);
    for (const word of shield.dangerousWords) {
      if (!existingWords.has(word)) mergedPolicy.dangerousWords.push(word);
    }
  }

  // Advisory rm rules are always appended last so user-defined rules (project/global/shield)
  // are evaluated first and can override default rm behaviour.
  const existingAdvisoryNames = new Set(mergedPolicy.smartRules.map((r) => r.name));
  for (const rule of ADVISORY_SMART_RULES) {
    if (!existingAdvisoryNames.has(rule.name)) mergedPolicy.smartRules.push(rule);
  }

  if (process.env.NODE9_MODE) mergedSettings.mode = process.env.NODE9_MODE as string;

  mergedPolicy.sandboxPaths = [...new Set(mergedPolicy.sandboxPaths)];
  mergedPolicy.dangerousWords = [...new Set(mergedPolicy.dangerousWords)];
  mergedPolicy.ignoredTools = [...new Set(mergedPolicy.ignoredTools)];
  mergedPolicy.snapshot.tools = [...new Set(mergedPolicy.snapshot.tools)];
  mergedPolicy.snapshot.onlyPaths = [...new Set(mergedPolicy.snapshot.onlyPaths)];
  mergedPolicy.snapshot.ignorePaths = [...new Set(mergedPolicy.snapshot.ignorePaths)];

  const result: Config = {
    settings: mergedSettings,
    policy: mergedPolicy,
    environments: mergedEnvironments,
  };

  // Only populate the cache when using the ambient cwd — explicit cwd calls are
  // per-project and must not overwrite the cached interactive-CLI config.
  if (!cwd) cachedConfig = result;

  return result;
}

function tryLoadConfig(filePath: string): Record<string, unknown> | null {
  if (!fs.existsSync(filePath)) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `\n⚠️  Node9: Failed to parse ${filePath}\n   ${msg}\n   → Using default config\n\n`
    );
    return null;
  }
  const SUPPORTED_VERSION = '1.0';
  const SUPPORTED_MAJOR = SUPPORTED_VERSION.split('.')[0];
  const fileVersion = (raw as Record<string, unknown>)?.version;
  if (fileVersion !== undefined) {
    const vStr = String(fileVersion);
    const fileMajor = vStr.split('.')[0];
    if (fileMajor !== SUPPORTED_MAJOR) {
      process.stderr.write(
        `\n❌  Node9: Config at ${filePath} has version "${vStr}" — major version is incompatible with this release (expected "${SUPPORTED_VERSION}"). Config will not be loaded.\n\n`
      );
      return null;
    } else if (vStr !== SUPPORTED_VERSION) {
      process.stderr.write(
        `\n⚠️  Node9: Config at ${filePath} declares version "${vStr}" — expected "${SUPPORTED_VERSION}". Continuing with best-effort parsing.\n\n`
      );
    }
  }

  const { sanitized, error } = sanitizeConfig(raw);
  if (error) {
    process.stderr.write(
      `\n⚠️  Node9: Invalid config at ${filePath}:\n${error.replace('Invalid config:\n', '')}\n   → Invalid fields ignored, using defaults for those keys\n\n`
    );
  }
  return sanitized;
}

function getActiveEnvironment(config: Config): EnvironmentConfig | null {
  const env = config.settings.environment || process.env.NODE_ENV || 'development';
  return config.environments[env] ?? null;
}

export function getCredentials() {
  const DEFAULT_API_URL = 'https://api.node9.ai/api/v1/intercept';
  if (process.env.NODE9_API_KEY) {
    return {
      apiKey: process.env.NODE9_API_KEY,
      apiUrl: process.env.NODE9_API_URL || DEFAULT_API_URL,
    };
  }
  try {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (fs.existsSync(credPath)) {
      const creds = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;
      const profileName = process.env.NODE9_PROFILE || 'default';
      const profile = creds[profileName] as Record<string, unknown> | undefined;

      if (profile?.apiKey) {
        return {
          apiKey: profile.apiKey as string,
          apiUrl: (profile.apiUrl as string) || DEFAULT_API_URL,
        };
      }
      if (creds.apiKey) {
        return {
          apiKey: creds.apiKey as string,
          apiUrl: (creds.apiUrl as string) || DEFAULT_API_URL,
        };
      }
    }
  } catch {}
  return null;
}

export async function authorizeAction(toolName: string, args: unknown): Promise<boolean> {
  const result = await authorizeHeadless(toolName, args, true);
  return result.approved;
}

export interface CloudApprovalResult {
  approved: boolean;
  reason?: string;
  remoteApprovalOnly?: boolean;
}

/**
 * Send an audit record to the SaaS backend for a locally fast-pathed call.
 * Returns a Promise so callers that precede process.exit(0) can await it.
 * Failures are silently ignored — never blocks the agent.
 */
function auditLocalAllow(
  toolName: string,
  args: unknown,
  checkedBy: string,
  creds: { apiKey: string; apiUrl: string },
  meta?: { agent?: string; mcpServer?: string }
): Promise<void> {
  return fetch(`${creds.apiUrl}/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${creds.apiKey}` },
    body: JSON.stringify({
      toolName,
      args,
      checkedBy,
      context: {
        agent: meta?.agent,
        mcpServer: meta?.mcpServer,
        hostname: os.hostname(),
        cwd: process.cwd(),
        platform: os.platform(),
      },
    }),
    signal: AbortSignal.timeout(5000),
  })
    .then(() => {})
    .catch(() => {});
}

/**
 * STEP 1: The Handshake. Runs BEFORE the local UI is spawned to check for locks.
 */
async function initNode9SaaS(
  toolName: string,
  args: unknown,
  creds: { apiKey: string; apiUrl: string },
  meta?: { agent?: string; mcpServer?: string },
  riskMetadata?: RiskMetadata
): Promise<{
  pending: boolean;
  requestId?: string;
  approved?: boolean;
  reason?: string;
  remoteApprovalOnly?: boolean;
  shadowMode?: boolean;
  shadowReason?: string;
}> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(creds.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${creds.apiKey}` },
      body: JSON.stringify({
        toolName,
        args,
        context: {
          agent: meta?.agent,
          mcpServer: meta?.mcpServer,
          hostname: os.hostname(),
          cwd: process.cwd(),
          platform: os.platform(),
        },
        ...(riskMetadata && { riskMetadata }),
      }),
      signal: controller.signal,
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    // FIX: Using TypeScript 'as' casting to resolve the unknown type error
    return (await response.json()) as {
      pending: boolean;
      requestId?: string;
      approved?: boolean;
      reason?: string;
      remoteApprovalOnly?: boolean;
      shadowMode?: boolean;
      shadowReason?: string;
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * STEP 2: The Poller. Runs INSIDE the Race Engine.
 */
async function pollNode9SaaS(
  requestId: string,
  creds: { apiKey: string; apiUrl: string },
  signal: AbortSignal
): Promise<CloudApprovalResult> {
  const statusUrl = `${creds.apiUrl}/status/${requestId}`;
  const POLL_INTERVAL_MS = 1000;
  const POLL_DEADLINE = Date.now() + 10 * 60 * 1000;

  while (Date.now() < POLL_DEADLINE) {
    if (signal.aborted) throw new Error('Aborted');
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));

    try {
      const pollCtrl = new AbortController();
      const pollTimer = setTimeout(() => pollCtrl.abort(), 5000);
      const statusRes = await fetch(statusUrl, {
        headers: { Authorization: `Bearer ${creds.apiKey}` },
        signal: pollCtrl.signal,
      });
      clearTimeout(pollTimer);

      if (!statusRes.ok) continue;

      // FIX: Using TypeScript 'as' casting to resolve the unknown type error
      const { status, reason } = (await statusRes.json()) as { status: string; reason?: string };

      if (status === 'APPROVED') {
        console.error(chalk.green('✅  Approved via Cloud.\n'));
        return { approved: true, reason };
      }
      if (status === 'DENIED' || status === 'AUTO_BLOCKED' || status === 'TIMED_OUT') {
        console.error(chalk.red('❌  Denied via Cloud.\n'));
        return { approved: false, reason };
      }
    } catch {
      /* transient network error */
    }
  }
  return { approved: false, reason: 'Cloud approval timed out after 10 minutes.' };
}

/**
 * Reports a locally-made decision (native/browser/terminal) back to the SaaS
 * so the pending request doesn't stay stuck in Mission Control.
 */
async function resolveNode9SaaS(
  requestId: string,
  creds: { apiKey: string; apiUrl: string },
  approved: boolean
): Promise<void> {
  try {
    const resolveUrl = `${creds.apiUrl}/requests/${requestId}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    await fetch(resolveUrl, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${creds.apiKey}` },
      body: JSON.stringify({ decision: approved ? 'APPROVED' : 'DENIED' }),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
  } catch {
    /* fire-and-forget — don't block the proxy on a network error */
  }
}
