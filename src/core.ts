// src/core.ts
import chalk from 'chalk';
import { confirm } from '@inquirer/prompts';
import fs from 'fs';
import path from 'path';
import os from 'os';
import pm from 'picomatch';
import { parse } from 'sh-syntax';
import { askNativePopup, sendDesktopNotification } from './ui/native';

// ── Feature file paths ────────────────────────────────────────────────────────
const PAUSED_FILE = path.join(os.homedir(), '.node9', 'PAUSED');
const TRUST_FILE = path.join(os.homedir(), '.node9', 'trust.json');

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

function appendAuditModeEntry(toolName: string, args: unknown): void {
  try {
    const entry = JSON.stringify({
      ts: new Date().toISOString(),
      tool: toolName,
      args,
      decision: 'would-have-blocked',
      source: 'audit-mode',
    });
    const logPath = path.join(os.homedir(), '.node9', 'audit.log');
    const dir = path.dirname(logPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(logPath, entry + '\n');
  } catch {}
}

// Default Enterprise Posture
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
  slackChannel?: string;
}

interface PolicyRule {
  action: string;
  allowPaths?: string[];
  blockPaths?: string[];
}

interface Config {
  settings: {
    mode: string;
    autoStartDaemon?: boolean;
    enableUndo?: boolean;
    enableHookLogDebug?: boolean;
    approvers: { native: boolean; browser: boolean; cloud: boolean; terminal: boolean };
  };
  policy: {
    sandboxPaths: string[];
    dangerousWords: string[];
    ignoredTools: string[];
    toolInspection: Record<string, string>;
    rules: PolicyRule[];
  };
  environments: Record<string, EnvironmentConfig>;
}

const DEFAULT_CONFIG: Config = {
  settings: {
    mode: 'standard',
    autoStartDaemon: true,
    enableUndo: false,
    enableHookLogDebug: false,
    approvers: { native: true, browser: true, cloud: true, terminal: true },
  },
  policy: {
    sandboxPaths: [],
    dangerousWords: DANGEROUS_WORDS,
    ignoredTools: [
      'list_*',
      'get_*',
      'read_*',
      'describe_*',
      'read',
      'grep',
      'ls',
      'askuserquestion',
    ],
    toolInspection: { bash: 'command', shell: 'command' },
    rules: [{ action: 'rm', allowPaths: ['**/node_modules/**', 'dist/**', '.DS_Store'] }],
  },
  environments: {},
};

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
        mode: (settings.mode as string) || 'standard',
        autoStartDaemon: settings.autoStartDaemon !== false,
        slackEnabled: settings.slackEnabled !== false,
        enableTrustSessions: settings.enableTrustSessions === true,
        allowGlobalPause: settings.allowGlobalPause !== false,
      };
    }
  } catch {}
  return {
    mode: 'standard',
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
  agent?: string // NEW: Added agent metadata parameter
): Promise<{ decision: 'allow' | 'review'; blockedByLabel?: string }> {
  const config = getConfig();

  // 1. Ignored tools (Fast Path) - Always allow these first
  if (matchesPattern(toolName, config.policy.ignoredTools)) return { decision: 'allow' };

  let allTokens: string[] = [];
  let actionTokens: string[] = [];
  let pathTokens: string[] = [];

  // 2. Tokenize the input
  const shellCommand = extractShellCommand(toolName, args, config.policy.toolInspection);
  if (shellCommand) {
    const analyzed = await analyzeShellCommand(shellCommand);
    allTokens = analyzed.allTokens;
    actionTokens = analyzed.actions;
    pathTokens = analyzed.paths;

    // Inline arbitrary code execution is always a review
    const INLINE_EXEC_PATTERN = /^(python3?|bash|sh|zsh|perl|ruby|node|php|lua)\s+(-c|-e|-eval)\s/i;
    if (INLINE_EXEC_PATTERN.test(shellCommand.trim())) {
      return { decision: 'review', blockedByLabel: 'Node9 Standard (Inline Execution)' };
    }
  } else {
    allTokens = tokenize(toolName);
    actionTokens = [toolName];
  }

  // ── 3. CONTEXTUAL RISK DOWNGRADE (PRD Section 3 / Phase 3) ──────────────
  // If the human is typing manually, we only block "Nuclear" actions.
  const isManual = agent === 'Terminal';
  if (isManual) {
    const NUCLEAR_COMMANDS = [
      'drop',
      'destroy',
      'purge',
      'rmdir',
      'format',
      'truncate',
      'alter',
      'grant',
      'revoke',
      'docker',
    ];

    const hasNuclear = allTokens.some((t) => NUCLEAR_COMMANDS.includes(t.toLowerCase()));

    // If it's manual and NOT nuclear, we auto-allow (bypass standard "dangerous" words like 'rm' or 'delete')
    if (!hasNuclear) return { decision: 'allow' };

    // If it IS nuclear, we fall through to the standard logic so the developer
    // gets a "Flagged By: Manual Nuclear Protection" popup.
  }

  // ── 4. Sandbox Check (Safe Zones) ───────────────────────────────────────
  if (pathTokens.length > 0 && config.policy.sandboxPaths.length > 0) {
    const allInSandbox = pathTokens.every((p) => matchesPattern(p, config.policy.sandboxPaths));
    if (allInSandbox) return { decision: 'allow' };
  }

  // ── 5. Rules Evaluation ─────────────────────────────────────────────────
  for (const action of actionTokens) {
    const rule = config.policy.rules.find(
      (r) => r.action === action || matchesPattern(action, r.action)
    );
    if (rule) {
      if (pathTokens.length > 0) {
        const anyBlocked = pathTokens.some((p) => matchesPattern(p, rule.blockPaths || []));
        if (anyBlocked)
          return { decision: 'review', blockedByLabel: 'Project/Global Config (Rule Block)' };
        const allAllowed = pathTokens.every((p) => matchesPattern(p, rule.allowPaths || []));
        if (allAllowed) return { decision: 'allow' };
      }
      return { decision: 'review', blockedByLabel: 'Project/Global Config (Rule Default Block)' };
    }
  }

  // ── 6. Dangerous Words Evaluation ───────────────────────────────────────
  const isDangerous = allTokens.some((token) =>
    config.policy.dangerousWords.some((word) => {
      const w = word.toLowerCase();
      if (token === w) return true;
      try {
        return new RegExp(`\\b${w}\\b`, 'i').test(token);
      } catch {
        return false;
      }
    })
  );

  if (isDangerous) {
    // Use "Project/Global Config" so E2E tests can verify hierarchy overrides
    const label = isManual ? 'Manual Nuclear Protection' : 'Project/Global Config (Dangerous Word)';
    return { decision: 'review', blockedByLabel: label };
  }

  // ── 7. Strict Mode Fallback ─────────────────────────────────────────────
  if (config.settings.mode === 'strict') {
    const envConfig = getActiveEnvironment(config);
    if (envConfig?.requireApproval === false) return { decision: 'allow' };
    return { decision: 'review', blockedByLabel: 'Global Config (Strict Mode Active)' };
  }

  return { decision: 'allow' };
}

/** Returns true when toolName matches an ignoredTools pattern (fast-path, silent allow). */
export function isIgnoredTool(toolName: string): boolean {
  const config = getConfig();
  return matchesPattern(toolName, config.policy.ignoredTools);
}

const DAEMON_PORT = 7391;
const DAEMON_HOST = '127.0.0.1';

export function isDaemonRunning(): boolean {
  try {
    const pidFile = path.join(os.homedir(), '.node9', 'daemon.pid');
    if (!fs.existsSync(pidFile)) return false;
    const { pid, port } = JSON.parse(fs.readFileSync(pidFile, 'utf-8'));
    if (port !== DAEMON_PORT) return false;
    process.kill(pid, 0);
    return true;
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
  signal?: AbortSignal // NEW: Added signal
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
      body: JSON.stringify({ toolName, args, agent: meta?.agent, mcpServer: meta?.mcpServer }),
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
  meta?: { agent?: string; mcpServer?: string }
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
    | 'no-approval-mechanism';
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

export async function authorizeHeadless(
  toolName: string,
  args: unknown,
  allowTerminalFallback = false,
  meta?: { agent?: string; mcpServer?: string }
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

  const isManual = meta?.agent === 'Terminal';

  let explainableLabel = 'Local Config';

  if (config.settings.mode === 'audit') {
    if (!isIgnoredTool(toolName)) {
      const policyResult = await evaluatePolicy(toolName, args, meta?.agent);
      if (policyResult.decision === 'review') {
        appendAuditModeEntry(toolName, args);
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
      if (creds?.apiKey) auditLocalAllow(toolName, args, 'trust', creds, meta);
      return { approved: true, checkedBy: 'trust' };
    }
    const policyResult = await evaluatePolicy(toolName, args, meta?.agent);
    if (policyResult.decision === 'allow') {
      if (creds?.apiKey) auditLocalAllow(toolName, args, 'local-policy', creds, meta);
      return { approved: true, checkedBy: 'local-policy' };
    }

    explainableLabel = policyResult.blockedByLabel || 'Local Config';

    const persistent = getPersistentDecision(toolName);
    if (persistent === 'allow') {
      if (creds?.apiKey) auditLocalAllow(toolName, args, 'persistent', creds, meta);
      return { approved: true, checkedBy: 'persistent' };
    }
    if (persistent === 'deny') {
      return {
        approved: false,
        reason: `This tool ("${toolName}") is explicitly listed in your 'Always Deny' list.`,
        blockedBy: 'persistent-deny',
        blockedByLabel: 'Persistent User Rule',
      };
    }
  } else {
    if (creds?.apiKey) auditLocalAllow(toolName, args, 'ignoredTools', creds, meta);
    return { approved: true };
  }

  // ── THE HANDSHAKE (Phase 4.1: Remote Lock Check) ──────────────────────────
  let cloudRequestId: string | null = null;
  let isRemoteLocked = false;
  const cloudEnforced = approvers.cloud && !!creds?.apiKey;

  if (cloudEnforced) {
    try {
      const envConfig = getActiveEnvironment(getConfig());
      const initResult = await initNode9SaaS(toolName, args, creds!, envConfig?.slackChannel, meta);

      if (!initResult.pending) {
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
  if (cloudEnforced && cloudRequestId) {
    console.error(
      chalk.yellow('\n🛡️  Node9: Action suspended — waiting for Organization approval.')
    );
    console.error(chalk.cyan('   Dashboard  → ') + chalk.bold('Mission Control > Activity Feed\n'));
  } else if (!cloudEnforced) {
    const cloudOffReason = !creds?.apiKey
      ? 'no API key — run `node9 login` to connect'
      : 'privacy mode (cloud disabled)';
    console.error(
      chalk.dim(`\n🛡️  Node9: intercepted "${toolName}" — cloud off (${cloudOffReason})\n`)
    );
  }

  // ── THE MULTI-CHANNEL RACE ENGINE ──────────────────────────────────────────
  const abortController = new AbortController();
  const { signal } = abortController;
  const racePromises: Promise<AuthResult>[] = [];

  let viewerId: string | null = null;
  const internalToken = getInternalToken();

  // 🏁 RACER 1: Cloud SaaS Channel (The Poller)
  if (cloudEnforced && cloudRequestId) {
    racePromises.push(
      (async () => {
        try {
          if (isDaemonRunning() && internalToken) {
            viewerId = await notifyDaemonViewer(toolName, args, meta).catch(() => null);
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
  if (approvers.native && !isManual) {
    racePromises.push(
      (async () => {
        // Pass isRemoteLocked so the popup knows to hide the "Allow" button
        const decision = await askNativePopup(
          toolName,
          args,
          meta?.agent,
          explainableLabel,
          isRemoteLocked,
          signal
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
  if (approvers.browser && isDaemonRunning()) {
    racePromises.push(
      (async () => {
        try {
          if (!approvers.native && !cloudEnforced) {
            console.error(
              chalk.yellow('\n🛡️  Node9: Action suspended — waiting for browser approval.')
            );
            console.error(chalk.cyan(`   URL → http://${DAEMON_HOST}:${DAEMON_PORT}/\n`));
          }

          const daemonDecision = await askDaemon(toolName, args, meta, signal);
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
          console.log(chalk.bgRed.white.bold(` 🛑 NODE9 INTERCEPTOR `));
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

export function getConfig(): Config {
  if (cachedConfig) return cachedConfig;

  const globalPath = path.join(os.homedir(), '.node9', 'config.json');
  const projectPath = path.join(process.cwd(), 'node9.config.json');

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
    rules: [...DEFAULT_CONFIG.policy.rules],
  };

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

    if (p.sandboxPaths) mergedPolicy.sandboxPaths.push(...p.sandboxPaths);
    if (p.dangerousWords) mergedPolicy.dangerousWords = [...p.dangerousWords];
    if (p.ignoredTools) mergedPolicy.ignoredTools.push(...p.ignoredTools);

    if (p.toolInspection)
      mergedPolicy.toolInspection = { ...mergedPolicy.toolInspection, ...p.toolInspection };
    if (p.rules) mergedPolicy.rules.push(...p.rules);
  };

  applyLayer(globalConfig);
  applyLayer(projectConfig);

  if (process.env.NODE9_MODE) mergedSettings.mode = process.env.NODE9_MODE as string;

  mergedPolicy.sandboxPaths = [...new Set(mergedPolicy.sandboxPaths)];
  mergedPolicy.dangerousWords = [...new Set(mergedPolicy.dangerousWords)];
  mergedPolicy.ignoredTools = [...new Set(mergedPolicy.ignoredTools)];

  cachedConfig = {
    settings: mergedSettings,
    policy: mergedPolicy,
    environments: {},
  };

  return cachedConfig;
}

function tryLoadConfig(filePath: string): Record<string, unknown> | null {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function getActiveEnvironment(config: Config): EnvironmentConfig | null {
  const env = process.env.NODE_ENV || 'development';
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
 * Fire-and-forget: send an audit record to the backend for a locally fast-pathed call.
 * Never blocks the agent — failures are silently ignored.
 */
function auditLocalAllow(
  toolName: string,
  args: unknown,
  checkedBy: string,
  creds: { apiKey: string; apiUrl: string },
  meta?: { agent?: string; mcpServer?: string }
): void {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 5000);

  fetch(`${creds.apiUrl}/audit`, {
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
    signal: controller.signal,
  }).catch(() => {});
}

/**
 * STEP 1: The Handshake. Runs BEFORE the local UI is spawned to check for locks.
 */
async function initNode9SaaS(
  toolName: string,
  args: unknown,
  creds: { apiKey: string; apiUrl: string },
  slackChannel?: string,
  meta?: { agent?: string; mcpServer?: string }
): Promise<{
  pending: boolean;
  requestId?: string;
  approved?: boolean;
  reason?: string;
  remoteApprovalOnly?: boolean;
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
        slackChannel,
        context: {
          agent: meta?.agent,
          mcpServer: meta?.mcpServer,
          hostname: os.hostname(),
          cwd: process.cwd(),
          platform: os.platform(),
        },
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
