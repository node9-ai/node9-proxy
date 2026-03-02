// src/core.ts
import chalk from 'chalk';
import { confirm } from '@inquirer/prompts';
import fs from 'fs';
import path from 'path';
import os from 'os';
import pm from 'picomatch';
import { parse } from 'sh-syntax';

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

function containsDangerousWord(toolName: string, dangerousWords: string[]): boolean {
  const tokens = tokenize(toolName);
  return dangerousWords.some((word) => tokens.includes(word.toLowerCase()));
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
  settings: { mode: string; autoStartDaemon?: boolean };
  policy: {
    dangerousWords: string[];
    ignoredTools: string[];
    toolInspection: Record<string, string>;
    rules: PolicyRule[];
  };
  environments: Record<string, EnvironmentConfig>;
}

const DEFAULT_CONFIG: Config = {
  settings: { mode: 'standard' },
  policy: {
    dangerousWords: DANGEROUS_WORDS,
    ignoredTools: [
      'list_*',
      'get_*',
      'read_*',
      'describe_*',
      'read',
      'write',
      'edit',
      'multiedit',
      'glob',
      'grep',
      'ls',
      'notebookread',
      'notebookedit',
      'todoread',
      'todowrite',
      'webfetch',
      'websearch',
      'exitplanmode',
      'askuserquestion',
    ],
    toolInspection: {
      bash: 'command',
      run_shell_command: 'command',
      shell: 'command',
      'terminal.execute': 'command',
    },
    rules: [
      { action: 'rm', allowPaths: ['**/node_modules/**', 'dist/**', 'build/**', '.DS_Store'] },
    ],
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
  agentMode: boolean;
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
        // agentMode defaults to false — user must explicitly opt in via `node9 login`
        agentMode: settings.agentMode === true,
      };
    }
  } catch {}
  return { mode: 'standard', autoStartDaemon: true, slackEnabled: true, agentMode: false };
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
  args?: unknown
): Promise<'allow' | 'review'> {
  const config = getConfig();
  if (matchesPattern(toolName, config.policy.ignoredTools)) return 'allow';
  const shellCommand = extractShellCommand(toolName, args, config.policy.toolInspection);
  if (shellCommand) {
    const { actions, paths, allTokens } = await analyzeShellCommand(shellCommand);

    // Inline interpreter execution (python3 -c, bash -c, perl -e, node -e, etc.)
    // is arbitrary code execution regardless of what the inner script does.
    const INLINE_EXEC_PATTERN = /^(python3?|bash|sh|zsh|perl|ruby|node|php|lua)\s+(-c|-e|-eval)\s/i;
    if (INLINE_EXEC_PATTERN.test(shellCommand.trim())) return 'review';

    for (const action of actions) {
      const basename = action.includes('/') ? action.split('/').pop() : action;
      const rule = config.policy.rules.find(
        (r) =>
          r.action === action ||
          matchesPattern(action, r.action) ||
          (basename && (r.action === basename || matchesPattern(basename, r.action)))
      );
      if (rule) {
        if (paths.length > 0) {
          const anyBlocked = paths.some((p) => matchesPattern(p, rule.blockPaths || []));
          if (anyBlocked) return 'review';
          const allAllowed = paths.every((p) => matchesPattern(p, rule.allowPaths || []));
          if (allAllowed) return 'allow';
        }
        return 'review';
      }
    }

    // Check tokens for dangerous words using word-boundary matching to avoid
    // false positives like "remake" matching "make" or "updated_at" matching "update".
    // Whole-token exact match is also accepted (handles tokens without word boundaries).
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
    if (isDangerous) return 'review';
    if (config.settings.mode === 'strict') return 'review';
    return 'allow';
  }
  const isDangerous = containsDangerousWord(toolName, config.policy.dangerousWords);
  if (isDangerous || config.settings.mode === 'strict') {
    const envConfig = getActiveEnvironment(config);
    if (envConfig?.requireApproval === false) return 'allow';
    return 'review';
  }
  return 'allow';
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
  meta?: { agent?: string; mcpServer?: string }
): Promise<'allow' | 'deny' | 'abandoned'> {
  const base = `http://${DAEMON_HOST}:${DAEMON_PORT}`;
  const checkRes = await fetch(`${base}/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ toolName, args, agent: meta?.agent, mcpServer: meta?.mcpServer }),
    signal: AbortSignal.timeout(5000),
  });
  if (!checkRes.ok) throw new Error('Daemon fail');
  const { id } = (await checkRes.json()) as { id: string };
  const waitRes = await fetch(`${base}/wait/${id}`, { signal: AbortSignal.timeout(120_000) });
  if (!waitRes.ok) return 'deny';
  const { decision } = (await waitRes.json()) as { decision: string };
  if (decision === 'allow') return 'allow';
  if (decision === 'abandoned') return 'abandoned';
  return 'deny';
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
  /** What caused the block — used to print a targeted "where to fix it" hint. */
  blockedBy?:
    | 'team-policy'
    | 'persistent-deny'
    | 'local-config'
    | 'local-decision'
    | 'no-approval-mechanism';
  changeHint?: string;
  /** Where the approval decision was made — set only for non-trivial approvals so
   *  the CLI can surface a visible confirmation line (mirrors Gemini's hook UI). */
  checkedBy?: 'cloud' | 'daemon' | 'local-policy' | 'persistent';
}

export async function authorizeHeadless(
  toolName: string,
  args: unknown,
  allowTerminalFallback = false,
  meta?: { agent?: string; mcpServer?: string }
): Promise<AuthResult> {
  const { agentMode } = getGlobalSettings();
  // Cloud enforcement is active only when the user explicitly opted in (agentMode: true)
  // AND cloud credentials are present. Otherwise local config is the authority.
  const cloudEnforced = agentMode && hasSlack();

  if (!cloudEnforced) {
    // Fast path: ignored tools are silently allowed — no checkedBy, no UI feedback.
    if (isIgnoredTool(toolName)) return { approved: true };

    const policyDecision = await evaluatePolicy(toolName, args);
    if (policyDecision === 'allow') return { approved: true, checkedBy: 'local-policy' };

    const persistent = getPersistentDecision(toolName);
    if (persistent === 'allow') return { approved: true, checkedBy: 'persistent' };
    if (persistent === 'deny')
      return {
        approved: false,
        reason: `Node9: "${toolName}" is set to always deny.`,
        blockedBy: 'persistent-deny',
        changeHint: `Open the daemon UI to manage decisions:  node9 daemon --openui`,
      };
  }

  // ── Cloud / team policy is the authority ─────────────────────────────────
  if (cloudEnforced) {
    const creds = getCredentials()!;
    const envConfig = getActiveEnvironment(getConfig());

    // Register a viewer card on the daemon if it's running, so the browser
    // shows the pending action (with disabled buttons — cloud decides).
    let viewerId: string | null = null;
    const internalToken = getInternalToken();
    if (isDaemonRunning() && internalToken) {
      viewerId = await notifyDaemonViewer(toolName, args, meta).catch(() => null);
    }

    const approved = await callNode9SaaS(toolName, args, creds, envConfig?.slackChannel, meta);

    if (viewerId && internalToken) {
      resolveViaDaemon(viewerId, approved ? 'allow' : 'deny', internalToken).catch(() => null);
    }

    return {
      approved,
      checkedBy: approved ? 'cloud' : undefined,
      blockedBy: approved ? undefined : 'team-policy',
      changeHint: approved
        ? undefined
        : `Visit your Node9 dashboard → Policy Studio to change this rule`,
    };
  }

  // ── Local browser daemon is the authority ────────────────────────────────
  if (isDaemonRunning()) {
    console.error(chalk.yellow('\n🛡️  Node9: Action suspended — waiting for your approval.'));
    console.error(chalk.cyan(`   Browser UI → http://${DAEMON_HOST}:${DAEMON_PORT}/\n`));
    try {
      const daemonDecision = await askDaemon(toolName, args, meta);
      if (daemonDecision === 'abandoned') {
        console.error(chalk.yellow('\n⚠️  Browser closed without a decision. Falling back...'));
      } else {
        return {
          approved: daemonDecision === 'allow',
          reason:
            daemonDecision === 'deny'
              ? `Node9 blocked "${toolName}" — denied in browser.`
              : undefined,
          checkedBy: daemonDecision === 'allow' ? 'daemon' : undefined,
          blockedBy: daemonDecision === 'deny' ? 'local-decision' : undefined,
          changeHint:
            daemonDecision === 'deny'
              ? `Open the daemon UI to change:  node9 daemon --openui`
              : undefined,
        };
      }
    } catch {}
  }

  // ── Terminal Y/N prompt ───────────────────────────────────────────────────
  if (allowTerminalFallback && process.stdout.isTTY) {
    console.log(chalk.bgRed.white.bold(` 🛑 NODE9 INTERCEPTOR `));
    console.log(`${chalk.bold('Action:')} ${chalk.red(toolName)}`);
    const argsPreview = JSON.stringify(args, null, 2);
    console.log(
      `${chalk.bold('Args:')}\n${chalk.gray(argsPreview.length > 500 ? argsPreview.slice(0, 500) + '...' : argsPreview)}`
    );
    const controller = new AbortController();
    const TIMEOUT_MS = 30_000;
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const approved = await confirm(
        { message: `Authorize? (auto-deny in ${TIMEOUT_MS / 1000}s)`, default: false },
        { signal: controller.signal }
      );
      clearTimeout(timer);
      return { approved };
    } catch {
      clearTimeout(timer);
      console.error(chalk.yellow('\n⏱  Prompt timed out — action denied by default.'));
      return { approved: false };
    }
  }

  // ── No approval mechanism ─────────────────────────────────────────────────
  return {
    approved: false,
    noApprovalMechanism: true,
    reason: `Node9 blocked "${toolName}". No approval mechanism is active.`,
    blockedBy: 'no-approval-mechanism',
    changeHint: `Start the approval daemon:  node9 daemon --background\n   Or connect to your team:   node9 login <apiKey>`,
  };
}

export { getCredentials };

/**
 * Returns the names of all saved profiles in ~/.node9/credentials.json.
 * Returns [] when the file doesn't exist or uses the legacy flat format.
 */
export function listCredentialProfiles(): string[] {
  try {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (!fs.existsSync(credPath)) return [];
    const creds = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;
    // Multi-profile format: keys are profile names with object values
    if (!creds.apiKey) return Object.keys(creds).filter((k) => typeof creds[k] === 'object');
  } catch {}
  return [];
}

/**
 * Policy resolution hierarchy (highest → lowest priority):
 *
 *  1. Cloud Policy Studio  — when agentMode:true + API key (handled in authorizeHeadless)
 *  2. ./node9.config.json  — project-level source of truth
 *  3. ~/.node9/config.json — machine-level source of truth
 *  4. Hardcoded defaults   — safety net when no config file exists at all
 *
 * Each level is a complete source of truth — the first file found is used entirely.
 * No cross-file merging: a project config does not inherit from the global config.
 * Within a single file, any unspecified field falls back to its hardcoded default
 * so that minimal configs (e.g. only setting dangerousWords) still work correctly.
 */
function getConfig(): Config {
  if (cachedConfig) return cachedConfig;

  const projectConfig = tryLoadConfig(path.join(process.cwd(), 'node9.config.json'));
  if (projectConfig) {
    cachedConfig = buildConfig(projectConfig);
    return cachedConfig;
  }

  const globalConfig = tryLoadConfig(path.join(os.homedir(), '.node9', 'config.json'));
  if (globalConfig) {
    cachedConfig = buildConfig(globalConfig);
    return cachedConfig;
  }

  cachedConfig = DEFAULT_CONFIG;
  return cachedConfig;
}

function tryLoadConfig(filePath: string): Record<string, unknown> | null {
  if (!fs.existsSync(filePath)) return null;
  try {
    const config = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
    validateConfig(config, filePath);
    return config;
  } catch {
    return null;
  }
}

function validateConfig(config: Record<string, unknown>, path: string): void {
  const allowedTopLevel = ['version', 'settings', 'policy', 'environments', 'apiKey', 'apiUrl'];
  Object.keys(config).forEach((key) => {
    if (!allowedTopLevel.includes(key))
      console.warn(chalk.yellow(`⚠️  Node9: Unknown top-level key "${key}" in ${path}`));
  });
}

/**
 * Builds a Config from a parsed file.
 * Each field falls back independently to its hardcoded default only if absent —
 * so a file that only sets `dangerousWords` still gets `ignoredTools` etc.,
 * but a file that explicitly sets `ignoredTools: []` gets an empty list.
 */
function buildConfig(parsed: Record<string, unknown>): Config {
  const p = (parsed.policy as Partial<Config['policy']>) || {};
  const s = (parsed.settings as Partial<Config['settings']>) || {};
  return {
    settings: {
      mode: s.mode ?? DEFAULT_CONFIG.settings.mode,
      autoStartDaemon: s.autoStartDaemon ?? DEFAULT_CONFIG.settings.autoStartDaemon,
    },
    policy: {
      dangerousWords: p.dangerousWords ?? DEFAULT_CONFIG.policy.dangerousWords,
      ignoredTools: p.ignoredTools ?? DEFAULT_CONFIG.policy.ignoredTools,
      toolInspection: p.toolInspection ?? DEFAULT_CONFIG.policy.toolInspection,
      rules: p.rules ?? DEFAULT_CONFIG.policy.rules,
    },
    environments: (parsed.environments as Record<string, EnvironmentConfig>) || {},
  };
}

function getActiveEnvironment(config: Config): EnvironmentConfig | null {
  const env = process.env.NODE_ENV || 'development';
  return config.environments[env] ?? null;
}

function getCredentials() {
  const DEFAULT_API_URL = 'https://api.node9.ai/api/v1/intercept';

  // 1. Env var — highest priority, always wins (CI, Docker, per-session overrides)
  if (process.env.NODE9_API_KEY)
    return {
      apiKey: process.env.NODE9_API_KEY,
      apiUrl: process.env.NODE9_API_URL || DEFAULT_API_URL,
    };

  // 2. Per-project node9.config.json apiKey — lets each repo point to its own workspace
  try {
    const projectConfigPath = path.join(process.cwd(), 'node9.config.json');
    if (fs.existsSync(projectConfigPath)) {
      const projectConfig = JSON.parse(fs.readFileSync(projectConfigPath, 'utf-8')) as Record<
        string,
        unknown
      >;
      if (typeof projectConfig.apiKey === 'string' && projectConfig.apiKey) {
        return {
          apiKey: projectConfig.apiKey,
          apiUrl:
            (typeof projectConfig.apiUrl === 'string' && projectConfig.apiUrl) || DEFAULT_API_URL,
        };
      }
    }
  } catch {}

  // 3. ~/.node9/credentials.json — supports both flat (legacy) and named profiles
  try {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (fs.existsSync(credPath)) {
      const creds = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;

      // Multi-profile format: { "default": { apiKey, apiUrl }, "gemini": { apiKey, apiUrl } }
      const profileName = process.env.NODE9_PROFILE || 'default';
      const profile = creds[profileName] as Record<string, unknown> | undefined;
      if (profile?.apiKey) {
        return {
          apiKey: profile.apiKey as string,
          apiUrl: (profile.apiUrl as string) || DEFAULT_API_URL,
        };
      }

      // Legacy flat format: { "apiKey": "...", "apiUrl": "..." }
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

async function callNode9SaaS(
  toolName: string,
  args: unknown,
  creds: { apiKey: string; apiUrl: string },
  slackChannel?: string,
  meta?: { agent?: string; mcpServer?: string }
): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 35000);
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
    clearTimeout(timeout);
    if (!response.ok) throw new Error('API fail');
    const data = (await response.json()) as {
      approved: boolean;
      pending?: boolean;
      requestId?: string;
    };

    // Auto-allowed or auto-blocked — no polling needed
    if (!data.pending) return data.approved;

    // PENDING — poll GET /intercept/status/:requestId until a decision is made
    if (!data.requestId) return false;
    const statusUrl = `${creds.apiUrl}/status/${data.requestId}`;

    // Tell the user where to act
    console.error(chalk.yellow('\n🛡️  Node9: Action suspended — waiting for your approval.'));
    if (isDaemonRunning()) {
      console.error(
        chalk.cyan('   Browser UI → ') + chalk.bold(`http://${DAEMON_HOST}:${DAEMON_PORT}/`)
      );
    }
    console.error(chalk.cyan('   Dashboard  → ') + chalk.bold('Mission Control > Flows'));
    console.error(chalk.gray('   Agent is paused. Approve or deny to continue.\n'));

    const POLL_INTERVAL_MS = 3000;
    const POLL_DEADLINE = Date.now() + 5 * 60 * 1000; // 5-minute timeout

    while (Date.now() < POLL_DEADLINE) {
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
      try {
        const statusRes = await fetch(statusUrl, {
          headers: { Authorization: `Bearer ${creds.apiKey}` },
          signal: AbortSignal.timeout(5000),
        });
        if (!statusRes.ok) continue;
        const { status } = (await statusRes.json()) as { status: string };
        if (status === 'APPROVED') {
          console.error(chalk.green('✅  Approved — continuing.\n'));
          return true;
        }
        if (status === 'DENIED' || status === 'AUTO_BLOCKED' || status === 'TIMED_OUT') {
          console.error(chalk.red('❌  Denied — action blocked.\n'));
          return false;
        }
        // status === 'PENDING' → keep polling
      } catch {
        // transient network error, retry on next tick
      }
    }

    console.error(chalk.yellow('⏱  Timed out waiting for approval — action blocked.\n'));
    return false; // timed out waiting for a decision
  } catch {
    return false;
  }
}
