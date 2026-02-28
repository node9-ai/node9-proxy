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

/**
 * Robust Shell Parser
 * Combines sh-syntax AST with a reliable fallback for keyword detection.
 */
async function analyzeShellCommand(
  command: string
): Promise<{ actions: string[]; paths: string[]; allTokens: string[] }> {
  const actions: string[] = [];
  const paths: string[] = [];
  const allTokens: string[] = [];

  const addToken = (token: string) => {
    const lower = token.toLowerCase();
    allTokens.push(lower);
    // If it's a path like /usr/bin/rm, also add 'rm'
    if (lower.includes('/')) {
      const segments = lower.split('/').filter(Boolean);
      allTokens.push(...segments);
    }
    // If it's a flag like -delete, also add 'delete'
    if (lower.startsWith('-')) {
      allTokens.push(lower.replace(/^-+/, ''));
    }
  };

  // 1. AST Pass (High Fidelity)
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
          const action = parts[0];
          actions.push(action.toLowerCase());
          parts.forEach((p) => addToken(p));
          parts.slice(1).forEach((p) => {
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
    // Fallback logic
  }

  // 2. Semantic Fallback Pass (Ensures no obfuscation bypasses)
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

/**
 * Redactor: Masks common secret patterns (API keys, tokens, auth headers)
 */
export function redactSecrets(text: string): string {
  if (!text) return text;

  let redacted = text;

  // Pattern 1: Authorization Header (Bearer/Basic)
  redacted = redacted.replace(
    /(authorization:\s*(?:bearer|basic)\s+)[a-zA-Z0-9._\-\/\\=]+/gi,
    '$1********'
  );

  // Pattern 2: API Keys, Secrets, Tokens
  redacted = redacted.replace(
    /(api[_-]?key|secret|password|token)([:=]\s*['"]?)[a-zA-Z0-9._\-]{8,}/gi,
    '$1$2********'
  );

  // Pattern 3: Generic long alphanumeric strings
  redacted = redacted.replace(/\b[a-zA-Z0-9]{32,}\b/g, '********');

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
  settings: { mode: string };
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
      {
        action: 'rm',
        allowPaths: ['**/node_modules/**', 'dist/**', 'build/**', '.DS_Store'],
      },
    ],
  },
  environments: {},
};

let cachedConfig: Config | null = null;

export function _resetConfigCache(): void {
  cachedConfig = null;
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
    for (const action of actions) {
      // Check if action itself is a path (e.g., /usr/bin/rm), check the basename too
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
    const isDangerous = allTokens.some((token) =>
      config.policy.dangerousWords.some((word) => token === word.toLowerCase())
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

export async function authorizeHeadless(
  toolName: string,
  args: unknown
): Promise<{ approved: boolean; reason?: string }> {
  const decision = await evaluatePolicy(toolName, args);
  if (decision === 'allow') return { approved: true };
  const creds = getCredentials();
  if (creds?.apiKey) {
    const envConfig = getActiveEnvironment(getConfig());
    const approved = await callNode9SaaS(toolName, args, creds, envConfig?.slackChannel);
    return { approved };
  }
  if (process.stdout.isTTY) {
    console.log(chalk.bgRed.white.bold(` 🛑 NODE9 INTERCEPTOR `));
    console.log(`${chalk.bold('Action:')} ${chalk.red(toolName)}`);
    const approved = await confirm({ message: 'Authorize?', default: false });
    return { approved };
  }
  return {
    approved: false,
    reason: `Node9 blocked "${toolName}". Run 'node9 login' to enable Slack approvals, or update node9.config.json policy.`,
  };
}

export { getCredentials };

function getConfig(): Config {
  if (cachedConfig) return cachedConfig;
  const projectConfig = tryLoadConfig(path.join(process.cwd(), 'node9.config.json'));
  if (projectConfig) {
    cachedConfig = mergeWithDefaults(projectConfig);
    return cachedConfig;
  }
  const globalConfig = tryLoadConfig(path.join(os.homedir(), '.node9', 'config.json'));
  if (globalConfig) {
    cachedConfig = mergeWithDefaults(globalConfig);
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
  const allowedTopLevel = ['version', 'settings', 'policy', 'environments'];
  Object.keys(config).forEach((key) => {
    if (!allowedTopLevel.includes(key))
      console.warn(chalk.yellow(`⚠️  Node9: Unknown top-level key "${key}" in ${path}`));
  });
  if (config.policy && typeof config.policy === 'object') {
    const policy = config.policy as Record<string, unknown>;
    const allowedPolicy = ['dangerousWords', 'ignoredTools', 'toolInspection', 'rules'];
    Object.keys(policy).forEach((key) => {
      if (!allowedPolicy.includes(key))
        console.warn(chalk.yellow(`⚠️  Node9: Unknown policy key "${key}" in ${path}`));
    });
  }
}

function mergeWithDefaults(parsed: Record<string, unknown>): Config {
  return {
    settings: { ...DEFAULT_CONFIG.settings, ...((parsed.settings as object) || {}) },
    policy: { ...DEFAULT_CONFIG.policy, ...((parsed.policy as object) || {}) },
    environments: (parsed.environments as Record<string, EnvironmentConfig>) || {},
  };
}

function getActiveEnvironment(config: Config): EnvironmentConfig | null {
  const env = process.env.NODE_ENV || 'development';
  return config.environments[env] ?? null;
}

function getCredentials() {
  if (process.env.NODE9_API_KEY) {
    return {
      apiKey: process.env.NODE9_API_KEY,
      apiUrl: process.env.NODE9_API_URL || 'https://api.node9.ai/api/v1/intercept',
    };
  }
  try {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (fs.existsSync(credPath)) {
      const creds = JSON.parse(fs.readFileSync(credPath, 'utf-8'));
      return {
        apiKey: creds.apiKey,
        apiUrl: creds.apiUrl || 'https://api.node9.ai/api/v1/intercept',
      };
    }
  } catch {}
  return null;
}

export async function authorizeAction(toolName: string, args: unknown): Promise<boolean> {
  if ((await evaluatePolicy(toolName, args)) === 'allow') return true;
  const creds = getCredentials();
  const envConfig = getActiveEnvironment(getConfig());
  if (creds && creds.apiKey) {
    return await callNode9SaaS(toolName, args, creds, envConfig?.slackChannel);
  }
  if (process.stdout.isTTY) {
    console.log(chalk.bgRed.white.bold(` 🛑 NODE9 INTERCEPTOR `));
    console.log(`${chalk.bold('Action:')} ${chalk.red(toolName)}`);
    const argsPreview = JSON.stringify(args, null, 2);
    console.log(
      `${chalk.bold('Args:')}\n${chalk.gray(argsPreview.length > 500 ? argsPreview.slice(0, 500) + '\n  ... (truncated)' : argsPreview)}`
    );
    return await confirm({ message: 'Authorize?', default: false });
  }
  throw new Error(
    `[Node9] Blocked dangerous action: ${toolName}. Run 'node9 login' to enable remote approval.`
  );
}

async function callNode9SaaS(
  toolName: string,
  args: unknown,
  creds: { apiKey: string; apiUrl: string },
  slackChannel?: string
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
        context: { hostname: os.hostname(), cwd: process.cwd(), platform: os.platform() },
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!response.ok) throw new Error(`API responded with Status ${response.status}`);
    const data = (await response.json()) as { approved: boolean; message?: string };
    if (data.approved) return true;
    else return false;
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(chalk.red(`❌ Cloud Error: ${msg}`));
    return false;
  }
}
