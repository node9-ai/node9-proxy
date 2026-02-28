// src/core.ts
import chalk from 'chalk';
import { confirm } from '@inquirer/prompts';
import fs from 'fs';
import path from 'path';
import os from 'os';
import pm from 'picomatch';

// Default Enterprise Posture
export const DANGEROUS_WORDS = [
  'delete', 'drop', 'remove', 'terminate', 'refund',
  'write', 'update', 'destroy', 'rm', 'rmdir', 'purge', 'format'
];

function tokenize(toolName: string): string[] {
  return toolName.toLowerCase().split(/[_.\-\s]+/).filter(Boolean);
}

function containsDangerousWord(toolName: string, dangerousWords: string[]): boolean {
  const tokens = tokenize(toolName);
  return dangerousWords.some(word => tokens.includes(word.toLowerCase()));
}

function extractShellCommand(toolName: string, args: unknown, toolInspection: Record<string, string>): string | null {
  const normalizedToolName = toolName.toLowerCase();
  const commandField = toolInspection[normalizedToolName];
  if (!commandField) return null;
  if (typeof args !== 'object' || args === null) return null;
  const cmd = (args as Record<string, unknown>)[commandField];
  return typeof cmd === 'string' ? cmd : null;
}

function tokenizeShellCommand(command: string): string[] {
  const normalized = command.replace(/\\(.)/g, '$1');
  const sanitized = normalized.replace(/["'<>]/g, ' ');
  const segments = sanitized.split(/[|;&]|\$\(|\)|`/);

  return segments.flatMap(segment =>
    segment
      .trim()
      .split(/\s+/)
      .flatMap(word => {
        const stripped = word.replace(/^-+/, '');
        // For keyword matching, we always want the stripped version (no dashes).
        // If it looks like a path, we also want the segments.
        return stripped.includes('/') ? [stripped, ...stripped.split('/')] : [stripped];
      })
      .map(t => t.toLowerCase())
      .filter(Boolean)
  );
}

function extractPathsFromCommand(command: string): string[] {
  const normalized = command.replace(/\\(.)/g, '$1');
  const segments = normalized.split(/[|;&]|\$\(|\)|`/);
  
  return segments.flatMap(segment => {
    const tokens = segment.trim().split(/\s+/);
    return tokens.slice(1).filter(t => t && !t.startsWith('-'));
  });
}

function matchesPath(targetPath: string, patterns: string[]): boolean {
  if (patterns.length === 0) return false;
  const isMatch = pm(patterns, { nocase: true, dot: true });
  const target = targetPath.replace(/^\.\//, '');
  return isMatch(target) || isMatch(`./${target}`);
}

function isShellCommandDangerous(command: string, dangerousWords: string[]): boolean {
  const tokens = tokenizeShellCommand(command);
  return tokens.some(token =>
    dangerousWords.some(word => token === word.toLowerCase())
  );
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
  settings: { mode: "standard" },
  policy: {
    dangerousWords: DANGEROUS_WORDS,
    ignoredTools: [
      'list_*', 'get_*', 'read_*', 'describe_*',
      'read', 'write', 'edit', 'multiedit', 'glob', 'grep', 'ls',
      'notebookread', 'notebookedit', 'todoread', 'todowrite',
      'webfetch', 'websearch', 'exitplanmode', 'askuserquestion',
    ],
    toolInspection: {
      'bash': 'command',               // Claude Code
      'run_shell_command': 'command',  // Gemini CLI (older versions)
      'shell': 'command',              // Gemini CLI (latest)
      'terminal.execute': 'command',   // Common pattern
    },
    rules: [
      {
        action: 'rm',
        allowPaths: ['**/node_modules/**', 'dist/**', 'build/**', '.DS_Store'],
      }
    ]
  },
  environments: {}
};

let cachedConfig: Config | null = null;

/** @internal — for testing only */
export function _resetConfigCache(): void {
  cachedConfig = null;
}

export function evaluatePolicy(toolName: string, args?: unknown): 'allow' | 'review' {
  const config = getConfig();

  if (matchesIgnored(toolName, config.policy.ignoredTools)) return 'allow';

  const shellCommand = extractShellCommand(toolName, args, config.policy.toolInspection);
  
  let isDangerous = false;
  if (shellCommand) {
    const tokens = tokenizeShellCommand(shellCommand);
    const action = tokens[0];
    const paths = extractPathsFromCommand(shellCommand);

    const rule = config.policy.rules.find(r => r.action === action);
    if (rule) {
      if (paths.length > 0) {
        const anyBlocked = paths.some(p => matchesPath(p, rule.blockPaths || []));
        if (anyBlocked) return 'review';

        const allAllowed = paths.every(p => matchesPath(p, rule.allowPaths || []));
        if (allAllowed) return 'allow';
      }
      return 'review';
    }

    isDangerous = isShellCommandDangerous(shellCommand, config.policy.dangerousWords);
  } else {
    isDangerous = containsDangerousWord(toolName, config.policy.dangerousWords);
  }

  if (!isDangerous && config.settings.mode !== 'strict') return 'allow';

  const envConfig = getActiveEnvironment(config);
  if (envConfig?.requireApproval === false) return 'allow';

  return 'review';
}

export async function authorizeHeadless(
  toolName: string,
  args: unknown
): Promise<{ approved: boolean; reason?: string }> {
  if (evaluatePolicy(toolName, args) === 'allow') return { approved: true };

  const creds = getCredentials();
  if (creds?.apiKey) {
    const envConfig = getActiveEnvironment(getConfig());
    const approved = await callNode9SaaS(toolName, args, creds, envConfig?.slackChannel);
    return { approved };
  }

  // NEW: Fallback to local prompt if in TTY
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
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Record<string, unknown>;
  } catch {
    console.warn(chalk.yellow(`⚠️ Node9: Invalid config at ${filePath}. Skipping.`));
    return null;
  }
}

function mergeWithDefaults(parsed: Record<string, unknown>): Config {
  return {
    settings: { ...DEFAULT_CONFIG.settings, ...(parsed.settings as object || {}) },
    policy: { ...DEFAULT_CONFIG.policy, ...(parsed.policy as object || {}) },
    environments: (parsed.environments as Record<string, EnvironmentConfig>) || {}
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
      apiUrl: process.env.NODE9_API_URL || 'https://api.node9.ai/api/v1/intercept'
    };
  }
  try {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (fs.existsSync(credPath)) {
      const creds = JSON.parse(fs.readFileSync(credPath, 'utf-8'));
      return {
        apiKey: creds.apiKey,
        apiUrl: creds.apiUrl || 'https://api.node9.ai/api/v1/intercept'
      };
    }
  } catch {}
  return null;
}

function matchesIgnored(toolName: string, patterns: string[]): boolean {
  const name = toolName.toLowerCase();
  return patterns.some(pattern => {
    const p = pattern.toLowerCase();
    if (p.endsWith('*')) return name.startsWith(p.slice(0, -1));
    return name === p;
  });
}

export async function authorizeAction(toolName: string, args: unknown): Promise<boolean> {
  if (evaluatePolicy(toolName, args) === 'allow') return true;
  const creds = getCredentials();
  const envConfig = getActiveEnvironment(getConfig());
  if (creds && creds.apiKey) {
    const slackChannel = envConfig?.slackChannel;
    console.log(chalk.blue(`🔹 Node9 Cloud: Routing approval to ${slackChannel || 'default channel'}...`));
    return await callNode9SaaS(toolName, args, creds, slackChannel);
  }
  if (process.stdout.isTTY) {
    console.log(chalk.bgRed.white.bold(` 🛑 NODE9 INTERCEPTOR `));
    console.log(`${chalk.bold('Action:')} ${chalk.red(toolName)}`);
    const argsPreview = JSON.stringify(args, null, 2);
    const truncated = argsPreview.length > 500 ? argsPreview.slice(0, 500) + '\n  ... (truncated)' : argsPreview;
    console.log(`${chalk.bold('Args:')}\n${chalk.gray(truncated)}`);
    return await confirm({ message: 'Authorize?', default: false });
  }
  throw new Error(`[Node9] Blocked dangerous action: ${toolName}. Run 'node9 login' to enable remote approval.`);
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
    console.log(chalk.yellow(`⏳ Routing to Node9 Cloud. Waiting for Slack approval...`));
    const response = await fetch(creds.apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${creds.apiKey}`
      },
      body: JSON.stringify({
        toolName, args, slackChannel,
        context: { hostname: os.hostname(), cwd: process.cwd(), platform: os.platform() }
      }),
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!response.ok) throw new Error(`API responded with Status ${response.status}`);
    const data = await response.json() as { approved: boolean; message?: string };
    if (data.approved) {
      console.log(chalk.green(`✅ Node9 Cloud: ${data.message || 'Approved'}`));
      return true;
    } else {
      console.log(chalk.red(`❌ Node9 Cloud: ${data.message || 'Blocked'}`));
      return false;
    }
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(chalk.red(`❌ Cloud Error: ${message}`));
    return false;
  }
}
