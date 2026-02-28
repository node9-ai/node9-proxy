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
    .filter((t) => t.length > 0);
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
  return path.split('.').reduce<unknown>((prev, curr) => (prev as Record<string, unknown>)?.[curr], obj);
}

function extractShellCommand(
  toolName: string,
  args: unknown,
  toolInspection: Record<string, string>
): string | null {
  const patterns = Object.keys(toolInspection);
  const matchingPattern = patterns.find(p => matchesPattern(toolName, p));
  
  if (!matchingPattern) return null;

  const fieldPath = toolInspection[matchingPattern];
  const value = getNestedValue(args, fieldPath);
  return typeof value === 'string' ? value : null;
}

interface ShellNode {
  type?: string;
  Args?: { Parts?: { Value?: string }[] }[];
  Parts?: { Value?: string }[];
  Value?: string;
  [key: string]: unknown;
}

/**
 * Robust Shell Parser
 * Combines sh-syntax AST with a reliable fallback for keyword detection.
 */
async function analyzeShellCommand(command: string): Promise<{ actions: string[], paths: string[], allTokens: string[] }> {
  const actions: string[] = [];
  const paths: string[] = [];
  const allTokens: string[] = [];

  // 1. AST Pass (High Fidelity)
  try {
    const ast = (await parse(command)) as unknown as ShellNode;
    const walk = (node: ShellNode) => {
      if (!node) return;
      if (node.type === 'CallExpr') {
        const parts = (node.Args || []).map((arg) => {
          return (arg.Parts || []).map((p) => p.Value || '').join('');
        }).filter((s: string) => s.length > 0);

        if (parts.length > 0) {
          // Decompose the action (e.g. /usr/bin/rm -> rm)
          const actionPart = parts[0].toLowerCase();
          const actionTokens = actionPart.split(/[/.]/).filter(t => t.length > 0);
          actions.push(...actionTokens);
          
          parts.forEach((p: string) => {
             // Add full token and its decomposed parts
             const clean = p.toLowerCase().replace(/^-+/, '');
             allTokens.push(clean);
             if (p.includes('/')) {
               p.split('/').filter(x => x.length > 0).forEach(x => allTokens.push(x.toLowerCase()));
             }
          });

          parts.slice(1).forEach((p: string) => { if (!p.startsWith('-')) paths.push(p); });
        }
      }
      for (const key in node) {
        if (key === 'Parent') continue;
        const val = node[key];
        if (Array.isArray(val)) {
          val.forEach((child) => { if (child && typeof child === 'object') walk(child as ShellNode); });
        } else if (val && typeof val === 'object') {
          walk(val as ShellNode);
        }
      }
    };
    walk(ast);
  } catch { /* Fallback used below */ }

  // 2. Semantic Fallback Pass (Fixes path-based bypasses like /usr/bin/rm)
  const normalized = command.replace(/\\(.)/g, '$1'); 
  const sanitized = normalized.replace(/["'<>]/g, ' '); 
  const segments = sanitized.split(/[|;&]|\$\(|\)|`/);
  
  segments.forEach(segment => {
    const tokens = segment.trim().split(/\s+/).filter((t) => t.length > 0);
    if (tokens.length > 0) {
      tokens.forEach((t, idx) => {
        // Remove leading dashes (e.g. -delete -> delete)
        const cleanToken = t.replace(/^-+/, '').toLowerCase();
        
        // Handle paths (e.g. /usr/bin/rm -> rm)
        const subParts = cleanToken.split(/[/.]/).filter(p => p.length > 0);
        
        subParts.forEach(part => {
          if (!allTokens.includes(part)) allTokens.push(part);
          // If it's the first token in a segment, it's an action
          if (idx === 0 && !actions.includes(part)) actions.push(part);
        });

        if (!allTokens.includes(cleanToken)) allTokens.push(cleanToken);

        // Path extraction
        if (idx !== 0 && !t.startsWith('-')) {
          if (!paths.includes(t)) paths.push(t);
        }
      });
    }
  });

  return { actions, paths, allTokens };
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
      'list_*', 'get_*', 'read_*', 'describe_*', 'read', 'write', 'edit',
      'multiedit', 'glob', 'grep', 'ls', 'notebookread', 'notebookedit',
      'todoread', 'todowrite', 'webfetch', 'websearch', 'exitplanmode', 'askuserquestion',
    ],
    toolInspection: {
      'bash': 'command',
      'run_shell_command': 'command',
      'shell': 'command',
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

/** @internal */
export function _resetConfigCache(): void {
  cachedConfig = null;
}

export async function evaluatePolicy(toolName: string, args?: unknown): Promise<'allow' | 'review'> {
  const config = getConfig();

  if (matchesPattern(toolName, config.policy.ignoredTools)) return 'allow';

  const shellCommand = extractShellCommand(toolName, args, config.policy.toolInspection);

  if (shellCommand) {
    const { actions, paths, allTokens } = await analyzeShellCommand(shellCommand);
    
    for (const action of actions) {
      const rule = config.policy.rules.find((r) => r.action === action || matchesPattern(action, r.action));
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
  const keys = Object.keys(config);
  keys.forEach(key => {
    if (!allowedTopLevel.includes(key)) {
      console.warn(chalk.yellow(`⚠️  Node9: Unknown top-level key "${key}" in ${path}`));
    }
  });

  if (config.policy && typeof config.policy === 'object') {
    const policy = config.policy as Record<string, unknown>;
    const allowedPolicy = ['dangerousWords', 'ignoredTools', 'toolInspection', 'rules'];
    Object.keys(policy).forEach(key => {
      if (!allowedPolicy.includes(key)) {
        console.warn(chalk.yellow(`⚠️  Node9: Unknown policy key "${key}" in ${path}`));
      }
    });
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

export async function authorizeAction(toolName: string, args: unknown): Promise<boolean> {
  if (await evaluatePolicy(toolName, args) === 'allow') return true;
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
    const msg = error instanceof Error ? error.message : String(error);
    console.error(chalk.red(`❌ Cloud Error: ${msg}`));
    return false;
  }
}