// src/setup.ts
import fs from 'fs';
import path from 'path';
import os from 'os';
import chalk from 'chalk';
import { confirm } from '@inquirer/prompts';

interface McpServer {
  type?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

interface ClaudeConfig {
  mcpServers?: Record<string, McpServer>;
  [key: string]: unknown;
}

interface HookEntry {
  type: string;
  command: string;
  timeout?: number;
}

interface HookMatcher {
  matcher: string;
  hooks: HookEntry[];
}

interface ClaudeSettings {
  hooks?: {
    PreToolUse?: HookMatcher[];
    PostToolUse?: HookMatcher[];
    [key: string]: HookMatcher[] | undefined;
  };
  [key: string]: unknown;
}

interface GeminiHookEntry {
  name?: string;
  type?: string;
  command: string;
  args?: string[];
  timeout?: number;
}

interface GeminiHookMatcher {
  matcher: string;
  hooks: GeminiHookEntry[];
}

interface GeminiSettings {
  mcpServers?: Record<string, McpServer>;
  hooks?: {
    BeforeTool?: GeminiHookMatcher[];
    AfterTool?: GeminiHookMatcher[];
    [key: string]: GeminiHookMatcher[] | undefined;
  };
  [key: string]: unknown;
}

function readJson<T>(filePath: string): T | null {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as T;
    }
  } catch {
    // ignore corrupt files
  }
  return null;
}

function writeJson(filePath: string, data: unknown): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}

// ── Claude Code ──────────────────────────────────────────────────────────────

export async function setupClaude(): Promise<void> {
  const homeDir = os.homedir();
  const mcpPath = path.join(homeDir, '.claude.json');
  const hooksPath = path.join(homeDir, '.claude', 'settings.json');

  const claudeConfig = readJson<ClaudeConfig>(mcpPath) ?? {};
  const settings = readJson<ClaudeSettings>(hooksPath) ?? {};
  const servers = claudeConfig.mcpServers ?? {};

  let anythingChanged = false;

  // ── Step 1: Pure additions — apply immediately, no prompt ────────────────
  if (!settings.hooks) settings.hooks = {};

  const hasPreHook = settings.hooks.PreToolUse?.some((m) =>
    m.hooks.some((h) => h.command?.includes('node9 check'))
  );
  if (!hasPreHook) {
    if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];
    settings.hooks.PreToolUse.push({
      matcher: '.*',
      hooks: [{ type: 'command', command: 'node9 check', timeout: 60 }],
    });
    console.log(chalk.green('  ✅ PreToolUse hook added  → node9 check'));
    anythingChanged = true;
  }

  const hasPostHook = settings.hooks.PostToolUse?.some((m) =>
    m.hooks.some((h) => h.command?.includes('node9 log'))
  );
  if (!hasPostHook) {
    if (!settings.hooks.PostToolUse) settings.hooks.PostToolUse = [];
    settings.hooks.PostToolUse.push({
      matcher: '.*',
      hooks: [{ type: 'command', command: 'node9 log' }],
    });
    console.log(chalk.green('  ✅ PostToolUse hook added → node9 log'));
    anythingChanged = true;
  }

  if (anythingChanged) {
    writeJson(hooksPath, settings);
    console.log('');
  }

  // ── Step 2: Modifications — show preview and ask ─────────────────────────
  const serversToWrap: Array<{ name: string; originalCmd: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    serversToWrap.push({
      name,
      originalCmd: [server.command, ...(server.args ?? [])].join(' '),
    });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${mcpPath}`));
    for (const { name, originalCmd } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "npx ${originalCmd}" → node9 proxy "${originalCmd}"`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, originalCmd } of serversToWrap) {
        servers[name] = { ...servers[name], command: 'node9', args: ['proxy', originalCmd] };
      }
      claudeConfig.mcpServers = servers;
      writeJson(mcpPath, claudeConfig);
      console.log(chalk.green(`\n  ✅ ${serversToWrap.length} MCP server(s) wrapped`));
      anythingChanged = true;
    } else {
      console.log(chalk.yellow('  Skipped MCP server wrapping.'));
    }
    console.log('');
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  if (!anythingChanged && serversToWrap.length === 0) {
    console.log(chalk.blue('ℹ️  Node9 is already fully configured for Claude Code.'));
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting Claude Code!'));
    console.log(chalk.gray('    Restart Claude Code for changes to take effect.'));
  }
}

// ── Gemini CLI ───────────────────────────────────────────────────────────────

export async function setupGemini(): Promise<void> {
  const homeDir = os.homedir();
  const settingsPath = path.join(homeDir, '.gemini', 'settings.json');

  const settings = readJson<GeminiSettings>(settingsPath) ?? {};
  const servers = settings.mcpServers ?? {};

  let anythingChanged = false;

  // ── Step 1: Pure additions — apply immediately, no prompt ────────────────
  if (!settings.hooks) settings.hooks = {};

  const hasBeforeHook =
    Array.isArray(settings.hooks.BeforeTool) &&
    settings.hooks.BeforeTool.some((m) => m.hooks.some((h) => h.command?.includes('node9 check')));
  if (!hasBeforeHook) {
    if (!settings.hooks.BeforeTool) settings.hooks.BeforeTool = [];
    // If it was an object (old format), we re-initialize it as an array
    if (!Array.isArray(settings.hooks.BeforeTool)) settings.hooks.BeforeTool = [];

    settings.hooks.BeforeTool.push({
      matcher: '.*',
      hooks: [{ name: 'node9-check', type: 'command', command: 'node9 check', timeout: 60000 }],
    });
    console.log(chalk.green('  ✅ BeforeTool hook added → node9 check'));
    anythingChanged = true;
  }

  const hasAfterHook =
    Array.isArray(settings.hooks.AfterTool) &&
    settings.hooks.AfterTool.some((m) => m.hooks.some((h) => h.command?.includes('node9 log')));
  if (!hasAfterHook) {
    if (!settings.hooks.AfterTool) settings.hooks.AfterTool = [];
    // If it was an object (old format), we re-initialize it as an array
    if (!Array.isArray(settings.hooks.AfterTool)) settings.hooks.AfterTool = [];

    settings.hooks.AfterTool.push({
      matcher: '.*',
      hooks: [{ name: 'node9-log', type: 'command', command: 'node9 log' }],
    });
    console.log(chalk.green('  ✅ AfterTool hook added  → node9 log'));
    anythingChanged = true;
  }

  if (anythingChanged) {
    writeJson(settingsPath, settings);
    console.log('');
  }

  // ── Step 2: Modifications — show preview and ask ─────────────────────────
  const serversToWrap: Array<{ name: string; originalCmd: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    serversToWrap.push({
      name,
      originalCmd: [server.command, ...(server.args ?? [])].join(' '),
    });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${settingsPath}  (mcpServers)`));
    for (const { name, originalCmd } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${originalCmd}" → node9 proxy "${originalCmd}"`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, originalCmd } of serversToWrap) {
        servers[name] = { ...servers[name], command: 'node9', args: ['proxy', originalCmd] };
      }
      settings.mcpServers = servers;
      writeJson(settingsPath, settings);
      console.log(chalk.green(`\n  ✅ ${serversToWrap.length} MCP server(s) wrapped`));
      anythingChanged = true;
    } else {
      console.log(chalk.yellow('  Skipped MCP server wrapping.'));
    }
    console.log('');
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  if (!anythingChanged && serversToWrap.length === 0) {
    console.log(chalk.blue('ℹ️  Node9 is already fully configured for Gemini CLI.'));
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting Gemini CLI!'));
    console.log(chalk.gray('    Restart Gemini CLI for changes to take effect.'));
  }
}

// ── Cursor ───────────────────────────────────────────────────────────────────

interface CursorMcpConfig {
  mcpServers?: Record<string, McpServer>;
  [key: string]: unknown;
}

interface CursorHookEntry {
  command: string;
  args?: string[];
}

interface CursorHooksFile {
  version: number;
  hooks?: {
    preToolUse?: CursorHookEntry[];
    postToolUse?: CursorHookEntry[];
    [key: string]: CursorHookEntry[] | undefined;
  };
}

export async function setupCursor(): Promise<void> {
  const homeDir = os.homedir();
  const mcpPath = path.join(homeDir, '.cursor', 'mcp.json');
  const hooksPath = path.join(homeDir, '.cursor', 'hooks.json');

  const mcpConfig = readJson<CursorMcpConfig>(mcpPath) ?? {};
  const hooksFile = readJson<CursorHooksFile>(hooksPath) ?? { version: 1 };
  const servers = mcpConfig.mcpServers ?? {};

  let anythingChanged = false;

  // ── Step 1: Pure additions — apply immediately, no prompt ────────────────
  if (!hooksFile.hooks) hooksFile.hooks = {};

  const hasPreHook = hooksFile.hooks.preToolUse?.some(
    (h) => h.command === 'node9' && h.args?.includes('check')
  );
  if (!hasPreHook) {
    if (!hooksFile.hooks.preToolUse) hooksFile.hooks.preToolUse = [];
    hooksFile.hooks.preToolUse.push({ command: 'node9', args: ['check'] });
    console.log(chalk.green('  ✅ preToolUse hook added → node9 check'));
    anythingChanged = true;
  }

  const hasPostHook = hooksFile.hooks.postToolUse?.some(
    (h) => h.command === 'node9' && h.args?.includes('log')
  );
  if (!hasPostHook) {
    if (!hooksFile.hooks.postToolUse) hooksFile.hooks.postToolUse = [];
    hooksFile.hooks.postToolUse.push({ command: 'node9', args: ['log'] });
    console.log(chalk.green('  ✅ postToolUse hook added → node9 log'));
    anythingChanged = true;
  }

  if (anythingChanged) {
    writeJson(hooksPath, hooksFile);
    console.log('');
  }

  // ── Step 2: Modifications — show preview and ask ─────────────────────────
  const serversToWrap: Array<{ name: string; originalCmd: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    serversToWrap.push({
      name,
      originalCmd: [server.command, ...(server.args ?? [])].join(' '),
    });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${mcpPath}`));
    for (const { name, originalCmd } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${originalCmd}" → node9 proxy "${originalCmd}"`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, originalCmd } of serversToWrap) {
        servers[name] = { ...servers[name], command: 'node9', args: ['proxy', originalCmd] };
      }
      mcpConfig.mcpServers = servers;
      writeJson(mcpPath, mcpConfig);
      console.log(chalk.green(`\n  ✅ ${serversToWrap.length} MCP server(s) wrapped`));
      anythingChanged = true;
    } else {
      console.log(chalk.yellow('  Skipped MCP server wrapping.'));
    }
    console.log('');
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  if (!anythingChanged && serversToWrap.length === 0) {
    console.log(chalk.blue('ℹ️  Node9 is already fully configured for Cursor.'));
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting Cursor!'));
    console.log(chalk.gray('    Restart Cursor for changes to take effect.'));
  }
}
