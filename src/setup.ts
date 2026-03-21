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

function printDaemonTip(): void {
  console.log(
    chalk.cyan('\n   💡 Node9 will protect you automatically using Native OS popups.') +
      chalk.white('\n      To view your history or manage persistent rules, run:') +
      chalk.green('\n      node9 daemon --openui')
  );
}

/**
 * Returns a shell-safe hook command that works regardless of the user's $PATH.
 * Hooks run in a restricted shell (no .bashrc / nvm init), so bare "node9"
 * is often not found. Using the full node + cli.js paths avoids this.
 */
function fullPathCommand(subcommand: string): string {
  if (process.env.NODE9_TESTING === '1') return `node9 ${subcommand}`;
  const nodeExec = process.execPath; // e.g. /home/user/.nvm/.../bin/node
  const cliScript = process.argv[1]; // e.g. /.../dist/cli.js
  return `${nodeExec} ${cliScript} ${subcommand}`;
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
    m.hooks.some((h) => h.command?.includes('node9 check') || h.command?.includes('cli.js check'))
  );
  if (!hasPreHook) {
    if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];
    settings.hooks.PreToolUse.push({
      matcher: '.*',
      hooks: [{ type: 'command', command: fullPathCommand('check'), timeout: 60 }],
    });
    console.log(chalk.green('  ✅ PreToolUse hook added  → node9 check'));
    anythingChanged = true;
  }

  const hasPostHook = settings.hooks.PostToolUse?.some((m) =>
    m.hooks.some((h) => h.command?.includes('node9 log') || h.command?.includes('cli.js log'))
  );
  if (!hasPostHook) {
    if (!settings.hooks.PostToolUse) settings.hooks.PostToolUse = [];
    settings.hooks.PostToolUse.push({
      matcher: '.*',
      hooks: [{ type: 'command', command: fullPathCommand('log'), timeout: 600 }],
    });
    console.log(chalk.green('  ✅ PostToolUse hook added → node9 log'));
    anythingChanged = true;
  }

  if (anythingChanged) {
    writeJson(hooksPath, settings);
    console.log('');
  }

  // ── Step 2: Modifications — show preview and ask ─────────────────────────
  const serversToWrap: Array<{ name: string; originalCmd: string; parts: string[] }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    const parts = [server.command, ...(server.args ?? [])];
    serversToWrap.push({ name, originalCmd: parts.join(' '), parts });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${mcpPath}`));
    for (const { name, originalCmd } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${originalCmd}" → node9 ${originalCmd}`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, parts } of serversToWrap) {
        servers[name] = { ...servers[name], command: 'node9', args: parts };
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
    printDaemonTip();
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting Claude Code!'));
    console.log(chalk.gray('    Restart Claude Code for changes to take effect.'));
    printDaemonTip();
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
    settings.hooks.BeforeTool.some((m) =>
      m.hooks.some((h) => h.command?.includes('node9 check') || h.command?.includes('cli.js check'))
    );
  if (!hasBeforeHook) {
    if (!settings.hooks.BeforeTool) settings.hooks.BeforeTool = [];
    // If it was an object (old format), we re-initialize it as an array
    if (!Array.isArray(settings.hooks.BeforeTool)) settings.hooks.BeforeTool = [];

    settings.hooks.BeforeTool.push({
      matcher: '.*',
      hooks: [
        {
          name: 'node9-check',
          type: 'command',
          command: fullPathCommand('check'),
          timeout: 600000,
        },
      ],
    });
    console.log(chalk.green('  ✅ BeforeTool hook added → node9 check'));
    anythingChanged = true;
  }

  const hasAfterHook =
    Array.isArray(settings.hooks.AfterTool) &&
    settings.hooks.AfterTool.some((m) =>
      m.hooks.some((h) => h.command?.includes('node9 log') || h.command?.includes('cli.js log'))
    );
  if (!hasAfterHook) {
    if (!settings.hooks.AfterTool) settings.hooks.AfterTool = [];
    // If it was an object (old format), we re-initialize it as an array
    if (!Array.isArray(settings.hooks.AfterTool)) settings.hooks.AfterTool = [];

    settings.hooks.AfterTool.push({
      matcher: '.*',
      hooks: [{ name: 'node9-log', type: 'command', command: fullPathCommand('log') }],
    });
    console.log(chalk.green('  ✅ AfterTool hook added  → node9 log'));
    anythingChanged = true;
  }

  if (anythingChanged) {
    writeJson(settingsPath, settings);
    console.log('');
  }

  // ── Step 2: Modifications — show preview and ask ─────────────────────────
  const serversToWrap: Array<{ name: string; originalCmd: string; parts: string[] }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    const parts = [server.command, ...(server.args ?? [])];
    serversToWrap.push({ name, originalCmd: parts.join(' '), parts });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${settingsPath}  (mcpServers)`));
    for (const { name, originalCmd } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${originalCmd}" → node9 ${originalCmd}`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, parts } of serversToWrap) {
        servers[name] = { ...servers[name], command: 'node9', args: parts };
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
    printDaemonTip();
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting Gemini CLI!'));
    console.log(chalk.gray('    Restart Gemini CLI for changes to take effect.'));
    printDaemonTip();
  }
}

// ── Cursor ───────────────────────────────────────────────────────────────────

interface CursorMcpConfig {
  mcpServers?: Record<string, McpServer>;
  [key: string]: unknown;
}

export async function setupCursor(): Promise<void> {
  const homeDir = os.homedir();
  const mcpPath = path.join(homeDir, '.cursor', 'mcp.json');

  const mcpConfig = readJson<CursorMcpConfig>(mcpPath) ?? {};
  const servers = mcpConfig.mcpServers ?? {};

  let anythingChanged = false;

  // Note: Cursor does not yet support a pre-execution hooks file.
  // Native hook mode is pending Cursor shipping that capability.
  // MCP proxy wrapping is the supported protection method for now.

  // ── Modifications — show preview and ask ─────────────────────────
  const serversToWrap: Array<{ name: string; originalCmd: string; parts: string[] }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    const parts = [server.command, ...(server.args ?? [])];
    serversToWrap.push({ name, originalCmd: parts.join(' '), parts });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${mcpPath}`));
    for (const { name, originalCmd } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${originalCmd}" → node9 ${originalCmd}`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, parts } of serversToWrap) {
        servers[name] = { ...servers[name], command: 'node9', args: parts };
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
  console.log(
    chalk.yellow(
      '  ⚠️  Note: Cursor does not yet support native pre-execution hooks.\n' +
        '     MCP proxy wrapping is the only supported protection mode for Cursor.'
    )
  );
  console.log('');

  if (!anythingChanged && serversToWrap.length === 0) {
    console.log(
      chalk.blue(
        'ℹ️  No MCP servers found to wrap. Add MCP servers to ~/.cursor/mcp.json and re-run.'
      )
    );
    printDaemonTip();
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting Cursor via MCP proxy!'));
    console.log(chalk.gray('    Restart Cursor for changes to take effect.'));
    printDaemonTip();
  }
}
