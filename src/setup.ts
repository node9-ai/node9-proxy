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

/** The MCP server entry node9 injects into agent configs. */
const NODE9_MCP_SERVER_ENTRY: McpServer = { command: 'node9', args: ['mcp-server'] };

/** Returns true if the mcpServers map already has the node9 MCP server entry. */
function hasNode9McpServer(servers: Record<string, McpServer>): boolean {
  const entry = servers['node9'];
  return (
    !!entry &&
    entry.command === 'node9' &&
    Array.isArray(entry.args) &&
    entry.args[0] === 'mcp-server'
  );
}

/** Removes the node9 MCP server entry from a servers map. Returns true if removed. */
function removeNode9McpServer(servers: Record<string, McpServer>): boolean {
  if (!hasNode9McpServer(servers)) return false;
  delete servers['node9'];
  return true;
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
  const cliScript = process.argv[1]; // dist/cli.js (dev) or .../bin/node9 (global install)
  // When installed globally or via npm link, argv[1] is the binary itself — a
  // self-contained executable that must not be prefixed with node.
  if (!cliScript.endsWith('.js')) return `${cliScript} ${subcommand}`;
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

// ── Helpers ───────────────────────────────────────────────────────────────────

// Matches hook commands written by node9 in any of these forms:
//   node9 check                     (global install, NODE9_TESTING)
//   /path/to/node9 check            (global install, full path)
//   /path/to/node /path/to/cli.js check  (npm link / local install)
// The word-boundary prefix (?:^|[\s/\\]) prevents false matches on
// binaries that merely contain "node9" as a substring (e.g. mynode9).
function isNode9Hook(cmd: string | undefined): boolean {
  if (!cmd) return false;
  return (
    /(?:^|[\s/\\])node9 (?:check|log)/.test(cmd) || /(?:^|[\s/\\])cli\.js (?:check|log)/.test(cmd)
  );
}

// ── Teardown ──────────────────────────────────────────────────────────────────

export function teardownClaude(): void {
  const homeDir = os.homedir();
  const hooksPath = path.join(homeDir, '.claude', 'settings.json');
  const mcpPath = path.join(homeDir, '.claude.json');
  let changed = false;

  // Remove hook matchers from settings.json
  const settings = readJson<ClaudeSettings>(hooksPath);
  if (settings?.hooks) {
    for (const event of ['PreToolUse', 'PostToolUse'] as const) {
      const before = settings.hooks[event]?.length ?? 0;
      settings.hooks[event] = settings.hooks[event]?.filter(
        (m) => !m.hooks.some((h) => isNode9Hook(h.command))
      );
      if ((settings.hooks[event]?.length ?? 0) < before) changed = true;
      if (settings.hooks[event]?.length === 0) delete settings.hooks[event];
    }
    if (changed) {
      writeJson(hooksPath, settings);
      console.log(
        chalk.green('  ✅ Removed PreToolUse / PostToolUse hooks from ~/.claude/settings.json')
      );
    } else {
      console.log(chalk.blue('  ℹ️  No Node9 hooks found in ~/.claude/settings.json'));
    }
  }

  // Unwrap MCP servers in .claude.json
  const claudeConfig = readJson<ClaudeConfig>(mcpPath);
  if (claudeConfig?.mcpServers) {
    let mcpChanged = false;

    // Remove the node9 MCP server entry added by setup
    if (removeNode9McpServer(claudeConfig.mcpServers)) {
      mcpChanged = true;
      console.log(chalk.green('  ✅ Removed node9 MCP server entry from ~/.claude.json'));
    }

    for (const [name, server] of Object.entries(claudeConfig.mcpServers)) {
      if (server.command === 'node9' && Array.isArray(server.args) && server.args.length > 0) {
        const [originalCmd, ...originalArgs] = server.args as string[];
        claudeConfig.mcpServers[name] = {
          ...server,
          command: originalCmd,
          args: originalArgs.length ? originalArgs : undefined,
        };
        mcpChanged = true;
      } else if (server.command === 'node9') {
        // args is empty or missing — cannot determine original command.
        // Leave the entry intact and warn so the user can fix it manually.
        console.warn(
          chalk.yellow(
            `  ⚠️  Cannot unwrap MCP server "${name}" in ~/.claude.json — args is empty. Remove it manually.`
          )
        );
      }
    }
    if (mcpChanged) {
      writeJson(mcpPath, claudeConfig);
      console.log(chalk.green('  ✅ Unwrapped MCP servers in ~/.claude.json'));
    }
  }
}

export function teardownGemini(): void {
  const homeDir = os.homedir();
  const settingsPath = path.join(homeDir, '.gemini', 'settings.json');

  const settings = readJson<GeminiSettings>(settingsPath);
  if (!settings) {
    console.log(chalk.blue('  ℹ️  ~/.gemini/settings.json not found — nothing to remove'));
    return;
  }

  let changed = false;
  for (const event of ['BeforeTool', 'AfterTool'] as const) {
    const before = settings.hooks?.[event]?.length ?? 0;
    if (settings.hooks?.[event]) {
      settings.hooks[event] = settings.hooks[event]!.filter(
        (m) => !m.hooks.some((h) => isNode9Hook(h.command))
      );
      if ((settings.hooks[event]?.length ?? 0) < before) changed = true;
      if (settings.hooks[event]?.length === 0) delete settings.hooks[event];
    }
  }

  // Unwrap MCP servers
  if (settings.mcpServers) {
    // Remove the node9 MCP server entry added by setup
    if (removeNode9McpServer(settings.mcpServers)) {
      changed = true;
      console.log(chalk.green('  ✅ Removed node9 MCP server entry from ~/.gemini/settings.json'));
    }

    for (const [name, server] of Object.entries(settings.mcpServers)) {
      if (server.command === 'node9' && Array.isArray(server.args) && server.args.length > 0) {
        const [originalCmd, ...originalArgs] = server.args as string[];
        settings.mcpServers[name] = {
          ...server,
          command: originalCmd,
          args: originalArgs.length ? originalArgs : undefined,
        };
        changed = true;
      }
    }
  }

  if (changed) {
    writeJson(settingsPath, settings);
    console.log(chalk.green('  ✅ Removed Node9 hooks from ~/.gemini/settings.json'));
  } else {
    console.log(chalk.blue('  ℹ️  No Node9 hooks found in ~/.gemini/settings.json'));
  }
}

export function teardownCursor(): void {
  const homeDir = os.homedir();
  const mcpPath = path.join(homeDir, '.cursor', 'mcp.json');

  const mcpConfig = readJson<CursorMcpConfig>(mcpPath);
  if (!mcpConfig?.mcpServers) {
    console.log(chalk.blue('  ℹ️  ~/.cursor/mcp.json not found — nothing to remove'));
    return;
  }

  let changed = false;

  // Remove the node9 MCP server entry added by setup
  if (removeNode9McpServer(mcpConfig.mcpServers)) {
    changed = true;
    console.log(chalk.green('  ✅ Removed node9 MCP server entry from ~/.cursor/mcp.json'));
  }

  for (const [name, server] of Object.entries(mcpConfig.mcpServers)) {
    if (server.command === 'node9' && Array.isArray(server.args) && server.args.length > 0) {
      const [originalCmd, ...originalArgs] = server.args as string[];
      mcpConfig.mcpServers[name] = {
        ...server,
        command: originalCmd,
        args: originalArgs.length ? originalArgs : undefined,
      };
      changed = true;
    }
  }

  if (changed) {
    writeJson(mcpPath, mcpConfig);
    console.log(chalk.green('  ✅ Unwrapped MCP servers in ~/.cursor/mcp.json'));
  } else {
    console.log(chalk.blue('  ℹ️  No Node9-wrapped MCP servers found in ~/.cursor/mcp.json'));
  }
}

// ── Claude Code ──────────────────────────────────────────────────────────────

export async function setupClaude(): Promise<void> {
  const homeDir = os.homedir();
  const mcpPath = path.join(homeDir, '.claude.json');
  const hooksPath = path.join(homeDir, '.claude', 'settings.json');

  const claudeConfig = readJson<ClaudeConfig>(mcpPath) ?? {};
  const settings = readJson<ClaudeSettings>(hooksPath) ?? {};
  const servers = claudeConfig.mcpServers ?? {};

  let hooksChanged = false;
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
    hooksChanged = true;
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
    hooksChanged = true;
    anythingChanged = true;
  }

  // Add the node9 MCP server entry if not already present (pure addition — no prompt)
  if (!hasNode9McpServer(servers)) {
    servers['node9'] = NODE9_MCP_SERVER_ENTRY;
    claudeConfig.mcpServers = servers;
    writeJson(mcpPath, claudeConfig);
    console.log(chalk.green('  ✅ node9 MCP server added   → node9 mcp-server'));
    anythingChanged = true;
  }

  if (hooksChanged) {
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

  let hooksChanged = false;
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
    hooksChanged = true;
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
    hooksChanged = true;
    anythingChanged = true;
  }

  // Add the node9 MCP server entry if not already present (pure addition — no prompt)
  if (!hasNode9McpServer(servers)) {
    servers['node9'] = NODE9_MCP_SERVER_ENTRY;
    settings.mcpServers = servers;
    console.log(chalk.green('  ✅ node9 MCP server added   → node9 mcp-server'));
    hooksChanged = true;
    anythingChanged = true;
  }

  if (hooksChanged) {
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

/**
 * Detect which AI agents are installed on this machine.
 * Used by `node9 init` to auto-wire all detected agents.
 */
export function detectAgents(homeDir: string = os.homedir()): {
  claude: boolean;
  gemini: boolean;
  cursor: boolean;
} {
  const exists = (p: string): boolean => {
    try {
      return fs.existsSync(p);
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') {
        process.stderr.write(`[node9] detectAgents: cannot access ${p}: ${code ?? String(err)}\n`);
      }
      return false;
    }
  };
  return {
    claude: exists(path.join(homeDir, '.claude')) || exists(path.join(homeDir, '.claude.json')),
    gemini: exists(path.join(homeDir, '.gemini')),
    cursor: exists(path.join(homeDir, '.cursor')),
  };
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

  // Add the node9 MCP server entry if not already present (pure addition — no prompt)
  if (!hasNode9McpServer(servers)) {
    servers['node9'] = NODE9_MCP_SERVER_ENTRY;
    mcpConfig.mcpServers = servers;
    writeJson(mcpPath, mcpConfig);
    console.log(chalk.green('  ✅ node9 MCP server added   → node9 mcp-server'));
    anythingChanged = true;
  }

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

// ── HUD (Claude Code statusLine) ─────────────────────────────────────────────

export function setupHud(): void {
  const homeDir = os.homedir();
  const hooksPath = path.join(homeDir, '.claude', 'settings.json');

  const settings = readJson<ClaudeSettings>(hooksPath) ?? {};

  const hudCommand = fullPathCommand('hud');
  // Claude Code expects statusLine as { command: string }, not a bare string.
  const statusLineObj = { type: 'command', command: hudCommand };
  const existing = settings.statusLine as { type?: string; command?: string } | string | undefined;
  const existingCommand = typeof existing === 'object' ? existing?.command : existing;

  if (existingCommand === hudCommand) {
    console.log(chalk.blue('ℹ️  node9 HUD is already configured in ~/.claude/settings.json'));
    console.log(chalk.gray('   Restart Claude Code to activate.'));
    return;
  }

  if (existing && existingCommand !== hudCommand) {
    console.log(
      chalk.yellow(
        `  ⚠️  statusLine is already set to: "${existingCommand}"\n` +
          `     Overwriting with node9 HUD.`
      )
    );
  }

  settings.statusLine = statusLineObj as unknown as string;
  writeJson(hooksPath, settings);

  console.log(chalk.green.bold('✅ node9 HUD added to Claude Code statusline'));
  console.log(chalk.gray('   Settings: ~/.claude/settings.json'));
  console.log(chalk.gray('   Restart Claude Code to activate.'));
}

export function teardownHud(): void {
  const homeDir = os.homedir();
  const hooksPath = path.join(homeDir, '.claude', 'settings.json');

  const settings = readJson<ClaudeSettings>(hooksPath);
  if (!settings) {
    console.log(chalk.blue('  ℹ️  ~/.claude/settings.json not found — nothing to remove'));
    return;
  }

  const existing = settings.statusLine as { command?: string } | string | undefined;
  const existingCommand = typeof existing === 'object' ? existing?.command : existing;
  if (!existingCommand || !String(existingCommand).includes('node9')) {
    console.log(chalk.blue('  ℹ️  node9 HUD not found in ~/.claude/settings.json'));
    return;
  }

  delete settings.statusLine;
  writeJson(hooksPath, settings);
  console.log(chalk.green('  ✅ node9 HUD removed from ~/.claude/settings.json'));
  console.log(chalk.gray('   Restart Claude Code for changes to take effect.'));
}
