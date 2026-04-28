// src/setup.ts
import fs from 'fs';
import path from 'path';
import os from 'os';
import chalk from 'chalk';
import { confirm } from '@inquirer/prompts';
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';

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

/**
 * A previously-installed Node9 hook command can outlive the install that
 * wrote it — `npm uninstall -g node9-ai` deletes the cli.js but leaves the
 * stored command in `~/.claude/settings.json` pointing at a vanished path.
 * Claude Code then crashes every tool call with `node:internal/modules/cjs/loader`.
 *
 * Returns true when the command references at least one absolute path that
 * no longer exists on disk. Bare commands like `node9 check` (no `/`)
 * resolve via $PATH at runtime and are never considered stale here.
 */
function isStaleHookCommand(command: string): boolean {
  if (!command) return false;
  const tokens = command.split(/\s+/);
  for (const tok of tokens) {
    if (!tok.startsWith('/')) continue;
    if (!fs.existsSync(tok)) return true;
  }
  return false;
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
  const mcpPath = path.join(homeDir, '.claude', '.mcp.json');
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
      console.log(chalk.green('  ✅ Removed node9 MCP server entry from ~/.claude/.mcp.json'));
    }

    for (const [name, server] of Object.entries(claudeConfig.mcpServers)) {
      const args = server.args as string[] | undefined;
      if (
        server.command === 'node9' &&
        Array.isArray(args) &&
        args[0] === 'mcp' &&
        args[1] === '--upstream' &&
        typeof args[2] === 'string'
      ) {
        const [originalCmd, ...originalArgs] = args[2].split(' ');
        claudeConfig.mcpServers[name] = {
          ...server,
          command: originalCmd,
          args: originalArgs.length ? originalArgs : undefined,
        };
        mcpChanged = true;
      } else if (server.command === 'node9') {
        // Not a wrapped entry (e.g. node9 mcp-server) — skip silently.
      }
    }
    if (mcpChanged) {
      writeJson(mcpPath, claudeConfig);
      console.log(chalk.green('  ✅ Unwrapped MCP servers in ~/.claude/.mcp.json'));
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
      const args = server.args as string[] | undefined;
      if (
        server.command === 'node9' &&
        Array.isArray(args) &&
        args[0] === 'mcp' &&
        args[1] === '--upstream' &&
        typeof args[2] === 'string'
      ) {
        const [originalCmd, ...originalArgs] = args[2].split(' ');
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
    const args = server.args as string[] | undefined;
    if (
      server.command === 'node9' &&
      Array.isArray(args) &&
      args[0] === 'mcp' &&
      args[1] === '--upstream' &&
      typeof args[2] === 'string'
    ) {
      const [originalCmd, ...originalArgs] = args[2].split(' ');
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
  const mcpPath = path.join(homeDir, '.claude', '.mcp.json');
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
      hooks: [{ type: 'command', command: fullPathCommand('check'), timeout: 600 }],
    });
    console.log(chalk.green('  ✅ PreToolUse hook added  → node9 check'));
    hooksChanged = true;
    anythingChanged = true;
  } else if (settings.hooks.PreToolUse) {
    // Self-heal: rewrite Node9 hooks whose absolute paths have vanished.
    for (const matcher of settings.hooks.PreToolUse) {
      for (const h of matcher.hooks) {
        const cmd = h.command ?? '';
        const isNode9 = cmd.includes('node9 check') || cmd.includes('cli.js check');
        if (isNode9 && isStaleHookCommand(cmd)) {
          h.command = fullPathCommand('check');
          console.log(chalk.yellow('  🔧 PreToolUse hook repaired (stale path → current binary)'));
          hooksChanged = true;
          anythingChanged = true;
        }
      }
    }
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
  } else if (settings.hooks.PostToolUse) {
    for (const matcher of settings.hooks.PostToolUse) {
      for (const h of matcher.hooks) {
        const cmd = h.command ?? '';
        const isNode9 = cmd.includes('node9 log') || cmd.includes('cli.js log');
        if (isNode9 && isStaleHookCommand(cmd)) {
          h.command = fullPathCommand('log');
          console.log(chalk.yellow('  🔧 PostToolUse hook repaired (stale path → current binary)'));
          hooksChanged = true;
          anythingChanged = true;
        }
      }
    }
  }

  // Add the node9 MCP server entry if not already present (pure addition — no prompt)
  if (!hasNode9McpServer(servers)) {
    servers['node9'] = NODE9_MCP_SERVER_ENTRY;
    claudeConfig.mcpServers = servers;
    writeJson(mcpPath, claudeConfig);
    console.log(chalk.green('  ✅ node9 MCP server added   → node9 mcp-server'));
    anythingChanged = true;
  }

  // ── HUD (statusLine) — set alongside hooks in the same write ────────────
  const hudCommand = fullPathCommand('hud');
  const statusLineObj = { type: 'command', command: hudCommand };
  const existingStatusLine = settings.statusLine as
    | { type?: string; command?: string }
    | string
    | undefined;
  const existingStatusCommand =
    typeof existingStatusLine === 'object' ? existingStatusLine?.command : existingStatusLine;
  if (existingStatusCommand !== hudCommand) {
    settings.statusLine = statusLineObj as unknown as string;
    hooksChanged = true;
    anythingChanged = true;
  }

  if (hooksChanged) {
    writeJson(hooksPath, settings);
    console.log('');
  }

  // ── Step 2: Modifications — show preview and ask ─────────────────────────
  const serversToWrap: Array<{ name: string; upstream: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    const upstream = [server.command, ...(server.args ?? [])].join(' ');
    serversToWrap.push({ name, upstream });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${mcpPath}`));
    for (const { name, upstream } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${upstream}" → node9 mcp --upstream "${upstream}"`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, upstream } of serversToWrap) {
        servers[name] = {
          ...servers[name],
          command: 'node9',
          args: ['mcp', '--upstream', upstream],
        };
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
  const serversToWrap: Array<{ name: string; upstream: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    const upstream = [server.command, ...(server.args ?? [])].join(' ');
    serversToWrap.push({ name, upstream });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${settingsPath}  (mcpServers)`));
    for (const { name, upstream } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${upstream}" → node9 mcp --upstream "${upstream}"`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, upstream } of serversToWrap) {
        servers[name] = {
          ...servers[name],
          command: 'node9',
          args: ['mcp', '--upstream', upstream],
        };
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

/** Returns the Claude Desktop config path for the current platform, or null if unsupported. */
export function claudeDesktopConfigPath(homeDir: string = os.homedir()): string | null {
  if (process.platform === 'darwin') {
    return path.join(
      homeDir,
      'Library',
      'Application Support',
      'Claude',
      'claude_desktop_config.json'
    );
  }
  if (process.platform === 'linux') {
    return path.join(homeDir, '.config', 'Claude', 'claude_desktop_config.json');
  }
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA ?? path.join(homeDir, 'AppData', 'Roaming');
    return path.join(appData, 'Claude', 'claude_desktop_config.json');
  }
  return null;
}

/**
 * Detect which AI agents are installed on this machine.
 * Used by `node9 init` to auto-wire all detected agents.
 */
export function detectAgents(homeDir: string = os.homedir()): {
  claude: boolean;
  gemini: boolean;
  cursor: boolean;
  codex: boolean;
  windsurf: boolean;
  vscode: boolean;
  claudeDesktop: boolean;
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
  const desktopPath = claudeDesktopConfigPath(homeDir);
  return {
    claude: exists(path.join(homeDir, '.claude')) || exists(path.join(homeDir, '.claude.json')),
    gemini: exists(path.join(homeDir, '.gemini')),
    cursor: exists(path.join(homeDir, '.cursor')),
    codex: exists(path.join(homeDir, '.codex')),
    windsurf: exists(path.join(homeDir, '.codeium', 'windsurf')),
    vscode: exists(path.join(homeDir, '.vscode')),
    claudeDesktop: desktopPath !== null && exists(path.dirname(desktopPath)),
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
  const serversToWrap: Array<{ name: string; upstream: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    const upstream = [server.command, ...(server.args ?? [])].join(' ');
    serversToWrap.push({ name, upstream });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${mcpPath}`));
    for (const { name, upstream } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${upstream}" → node9 mcp --upstream "${upstream}"`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, upstream } of serversToWrap) {
        servers[name] = {
          ...servers[name],
          command: 'node9',
          args: ['mcp', '--upstream', upstream],
        };
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

// ── Codex ─────────────────────────────────────────────────────────────────────

interface CodexConfig {
  mcp_servers?: Record<string, McpServer>;
  [key: string]: unknown;
}

function readToml<T>(filePath: string): T | null {
  try {
    if (fs.existsSync(filePath)) {
      return parseToml(fs.readFileSync(filePath, 'utf-8')) as T;
    }
  } catch {
    // ignore corrupt or missing files
  }
  return null;
}

function writeToml(filePath: string, data: unknown): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, stringifyToml(data as Record<string, unknown>));
}

export async function setupCodex(): Promise<void> {
  const homeDir = os.homedir();
  const configPath = path.join(homeDir, '.codex', 'config.toml');

  const config = readToml<CodexConfig>(configPath) ?? {};
  const servers = config.mcp_servers ?? {};

  let anythingChanged = false;

  // Note: Codex does not yet support a pre-execution hooks file.
  // MCP proxy wrapping is the supported protection method for now.

  // Add the node9 MCP server entry if not already present (pure addition — no prompt)
  if (!hasNode9McpServer(servers)) {
    servers['node9'] = NODE9_MCP_SERVER_ENTRY;
    config.mcp_servers = servers;
    writeToml(configPath, config);
    console.log(chalk.green('  ✅ node9 MCP server added   → node9 mcp-server'));
    anythingChanged = true;
  }

  // ── Modifications — show preview and ask ─────────────────────────
  const serversToWrap: Array<{ name: string; upstream: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    const upstream = [server.command, ...(server.args ?? [])].join(' ');
    serversToWrap.push({ name, upstream });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${configPath}`));
    for (const { name, upstream } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${upstream}" → node9 mcp --upstream "${upstream}"`));
    }
    console.log('');

    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, upstream } of serversToWrap) {
        servers[name] = {
          ...servers[name],
          command: 'node9',
          args: ['mcp', '--upstream', upstream],
        };
      }
      config.mcp_servers = servers;
      writeToml(configPath, config);
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
      '  ⚠️  Note: Codex does not yet support native pre-execution hooks.\n' +
        '     MCP proxy wrapping is the only supported protection mode for Codex.\n' +
        '     Native bash and file operations are not monitored.'
    )
  );
  console.log('');

  if (!anythingChanged && serversToWrap.length === 0) {
    console.log(
      chalk.blue(
        'ℹ️  No MCP servers found to wrap. Add MCP servers to ~/.codex/config.toml and re-run.'
      )
    );
    printDaemonTip();
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting Codex via MCP proxy!'));
    console.log(chalk.gray('    Restart Codex for changes to take effect.'));
    printDaemonTip();
  }
}

export function teardownCodex(): void {
  const homeDir = os.homedir();
  const configPath = path.join(homeDir, '.codex', 'config.toml');

  const config = readToml<CodexConfig>(configPath);
  if (!config?.mcp_servers) {
    console.log(chalk.blue('  ℹ️  ~/.codex/config.toml not found — nothing to remove'));
    return;
  }

  let changed = false;

  // Remove the node9 MCP server entry added by setup
  if (removeNode9McpServer(config.mcp_servers)) {
    changed = true;
    console.log(chalk.green('  ✅ Removed node9 MCP server entry from ~/.codex/config.toml'));
  }

  for (const [name, server] of Object.entries(config.mcp_servers)) {
    const args = server.args as string[] | undefined;
    if (
      server.command === 'node9' &&
      Array.isArray(args) &&
      args[0] === 'mcp' &&
      args[1] === '--upstream' &&
      typeof args[2] === 'string'
    ) {
      const [originalCmd, ...originalArgs] = args[2].split(' ');
      config.mcp_servers[name] = {
        ...server,
        command: originalCmd,
        args: originalArgs.length ? originalArgs : undefined,
      };
      changed = true;
    }
  }

  if (changed) {
    writeToml(configPath, config);
    console.log(chalk.green('  ✅ Unwrapped MCP servers in ~/.codex/config.toml'));
  } else {
    console.log(chalk.blue('  ℹ️  No Node9-wrapped MCP servers found in ~/.codex/config.toml'));
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

// ── Windsurf ──────────────────────────────────────────────────────────────────
// Config: ~/.codeium/windsurf/mcp_config.json
// Format: { mcpServers: { name: { command, args } } }
// Note: Windsurf does not yet support pre-execution hooks — MCP proxy only.

interface WindsurfMcpConfig {
  mcpServers?: Record<string, McpServer>;
  [key: string]: unknown;
}

export async function setupWindsurf(): Promise<void> {
  const homeDir = os.homedir();
  const mcpPath = path.join(homeDir, '.codeium', 'windsurf', 'mcp_config.json');

  const mcpConfig = readJson<WindsurfMcpConfig>(mcpPath) ?? {};
  const servers = mcpConfig.mcpServers ?? {};

  let anythingChanged = false;

  if (!hasNode9McpServer(servers)) {
    servers['node9'] = NODE9_MCP_SERVER_ENTRY;
    mcpConfig.mcpServers = servers;
    writeJson(mcpPath, mcpConfig);
    console.log(chalk.green('  ✅ node9 MCP server added   → node9 mcp-server'));
    anythingChanged = true;
  }

  // Wrap existing non-node9 MCP servers
  const serversToWrap: Array<{ name: string; upstream: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    serversToWrap.push({ name, upstream: [server.command, ...(server.args ?? [])].join(' ') });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${mcpPath}`));
    for (const { name, upstream } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${upstream}" → node9 mcp --upstream "${upstream}"`));
    }
    console.log('');
    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, upstream } of serversToWrap) {
        servers[name] = {
          ...servers[name],
          command: 'node9',
          args: ['mcp', '--upstream', upstream],
        };
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

  console.log(
    chalk.yellow(
      '  ⚠️  Note: Windsurf does not yet support native pre-execution hooks.\n' +
        '     MCP proxy wrapping is the only supported protection mode for Windsurf.'
    )
  );
  console.log('');

  if (!anythingChanged && serversToWrap.length === 0) {
    console.log(chalk.blue('ℹ️  Node9 is already fully configured for Windsurf.'));
    printDaemonTip();
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting Windsurf via MCP proxy!'));
    console.log(chalk.gray('    Restart Windsurf for changes to take effect.'));
    printDaemonTip();
  }
}

export function teardownWindsurf(): void {
  const homeDir = os.homedir();
  const mcpPath = path.join(homeDir, '.codeium', 'windsurf', 'mcp_config.json');

  const mcpConfig = readJson<WindsurfMcpConfig>(mcpPath);
  if (!mcpConfig?.mcpServers) {
    console.log(
      chalk.blue('  ℹ️  ~/.codeium/windsurf/mcp_config.json not found — nothing to remove')
    );
    return;
  }

  let changed = false;
  if (removeNode9McpServer(mcpConfig.mcpServers)) {
    changed = true;
    console.log(
      chalk.green('  ✅ Removed node9 MCP server entry from ~/.codeium/windsurf/mcp_config.json')
    );
  }

  for (const [name, server] of Object.entries(mcpConfig.mcpServers)) {
    const args = server.args as string[] | undefined;
    if (
      server.command === 'node9' &&
      Array.isArray(args) &&
      args[0] === 'mcp' &&
      args[1] === '--upstream' &&
      typeof args[2] === 'string'
    ) {
      const [originalCmd, ...originalArgs] = args[2].split(' ');
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
    console.log(chalk.green('  ✅ Unwrapped MCP servers in ~/.codeium/windsurf/mcp_config.json'));
  } else {
    console.log(
      chalk.blue('  ℹ️  No Node9-wrapped MCP servers found in ~/.codeium/windsurf/mcp_config.json')
    );
  }
}

// ── VSCode (GitHub Copilot) ───────────────────────────────────────────────────
// Config: ~/.vscode/mcp.json  (VS Code 1.99+, requires GitHub Copilot extension)
// Format: { servers: { name: { type: "stdio", command, args } } }
// Note: VSCode does not support pre-execution hooks — MCP only.

interface VSCodeMcpServer {
  type?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

interface VSCodeMcpConfig {
  servers?: Record<string, VSCodeMcpServer>;
  [key: string]: unknown;
}

function hasNode9McpServerVSCode(servers: Record<string, VSCodeMcpServer>): boolean {
  const entry = servers['node9'];
  return (
    !!entry &&
    entry.command === 'node9' &&
    Array.isArray(entry.args) &&
    entry.args[0] === 'mcp-server'
  );
}

export async function setupVSCode(): Promise<void> {
  const homeDir = os.homedir();
  const mcpPath = path.join(homeDir, '.vscode', 'mcp.json');

  const mcpConfig = readJson<VSCodeMcpConfig>(mcpPath) ?? {};
  const servers = mcpConfig.servers ?? {};

  let anythingChanged = false;

  if (!hasNode9McpServerVSCode(servers)) {
    servers['node9'] = { type: 'stdio', command: 'node9', args: ['mcp-server'] };
    mcpConfig.servers = servers;
    writeJson(mcpPath, mcpConfig);
    console.log(chalk.green('  ✅ node9 MCP server added   → node9 mcp-server'));
    anythingChanged = true;
  }

  // Wrap existing non-node9 MCP servers
  const serversToWrap: Array<{ name: string; upstream: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    serversToWrap.push({ name, upstream: [server.command, ...(server.args ?? [])].join(' ') });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${mcpPath}`));
    for (const { name, upstream } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${upstream}" → node9 mcp --upstream "${upstream}"`));
    }
    console.log('');
    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, upstream } of serversToWrap) {
        servers[name] = {
          ...servers[name],
          type: 'stdio',
          command: 'node9',
          args: ['mcp', '--upstream', upstream],
        };
      }
      mcpConfig.servers = servers;
      writeJson(mcpPath, mcpConfig);
      console.log(chalk.green(`\n  ✅ ${serversToWrap.length} MCP server(s) wrapped`));
      anythingChanged = true;
    } else {
      console.log(chalk.yellow('  Skipped MCP server wrapping.'));
    }
    console.log('');
  }

  console.log(
    chalk.yellow(
      '  ⚠️  Note: VSCode MCP support requires the GitHub Copilot extension (v1.99+).\n' +
        '     Pre-execution hooks are not supported — MCP proxy wrapping only.'
    )
  );
  console.log('');

  if (!anythingChanged && serversToWrap.length === 0) {
    console.log(chalk.blue('ℹ️  Node9 is already fully configured for VSCode.'));
    printDaemonTip();
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting VSCode via MCP proxy!'));
    console.log(chalk.gray('    Restart VSCode for changes to take effect.'));
    printDaemonTip();
  }
}

export function teardownVSCode(): void {
  const homeDir = os.homedir();
  const mcpPath = path.join(homeDir, '.vscode', 'mcp.json');

  const mcpConfig = readJson<VSCodeMcpConfig>(mcpPath);
  if (!mcpConfig?.servers) {
    console.log(chalk.blue('  ℹ️  ~/.vscode/mcp.json not found — nothing to remove'));
    return;
  }

  let changed = false;

  if (hasNode9McpServerVSCode(mcpConfig.servers)) {
    delete mcpConfig.servers['node9'];
    changed = true;
    console.log(chalk.green('  ✅ Removed node9 MCP server entry from ~/.vscode/mcp.json'));
  }

  for (const [name, server] of Object.entries(mcpConfig.servers)) {
    const args = server.args as string[] | undefined;
    if (
      server.command === 'node9' &&
      Array.isArray(args) &&
      args[0] === 'mcp' &&
      args[1] === '--upstream' &&
      typeof args[2] === 'string'
    ) {
      const [originalCmd, ...originalArgs] = args[2].split(' ');
      mcpConfig.servers[name] = {
        ...server,
        type: 'stdio',
        command: originalCmd,
        args: originalArgs.length ? originalArgs : undefined,
      };
      changed = true;
    }
  }

  if (changed) {
    writeJson(mcpPath, mcpConfig);
    console.log(chalk.green('  ✅ Unwrapped MCP servers in ~/.vscode/mcp.json'));
  } else {
    console.log(chalk.blue('  ℹ️  No Node9-wrapped MCP servers found in ~/.vscode/mcp.json'));
  }
}

// ── Claude Desktop ────────────────────────────────────────────────────────────
// Config: ~/Library/Application Support/Claude/claude_desktop_config.json (macOS)
//         ~/.config/Claude/claude_desktop_config.json (Linux)
// Format: { mcpServers: { name: { command, args } } }
// Note: Claude Desktop does not support pre-execution hooks — MCP proxy only.

export async function setupClaudeDesktop(): Promise<void> {
  const configPath = claudeDesktopConfigPath();
  if (!configPath) {
    console.log(chalk.yellow('  ⚠️  Claude Desktop is not supported on this platform.'));
    return;
  }

  const config = readJson<ClaudeConfig>(configPath) ?? {};
  const servers = config.mcpServers ?? {};

  let anythingChanged = false;

  if (!hasNode9McpServer(servers)) {
    servers['node9'] = NODE9_MCP_SERVER_ENTRY;
    config.mcpServers = servers;
    writeJson(configPath, config);
    console.log(chalk.green('  ✅ node9 MCP server added   → node9 mcp-server'));
    anythingChanged = true;
  }

  const serversToWrap: Array<{ name: string; upstream: string }> = [];
  for (const [name, server] of Object.entries(servers)) {
    if (!server.command || server.command === 'node9') continue;
    serversToWrap.push({ name, upstream: [server.command, ...(server.args ?? [])].join(' ') });
  }

  if (serversToWrap.length > 0) {
    console.log(chalk.bold('The following existing entries will be modified:\n'));
    console.log(chalk.white(`  ${configPath}`));
    for (const { name, upstream } of serversToWrap) {
      console.log(chalk.gray(`    • ${name}: "${upstream}" → node9 mcp --upstream "${upstream}"`));
    }
    console.log('');
    const proceed = await confirm({ message: 'Wrap these MCP servers?', default: true });
    if (proceed) {
      for (const { name, upstream } of serversToWrap) {
        servers[name] = {
          ...servers[name],
          command: 'node9',
          args: ['mcp', '--upstream', upstream],
        };
      }
      config.mcpServers = servers;
      writeJson(configPath, config);
      console.log(chalk.green(`\n  ✅ ${serversToWrap.length} MCP server(s) wrapped`));
      anythingChanged = true;
    } else {
      console.log(chalk.yellow('  Skipped MCP server wrapping.'));
    }
    console.log('');
  }

  console.log(
    chalk.yellow(
      '  ⚠️  Note: Claude Desktop does not support pre-execution hooks.\n' +
        '     MCP proxy wrapping is the only supported protection mode.'
    )
  );
  console.log('');

  if (!anythingChanged && serversToWrap.length === 0) {
    console.log(chalk.blue('ℹ️  Node9 is already fully configured for Claude Desktop.'));
    printDaemonTip();
    return;
  }

  if (anythingChanged) {
    console.log(chalk.green.bold('🛡️  Node9 is now protecting Claude Desktop via MCP proxy!'));
    console.log(chalk.gray('    Restart Claude Desktop for changes to take effect.'));
    printDaemonTip();
  }
}

export function teardownClaudeDesktop(): void {
  const configPath = claudeDesktopConfigPath();
  if (!configPath) {
    console.log(chalk.yellow('  ⚠️  Claude Desktop is not supported on this platform.'));
    return;
  }

  const config = readJson<ClaudeConfig>(configPath);
  if (!config?.mcpServers) {
    console.log(chalk.blue('  ℹ️  Claude Desktop config not found — nothing to remove'));
    return;
  }

  let changed = false;

  if (removeNode9McpServer(config.mcpServers)) {
    changed = true;
    console.log(chalk.green(`  ✅ Removed node9 MCP server entry from ${configPath}`));
  }

  for (const [name, server] of Object.entries(config.mcpServers)) {
    const args = server.args as string[] | undefined;
    if (
      server.command === 'node9' &&
      Array.isArray(args) &&
      args[0] === 'mcp' &&
      args[1] === '--upstream' &&
      typeof args[2] === 'string'
    ) {
      const [originalCmd, ...originalArgs] = args[2].split(' ');
      config.mcpServers[name] = {
        ...server,
        command: originalCmd,
        args: originalArgs.length ? originalArgs : undefined,
      };
      changed = true;
    }
  }

  if (changed) {
    writeJson(configPath, config);
    console.log(chalk.green('  ✅ Unwrapped MCP servers in Claude Desktop config'));
  } else {
    console.log(chalk.blue('  ℹ️  No Node9-wrapped MCP servers found in Claude Desktop config'));
  }
}

// ── Agent wired-status checks ─────────────────────────────────────────────────
// Each function returns true if node9 hooks/MCP are present in the agent config.

export type AgentName =
  | 'claude'
  | 'gemini'
  | 'cursor'
  | 'codex'
  | 'windsurf'
  | 'vscode'
  | 'claudeDesktop';

export interface AgentStatus {
  name: AgentName;
  label: string;
  installed: boolean;
  wired: boolean;
  mode: 'hooks' | 'mcp' | null; // null when not installed
}

export function getAgentsStatus(homeDir: string = os.homedir()): AgentStatus[] {
  const detected = detectAgents(homeDir);

  const claudeWired = (() => {
    const settings = readJson<ClaudeSettings>(path.join(homeDir, '.claude', 'settings.json'));
    return !!settings?.hooks?.PreToolUse?.some((m) => m.hooks.some((h) => isNode9Hook(h.command)));
  })();

  const geminiWired = (() => {
    const settings = readJson<GeminiSettings>(path.join(homeDir, '.gemini', 'settings.json'));
    return !!settings?.hooks?.BeforeTool?.some((m) => m.hooks.some((h) => isNode9Hook(h.command)));
  })();

  const cursorWired = (() => {
    const cfg = readJson<CursorMcpConfig>(path.join(homeDir, '.cursor', 'mcp.json'));
    return !!(cfg?.mcpServers && hasNode9McpServer(cfg.mcpServers));
  })();

  const codexWired = (() => {
    const cfg = readToml<CodexConfig>(path.join(homeDir, '.codex', 'config.toml'));
    return !!(cfg?.mcp_servers && hasNode9McpServer(cfg.mcp_servers));
  })();

  const windsurfWired = (() => {
    const cfg = readJson<WindsurfMcpConfig>(
      path.join(homeDir, '.codeium', 'windsurf', 'mcp_config.json')
    );
    return !!(cfg?.mcpServers && hasNode9McpServer(cfg.mcpServers));
  })();

  const vscodeWired = (() => {
    const cfg = readJson<VSCodeMcpConfig>(path.join(homeDir, '.vscode', 'mcp.json'));
    return !!(cfg?.servers && hasNode9McpServerVSCode(cfg.servers));
  })();

  return [
    {
      name: 'claude',
      label: 'Claude Code',
      installed: detected.claude,
      wired: claudeWired,
      mode: detected.claude ? 'hooks' : null,
    },
    {
      name: 'gemini',
      label: 'Gemini CLI',
      installed: detected.gemini,
      wired: geminiWired,
      mode: detected.gemini ? 'hooks' : null,
    },
    {
      name: 'cursor',
      label: 'Cursor',
      installed: detected.cursor,
      wired: cursorWired,
      mode: detected.cursor ? 'mcp' : null,
    },
    {
      name: 'windsurf',
      label: 'Windsurf',
      installed: detected.windsurf,
      wired: windsurfWired,
      mode: detected.windsurf ? 'mcp' : null,
    },
    {
      name: 'vscode',
      label: 'VSCode',
      installed: detected.vscode,
      wired: vscodeWired,
      mode: detected.vscode ? 'mcp' : null,
    },
    {
      name: 'codex',
      label: 'Codex',
      installed: detected.codex,
      wired: codexWired,
      mode: detected.codex ? 'mcp' : null,
    },
    {
      name: 'claudeDesktop',
      label: 'Claude Desktop',
      installed: detected.claudeDesktop,
      wired: (() => {
        const cfgPath = claudeDesktopConfigPath(homeDir);
        if (!cfgPath) return false;
        const cfg = readJson<ClaudeConfig>(cfgPath);
        return !!(cfg?.mcpServers && hasNode9McpServer(cfg.mcpServers));
      })(),
      mode: detected.claudeDesktop ? 'mcp' : null,
    },
  ];
}
