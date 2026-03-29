// src/cli/commands/status.ts
// Registered as `node9 status` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { getCredentials, getConfig, checkPause } from '../../core';
import { isDaemonRunning, DAEMON_PORT } from '../../auth/daemon';

interface McpServer {
  command?: string;
  args?: string[];
  [key: string]: unknown;
}

interface ClaudeConfig {
  mcpServers?: Record<string, McpServer>;
  [key: string]: unknown;
}

interface HookEntry {
  command?: string;
  [key: string]: unknown;
}

interface HookMatcher {
  hooks: HookEntry[];
  [key: string]: unknown;
}

interface ClaudeSettings {
  hooks?: {
    PreToolUse?: HookMatcher[];
    PostToolUse?: HookMatcher[];
    [key: string]: HookMatcher[] | undefined;
  };
  [key: string]: unknown;
}

interface GeminiSettings {
  mcpServers?: Record<string, McpServer>;
  hooks?: {
    BeforeTool?: HookMatcher[];
    AfterTool?: HookMatcher[];
    [key: string]: HookMatcher[] | undefined;
  };
  [key: string]: unknown;
}

interface CursorMcpConfig {
  mcpServers?: Record<string, McpServer>;
  [key: string]: unknown;
}

function readJson<T>(filePath: string): T | null {
  try {
    if (fs.existsSync(filePath)) return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as T;
  } catch {}
  return null;
}

function isNode9Hook(cmd: string | undefined): boolean {
  if (!cmd) return false;
  return (
    /(?:^|[\s/\\])node9 (?:check|log)/.test(cmd) || /(?:^|[\s/\\])cli\.js (?:check|log)/.test(cmd)
  );
}

function wrappedMcpServers(servers: Record<string, McpServer> | undefined): string[] {
  if (!servers) return [];
  return Object.entries(servers)
    .filter(([, s]) => s.command === 'node9' && Array.isArray(s.args) && s.args.length > 0)
    .map(([name, s]) => `${name} → ${(s.args as string[]).join(' ')}`);
}

function printAgentSection(
  label: string,
  hookPairs: Array<{ name: string; present: boolean }>,
  wrapped: string[]
): void {
  console.log(chalk.bold(`  ${label}`));
  for (const { name, present } of hookPairs) {
    if (present) {
      console.log(chalk.green(`    ✓ ${name}`));
    } else {
      console.log(chalk.red(`    ✗ ${name}`) + chalk.gray(' (not wired)'));
    }
  }
  if (wrapped.length > 0) {
    console.log(chalk.cyan(`    MCP proxied:`));
    for (const entry of wrapped) {
      console.log(chalk.gray(`      • ${entry}`));
    }
  } else {
    console.log(chalk.gray(`    MCP proxied: none`));
  }
}

export function registerStatusCommand(program: Command): void {
  program
    .command('status')
    .description('Show current Node9 mode, policy source, and persistent decisions')
    .action(() => {
      const creds = getCredentials();
      const daemonRunning = isDaemonRunning();

      // Grab the fully resolved waterfall config!
      const mergedConfig = getConfig();
      const settings = mergedConfig.settings;

      console.log('');

      // ── Policy authority ────────────────────────────────────────────────────
      if (creds && settings.approvers.cloud) {
        console.log(chalk.green('  ● Agent mode') + chalk.gray(' — cloud team policy enforced'));
      } else if (creds && !settings.approvers.cloud) {
        console.log(
          chalk.blue('  ● Privacy mode 🛡️') + chalk.gray(' — all decisions stay on this machine')
        );
      } else {
        console.log(
          chalk.yellow('  ○ Privacy mode 🛡️') + chalk.gray(' — no API key (Local rules only)')
        );
      }

      // ── Daemon & Architecture ────────────────────────────────────────────────
      console.log('');
      if (daemonRunning) {
        console.log(
          chalk.green('  ● Daemon running') + chalk.gray(` → http://127.0.0.1:${DAEMON_PORT}/`)
        );
      } else {
        console.log(chalk.gray('  ○ Daemon stopped'));
      }

      if (settings.enableUndo) {
        console.log(
          chalk.magenta('  ● Undo Engine') +
            chalk.gray(`    → Auto-snapshotting Git repos on AI change`)
        );
      }

      // ── Configuration State ──────────────────────────────────────────────────
      console.log('');
      const modeLabel =
        settings.mode === 'audit'
          ? chalk.blue('audit')
          : settings.mode === 'strict'
            ? chalk.red('strict')
            : chalk.white('standard');
      console.log(`  Mode:    ${modeLabel}`);

      const projectConfig = path.join(process.cwd(), 'node9.config.json');
      const globalConfig = path.join(os.homedir(), '.node9', 'config.json');
      console.log(
        `  Local:   ${fs.existsSync(projectConfig) ? chalk.green('Active (node9.config.json)') : chalk.gray('Not present')}`
      );
      console.log(
        `  Global:  ${fs.existsSync(globalConfig) ? chalk.green('Active (~/.node9/config.json)') : chalk.gray('Not present')}`
      );

      if (mergedConfig.policy.sandboxPaths.length > 0) {
        console.log(
          `  Sandbox: ${chalk.green(`${mergedConfig.policy.sandboxPaths.length} safe zones active`)}`
        );
      }

      // ── Agent wiring ─────────────────────────────────────────────────────────
      const homeDir = os.homedir();

      const claudeSettings = readJson<ClaudeSettings>(
        path.join(homeDir, '.claude', 'settings.json')
      );
      const claudeConfig = readJson<ClaudeConfig>(path.join(homeDir, '.claude.json'));
      const geminiSettings = readJson<GeminiSettings>(
        path.join(homeDir, '.gemini', 'settings.json')
      );
      const cursorConfig = readJson<CursorMcpConfig>(path.join(homeDir, '.cursor', 'mcp.json'));

      const agentFound = claudeSettings || claudeConfig || geminiSettings || cursorConfig;

      if (agentFound) {
        console.log('');
        console.log(chalk.bold('  Agent Wiring:'));
        console.log('');

        if (claudeSettings || claudeConfig) {
          const preHook =
            claudeSettings?.hooks?.PreToolUse?.some((m) =>
              m.hooks.some((h) => isNode9Hook(h.command))
            ) ?? false;
          const postHook =
            claudeSettings?.hooks?.PostToolUse?.some((m) =>
              m.hooks.some((h) => isNode9Hook(h.command))
            ) ?? false;
          printAgentSection(
            'Claude Code',
            [
              { name: 'PreToolUse  (node9 check)', present: preHook },
              { name: 'PostToolUse (node9 log)', present: postHook },
            ],
            wrappedMcpServers(claudeConfig?.mcpServers)
          );
          console.log('');
        }

        if (geminiSettings) {
          const beforeHook =
            geminiSettings.hooks?.BeforeTool?.some((m) =>
              m.hooks.some((h) => isNode9Hook(h.command))
            ) ?? false;
          const afterHook =
            geminiSettings.hooks?.AfterTool?.some((m) =>
              m.hooks.some((h) => isNode9Hook(h.command))
            ) ?? false;
          printAgentSection(
            'Gemini CLI',
            [
              { name: 'BeforeTool  (node9 check)', present: beforeHook },
              { name: 'AfterTool   (node9 log)', present: afterHook },
            ],
            wrappedMcpServers(geminiSettings.mcpServers)
          );
          console.log('');
        }

        if (cursorConfig) {
          printAgentSection('Cursor', [], wrappedMcpServers(cursorConfig.mcpServers));
          console.log('');
        }
      }

      // ── Pause state ──────────────────────────────────────────────────────────
      const pauseState = checkPause();
      if (pauseState.paused) {
        const expiresAt = pauseState.expiresAt
          ? new Date(pauseState.expiresAt).toLocaleTimeString()
          : 'indefinitely';
        console.log('');
        console.log(
          chalk.yellow(`  ⏸  PAUSED until ${expiresAt}`) + chalk.gray(' — all tool calls allowed')
        );
      }

      console.log('');
    });
}
