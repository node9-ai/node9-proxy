#!/usr/bin/env node
import { Command } from 'commander';
import {
  authorizeHeadless,
  DEFAULT_CONFIG,
  isDaemonRunning,
  getCredentials,
  checkPause,
  pauseNode9,
  resumeNode9,
  getConfig,
  explainPolicy,
} from './core';
import {
  setupClaude,
  setupGemini,
  setupCursor,
  teardownClaude,
  teardownGemini,
  teardownCursor,
} from './setup';
import { startDaemon, stopDaemon, daemonStatus, DAEMON_PORT, DAEMON_HOST } from './daemon/index';
import { spawn, execSync, spawnSync } from 'child_process';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { applyUndo, getSnapshotHistory, computeUndoDiff } from './undo';
import { confirm } from '@inquirer/prompts';
import { parseDuration } from './utils/duration';
import { runProxy } from './proxy';
import { openBrowserLocal, autoStartDaemonAndWait } from './cli/daemon-starter';
import { registerCheckCommand } from './cli/commands/check';
import { registerLogCommand } from './cli/commands/log';
import { registerShieldCommand, registerConfigShowCommand } from './cli/commands/shield';

const { version } = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../package.json'), 'utf-8')
) as { version: string };

const program = new Command();
program.name('node9').description('The Sudo Command for AI Agents').version(version);

// 1. LOGIN
program
  .command('login')
  .argument('<apiKey>')
  .option('--local', 'Save key for audit/logging only — local config still controls all decisions')
  .option('--profile <name>', 'Save as a named profile (default: "default")')
  .action((apiKey, options: { local?: boolean; profile?: string }) => {
    const DEFAULT_API_URL = 'https://api.node9.ai/api/v1/intercept';
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (!fs.existsSync(path.dirname(credPath)))
      fs.mkdirSync(path.dirname(credPath), { recursive: true });

    const profileName = options.profile || 'default';
    let existingCreds: Record<string, unknown> = {};
    try {
      if (fs.existsSync(credPath)) {
        const raw = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;
        if (raw.apiKey) {
          existingCreds = {
            default: { apiKey: raw.apiKey, apiUrl: raw.apiUrl || DEFAULT_API_URL },
          };
        } else {
          existingCreds = raw;
        }
      }
    } catch {}

    existingCreds[profileName] = { apiKey, apiUrl: DEFAULT_API_URL };
    fs.writeFileSync(credPath, JSON.stringify(existingCreds, null, 2), { mode: 0o600 });

    if (profileName === 'default') {
      const configPath = path.join(os.homedir(), '.node9', 'config.json');
      let config: Record<string, unknown> = {};
      try {
        if (fs.existsSync(configPath))
          config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
      } catch {}
      if (!config.settings || typeof config.settings !== 'object') config.settings = {};
      const s = config.settings as Record<string, unknown>;
      const approvers = (s.approvers as Record<string, unknown>) || {
        native: true,
        browser: true,
        cloud: true,
        terminal: true,
      };
      // Only change cloud setting when --local is explicitly passed.
      // Without --local, preserve whatever the user had before so that
      // re-running `node9 login` to refresh an API key doesn't silently
      // re-enable cloud approvals for users who had turned them off.
      if (options.local) {
        approvers.cloud = false;
      }
      s.approvers = approvers;
      if (!fs.existsSync(path.dirname(configPath)))
        fs.mkdirSync(path.dirname(configPath), { recursive: true });
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
    }

    if (options.profile && profileName !== 'default') {
      console.log(chalk.green(`✅ Profile "${profileName}" saved`));
      console.log(chalk.gray(`   Switch to it per-session:  NODE9_PROFILE=${profileName} claude`));
    } else if (options.local) {
      console.log(chalk.green(`✅ Privacy mode 🛡️`));
      console.log(chalk.gray(`   All decisions stay on this machine.`));
    } else {
      console.log(chalk.green(`✅ Logged in — agent mode`));
      console.log(chalk.gray(`   Team policy enforced for all calls via Node9 cloud.`));
    }
  });

// 2. ADDTO
program
  .command('addto')
  .description('Integrate Node9 with an AI agent')
  .addHelpText('after', '\n  Supported targets:  claude  gemini  cursor')
  .argument('<target>', 'The agent to protect: claude | gemini | cursor')
  .action(async (target: string) => {
    if (target === 'gemini') return await setupGemini();
    if (target === 'claude') return await setupClaude();
    if (target === 'cursor') return await setupCursor();
    console.error(chalk.red(`Unknown target: "${target}". Supported: claude, gemini, cursor`));
    process.exit(1);
  });

// 2b. SETUP (alias for addto)
program
  .command('setup')
  .description('Alias for "addto" — integrate Node9 with an AI agent')
  .addHelpText('after', '\n  Supported targets:  claude  gemini  cursor')
  .argument('[target]', 'The agent to protect: claude | gemini | cursor')
  .action(async (target?: string) => {
    if (!target) {
      console.log(chalk.cyan('\n🛡️  Node9 Setup — integrate with your AI agent\n'));
      console.log('  Usage:  ' + chalk.white('node9 setup <target>') + '\n');
      console.log('  Targets:');
      console.log('    ' + chalk.green('claude') + '   — Claude Code (hook mode)');
      console.log('    ' + chalk.green('gemini') + '   — Gemini CLI (hook mode)');
      console.log('    ' + chalk.green('cursor') + '   — Cursor (hook mode)');
      console.log('');
      return;
    }
    const t = target.toLowerCase();
    if (t === 'gemini') return await setupGemini();
    if (t === 'claude') return await setupClaude();
    if (t === 'cursor') return await setupCursor();
    console.error(chalk.red(`Unknown target: "${target}". Supported: claude, gemini, cursor`));
    process.exit(1);
  });

// 2c. REMOVEFROM
program
  .command('removefrom')
  .description('Remove Node9 hooks from an AI agent configuration')
  .addHelpText('after', '\n  Supported targets:  claude  gemini  cursor')
  .argument('<target>', 'The agent to remove from: claude | gemini | cursor')
  .action((target: string) => {
    // Validate before logging so the target string is never interpolated
    // into output before it has been confirmed to be a known value.
    let fn: (() => void) | undefined;
    if (target === 'claude') fn = teardownClaude;
    else if (target === 'gemini') fn = teardownGemini;
    else if (target === 'cursor') fn = teardownCursor;
    else {
      console.error(chalk.red(`Unknown target: "${target}". Supported: claude, gemini, cursor`));
      process.exit(1);
    }
    console.log(chalk.cyan(`\n🛡️  Node9: removing hooks from ${target}...\n`));
    try {
      fn!();
    } catch (err) {
      console.error(chalk.red(`  ⚠️  Failed: ${err instanceof Error ? err.message : String(err)}`));
      process.exit(1);
    }
    console.log(chalk.gray('\n  Restart the agent for changes to take effect.'));
  });

// 2d. UNINSTALL
program
  .command('uninstall')
  .description('Remove all Node9 hooks and optionally delete config files')
  .option('--purge', 'Also delete ~/.node9/ directory (config, audit log, credentials)')
  .action(async (options: { purge?: boolean }) => {
    console.log(chalk.cyan('\n🛡️  Node9 Uninstall\n'));

    // 1. Stop the daemon
    console.log(chalk.bold('Stopping daemon...'));
    try {
      stopDaemon();
      console.log(chalk.green('  ✅ Daemon stopped'));
    } catch {
      console.log(chalk.blue('  ℹ️  Daemon was not running'));
    }

    // 2. Remove hooks from all agents (each wrapped independently so a partial
    //    failure does not silently skip the remaining agents)
    console.log(chalk.bold('\nRemoving hooks...'));
    let teardownFailed = false;
    for (const [label, fn] of [
      ['Claude', teardownClaude],
      ['Gemini', teardownGemini],
      ['Cursor', teardownCursor],
    ] as const) {
      try {
        fn();
      } catch (err) {
        teardownFailed = true;
        console.error(
          chalk.red(
            `  ⚠️  Failed to remove ${label} hooks: ${err instanceof Error ? err.message : String(err)}`
          )
        );
      }
    }

    // 3. Optionally purge ~/.node9/ — requires explicit confirmation because the
    //    directory may contain credentials and cannot be recovered after deletion.
    if (options.purge) {
      const node9Dir = path.join(os.homedir(), '.node9');
      if (fs.existsSync(node9Dir)) {
        const confirmed = await confirm({
          message: `Permanently delete ${node9Dir} (config, audit log, credentials)?`,
          default: false,
        });
        if (confirmed) {
          fs.rmSync(node9Dir, { recursive: true });
          // Verify deletion succeeded — force:true would swallow errors and
          // print a false success if a file was locked or permission-denied.
          if (fs.existsSync(node9Dir)) {
            console.error(
              chalk.red('\n  ⚠️  ~/.node9/ could not be fully deleted — remove it manually.')
            );
          } else {
            console.log(chalk.green('\n  ✅ Deleted ~/.node9/ (config, audit log, credentials)'));
          }
        } else {
          console.log(chalk.yellow('\n  Skipped — ~/.node9/ was not deleted.'));
        }
      } else {
        console.log(chalk.blue('\n  ℹ️  ~/.node9/ not found — nothing to delete'));
      }
    } else {
      console.log(
        chalk.gray('\n  ~/.node9/ kept — run with --purge to delete config and audit log')
      );
    }

    if (teardownFailed) {
      console.error(chalk.red('\n  ⚠️  Some hooks could not be removed — see errors above.'));
      process.exit(1);
    }
    console.log(chalk.green.bold('\n🛡️  Node9 removed. Run: npm uninstall -g @node9/proxy'));
    console.log(chalk.gray('   Restart any open AI agent sessions for changes to take effect.\n'));
  });

// 2e. DOCTOR
program
  .command('doctor')
  .description('Check that Node9 is installed and configured correctly')
  .action(() => {
    const homeDir = os.homedir();
    let failures = 0;

    function pass(msg: string) {
      console.log(chalk.green('  ✅ ') + msg);
    }
    function fail(msg: string, hint?: string) {
      console.log(chalk.red('  ❌ ') + msg);
      if (hint) console.log(chalk.gray('       ' + hint));
      failures++;
    }
    function warn(msg: string, hint?: string) {
      console.log(chalk.yellow('  ⚠️  ') + msg);
      if (hint) console.log(chalk.gray('       ' + hint));
    }
    function section(title: string) {
      console.log('\n' + chalk.bold(title));
    }

    console.log(chalk.cyan.bold(`\n🛡️  Node9 Doctor  v${version}\n`));

    // ── Binary ───────────────────────────────────────────────────────────────
    section('Binary');
    try {
      const which = execSync('which node9', { encoding: 'utf-8', timeout: 3000 }).trim();
      pass(`node9 found at ${which}`);
    } catch {
      warn('node9 not found in $PATH — hooks may not find it', 'Run: npm install -g @node9/proxy');
    }

    const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
    if (nodeMajor >= 18) {
      pass(`Node.js ${process.versions.node}`);
    } else {
      fail(
        `Node.js ${process.versions.node} (requires ≥18)`,
        'Upgrade Node.js: https://nodejs.org'
      );
    }

    try {
      const gitVersion = execSync('git --version', { encoding: 'utf-8', timeout: 3000 }).trim();
      pass(gitVersion);
    } catch {
      warn(
        'git not found — Undo Engine will be disabled',
        'Install git to enable snapshot-based undo'
      );
    }

    // ── Config ───────────────────────────────────────────────────────────────
    section('Configuration');
    const globalConfigPath = path.join(homeDir, '.node9', 'config.json');
    if (fs.existsSync(globalConfigPath)) {
      try {
        JSON.parse(fs.readFileSync(globalConfigPath, 'utf-8'));
        pass('~/.node9/config.json found and valid');
      } catch {
        fail('~/.node9/config.json is invalid JSON', 'Run: node9 init --force');
      }
    } else {
      warn('~/.node9/config.json not found (using defaults)', 'Run: node9 init');
    }

    const projectConfigPath = path.join(process.cwd(), 'node9.config.json');
    if (fs.existsSync(projectConfigPath)) {
      try {
        JSON.parse(fs.readFileSync(projectConfigPath, 'utf-8'));
        pass('node9.config.json found and valid (project)');
      } catch {
        fail('node9.config.json is invalid JSON', 'Fix the JSON or delete it and run: node9 init');
      }
    }

    const credsPath = path.join(homeDir, '.node9', 'credentials.json');
    if (fs.existsSync(credsPath)) {
      pass('Cloud credentials found (~/.node9/credentials.json)');
    } else {
      warn(
        'No cloud credentials — running in local-only mode',
        'Run: node9 login <apiKey>  (or skip for local-only)'
      );
    }

    // ── Hooks ────────────────────────────────────────────────────────────────
    section('Agent Hooks');

    // Claude
    const claudeSettingsPath = path.join(homeDir, '.claude', 'settings.json');
    if (fs.existsSync(claudeSettingsPath)) {
      try {
        const cs = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf-8')) as {
          hooks?: { PreToolUse?: Array<{ hooks: Array<{ command?: string }> }> };
        };
        const hasHook = cs.hooks?.PreToolUse?.some((m) =>
          m.hooks.some((h) => h.command?.includes('node9') || h.command?.includes('cli.js'))
        );
        if (hasHook) pass('Claude Code — PreToolUse hook active');
        else
          fail('Claude Code — hooks file found but node9 hook missing', 'Run: node9 setup claude');
      } catch {
        fail('Claude Code — ~/.claude/settings.json is invalid JSON');
      }
    } else {
      warn('Claude Code — not configured', 'Run: node9 setup claude');
    }

    // Gemini
    const geminiSettingsPath = path.join(homeDir, '.gemini', 'settings.json');
    if (fs.existsSync(geminiSettingsPath)) {
      try {
        const gs = JSON.parse(fs.readFileSync(geminiSettingsPath, 'utf-8')) as {
          hooks?: { BeforeTool?: Array<{ hooks: Array<{ command?: string }> }> };
        };
        const hasHook = gs.hooks?.BeforeTool?.some((m) =>
          m.hooks.some((h) => h.command?.includes('node9') || h.command?.includes('cli.js'))
        );
        if (hasHook) pass('Gemini CLI  — BeforeTool hook active');
        else
          fail('Gemini CLI  — hooks file found but node9 hook missing', 'Run: node9 setup gemini');
      } catch {
        fail('Gemini CLI  — ~/.gemini/settings.json is invalid JSON');
      }
    } else {
      warn('Gemini CLI  — not configured', 'Run: node9 setup gemini  (skip if not using Gemini)');
    }

    // Cursor
    const cursorHooksPath = path.join(homeDir, '.cursor', 'hooks.json');
    if (fs.existsSync(cursorHooksPath)) {
      try {
        const cur = JSON.parse(fs.readFileSync(cursorHooksPath, 'utf-8')) as {
          hooks?: { preToolUse?: Array<{ command?: string }> };
        };
        const hasHook = cur.hooks?.preToolUse?.some(
          (h) => h.command?.includes('node9') || h.command?.includes('cli.js')
        );
        if (hasHook) pass('Cursor      — preToolUse hook active');
        else
          fail('Cursor      — hooks file found but node9 hook missing', 'Run: node9 setup cursor');
      } catch {
        fail('Cursor      — ~/.cursor/hooks.json is invalid JSON');
      }
    } else {
      warn('Cursor      — not configured', 'Run: node9 setup cursor  (skip if not using Cursor)');
    }

    // ── Daemon ───────────────────────────────────────────────────────────────
    section('Daemon (optional)');
    if (isDaemonRunning()) {
      pass(`Browser dashboard running → http://${DAEMON_HOST}:${DAEMON_PORT}/`);
    } else {
      warn('Daemon not running — browser approvals unavailable', 'Run: node9 daemon --background');
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    console.log('');
    if (failures === 0) {
      console.log(chalk.green.bold('  All checks passed. Node9 is ready.\n'));
    } else {
      console.log(chalk.red.bold(`  ${failures} check(s) failed. See hints above.\n`));
      process.exit(1);
    }
  });

// 2d. EXPLAIN
program
  .command('explain')
  .description(
    'Show exactly how Node9 evaluates a tool call — waterfall + step-by-step policy trace'
  )
  .argument('<tool>', 'Tool name (e.g. bash, str_replace_based_edit_tool, execute_query)')
  .argument('[args]', 'Tool arguments as JSON, or a plain command string for shell tools')
  .action(async (tool: string, argsRaw?: string) => {
    let args: unknown = {};
    if (argsRaw) {
      const trimmed = argsRaw.trim();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try {
          args = JSON.parse(trimmed);
        } catch {
          console.error(chalk.red(`\n❌ Invalid JSON: ${trimmed}\n`));
          process.exit(1);
        }
      } else {
        // Plain string — treat as a shell command for convenience
        args = { command: trimmed };
      }
    }

    const result = await explainPolicy(tool, args);

    console.log('');
    console.log(chalk.cyan.bold('🛡️  Node9 Explain'));
    console.log('');
    console.log(`   ${chalk.bold('Tool:')}    ${chalk.white(result.tool)}`);
    if (argsRaw) {
      const preview = argsRaw.length > 80 ? argsRaw.slice(0, 77) + '…' : argsRaw;
      console.log(`   ${chalk.bold('Input:')}   ${chalk.gray(preview)}`);
    }

    // ── Waterfall ────────────────────────────────────────────────────────────
    console.log('');
    console.log(chalk.bold('Config Sources (Waterfall):'));
    for (const tier of result.waterfall) {
      const num = chalk.gray(`  ${tier.tier}.`);
      const label = tier.label.padEnd(16);
      let statusStr: string;
      if (tier.tier === 1) {
        statusStr = chalk.gray(tier.note ?? '');
      } else if (tier.status === 'active') {
        const loc = tier.path ? chalk.gray(tier.path) : '';
        const note = tier.note ? chalk.gray(`(${tier.note})`) : '';
        statusStr = chalk.green('✓ active') + (loc ? '  ' + loc : '') + (note ? '  ' + note : '');
      } else {
        statusStr = chalk.gray('○ ' + (tier.note ?? 'not found'));
      }
      console.log(`${num} ${chalk.white(label)} ${statusStr}`);
    }

    // ── Policy steps ─────────────────────────────────────────────────────────
    console.log('');
    console.log(chalk.bold('Policy Evaluation:'));
    for (const step of result.steps) {
      const isFinal = step.isFinal;
      let icon: string;
      if (step.outcome === 'allow') icon = chalk.green('  ✅');
      else if (step.outcome === 'review') icon = chalk.red('  🔴');
      else if (step.outcome === 'skip') icon = chalk.gray('  ─ ');
      else icon = chalk.gray('  ○ ');

      const name = step.name.padEnd(18);
      const nameStr = isFinal ? chalk.white.bold(name) : chalk.white(name);
      const detail = isFinal ? chalk.white(step.detail) : chalk.gray(step.detail);
      const arrow = isFinal ? chalk.yellow('  ← STOP') : '';
      console.log(`${icon} ${nameStr} ${detail}${arrow}`);
    }

    // ── Final verdict ─────────────────────────────────────────────────────────
    console.log('');
    if (result.decision === 'allow') {
      console.log(chalk.green.bold('  Decision: ✅ ALLOW') + chalk.gray('  — no approval needed'));
    } else {
      console.log(
        chalk.red.bold('  Decision: 🔴 REVIEW') + chalk.gray('  — human approval required')
      );
      if (result.blockedByLabel) {
        console.log(chalk.gray(`  Reason:   ${result.blockedByLabel}`));
      }
    }
    console.log('');
  });

// 3. INIT (Upgraded with Enterprise Schema)
program
  .command('init')
  .description('Create ~/.node9/config.json with default policy (safe to run multiple times)')
  .option('--force', 'Overwrite existing config')
  .option('-m, --mode <mode>', 'Set initial security mode (standard, strict, audit)', 'standard')
  .action((options: { force?: boolean; mode: string }) => {
    const configPath = path.join(os.homedir(), '.node9', 'config.json');

    if (fs.existsSync(configPath) && !options.force) {
      console.log(chalk.yellow(`ℹ️  Global config already exists: ${configPath}`));
      console.log(chalk.gray(`   Run with --force to overwrite.`));
      return;
    }

    // Validate mode from CLI flag
    const requestedMode = options.mode.toLowerCase();
    const safeMode = ['standard', 'strict', 'audit'].includes(requestedMode)
      ? requestedMode
      : DEFAULT_CONFIG.settings.mode;

    // Use the exact same object from core.ts, just override the mode from the CLI flag
    const configToSave = {
      ...DEFAULT_CONFIG,
      settings: {
        ...DEFAULT_CONFIG.settings,
        mode: safeMode,
      },
    };

    const dir = path.dirname(configPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    fs.writeFileSync(configPath, JSON.stringify(configToSave, null, 2));

    console.log(chalk.green(`✅ Global config created: ${configPath}`));
    console.log(chalk.cyan(`   Mode set to: ${safeMode}`));
    console.log(
      chalk.gray(`   Undo Engine is ENABLED by default. Use 'node9 undo' to revert AI changes.`)
    );
  });

// 4. AUDIT
function formatRelativeTime(timestamp: string): string {
  const diff = Date.now() - new Date(timestamp).getTime();
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return new Date(timestamp).toLocaleDateString();
}

program
  .command('audit')
  .description('View local execution audit log')
  .option('--tail <n>', 'Number of entries to show', '20')
  .option('--tool <pattern>', 'Filter by tool name (substring match)')
  .option('--deny', 'Show only denied actions')
  .option('--json', 'Output raw JSON')
  .action((options: { tail: string; tool?: string; deny?: boolean; json?: boolean }) => {
    const logPath = path.join(os.homedir(), '.node9', 'audit.log');
    if (!fs.existsSync(logPath)) {
      console.log(
        chalk.yellow('No audit logs found. Run node9 with an agent to generate entries.')
      );
      return;
    }

    const raw = fs.readFileSync(logPath, 'utf-8');
    const lines = raw.split('\n').filter((l) => l.trim() !== '');

    let entries = lines.flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });

    // Normalize decision field — some older entries use "allowed"/"denied"
    entries = entries.map((e) => ({
      ...e,
      decision: String(e.decision).startsWith('allow') ? 'allow' : 'deny',
    }));

    if (options.tool) entries = entries.filter((e) => String(e.tool).includes(options.tool!));
    if (options.deny) entries = entries.filter((e) => e.decision === 'deny');

    const limit = Math.max(1, parseInt(options.tail, 10) || 20);
    entries = entries.slice(-limit);

    if (options.json) {
      console.log(JSON.stringify(entries, null, 2));
      return;
    }

    if (entries.length === 0) {
      console.log(chalk.yellow('No matching audit entries.'));
      return;
    }

    console.log(
      `\n  ${chalk.bold('Node9 Audit Log')}  ${chalk.dim(`(${entries.length} entries)`)}`
    );
    console.log(chalk.dim('  ' + '─'.repeat(65)));
    console.log(
      `  ${'Time'.padEnd(12)} ${'Tool'.padEnd(18)} ${'Result'.padEnd(10)} ${'By'.padEnd(15)} Agent`
    );
    console.log(chalk.dim('  ' + '─'.repeat(65)));

    for (const e of entries) {
      const time = formatRelativeTime(String(e.ts)).padEnd(12);
      const tool = String(e.tool).slice(0, 17).padEnd(18);
      const result =
        e.decision === 'allow' ? chalk.green('ALLOW'.padEnd(10)) : chalk.red('DENY'.padEnd(10));
      const checker = String(e.checkedBy || 'unknown')
        .slice(0, 14)
        .padEnd(15);
      const agent = String(e.agent || 'unknown');
      console.log(`  ${time} ${tool} ${result} ${checker} ${agent}`);
    }

    const allowed = entries.filter((e) => e.decision === 'allow').length;
    const denied = entries.filter((e) => e.decision === 'deny').length;
    console.log(chalk.dim('  ' + '─'.repeat(65)));
    console.log(
      `  ${entries.length} entries  |  ${chalk.green(allowed + ' allowed')}  |  ${chalk.red(denied + ' denied')}\n`
    );
  });

// 5. STATUS (Upgraded to show Waterfall & Undo status)
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

// 5. DAEMON
program
  .command('daemon')
  .description('Run the local approval server')
  .argument('[action]', 'start | stop | status (default: start)')
  .option('-b, --background', 'Start the daemon in the background (detached)')
  .option('-o, --openui', 'Start in background and open browser')
  .option(
    '-w, --watch',
    'Start daemon + open browser, stay alive permanently (Flight Recorder mode)'
  )
  .action(
    async (
      action: string | undefined,
      options: { background?: boolean; openui?: boolean; watch?: boolean }
    ) => {
      const cmd = (action ?? 'start').toLowerCase();
      if (cmd === 'stop') return stopDaemon();
      if (cmd === 'status') return daemonStatus();
      if (cmd !== 'start' && action !== undefined) {
        console.error(chalk.red(`Unknown daemon action: "${action}". Use: start | stop | status`));
        process.exit(1);
      }

      if (options.watch) {
        process.env.NODE9_WATCH_MODE = '1';
        // Open browser shortly after daemon binds to its port
        setTimeout(() => {
          openBrowserLocal();
          console.log(chalk.cyan(`🛰️  Flight Recorder: http://${DAEMON_HOST}:${DAEMON_PORT}/`));
        }, 600);
        startDaemon(); // foreground — keeps process alive
        return;
      }

      if (options.openui) {
        if (isDaemonRunning()) {
          openBrowserLocal();
          console.log(chalk.green(`🌐  Opened browser: http://${DAEMON_HOST}:${DAEMON_PORT}/`));
          process.exit(0);
        }
        const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
          detached: true,
          stdio: 'ignore',
        });
        child.unref();
        for (let i = 0; i < 12; i++) {
          await new Promise((r) => setTimeout(r, 250));
          if (isDaemonRunning()) break;
        }
        openBrowserLocal();
        console.log(chalk.green(`\n🛡️  Node9 daemon started + browser opened`));
        process.exit(0);
      }

      if (options.background) {
        const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
          detached: true,
          stdio: 'ignore',
        });
        child.unref();
        console.log(chalk.green(`\n🛡️  Node9 daemon started in background  (PID ${child.pid})`));
        process.exit(0);
      }

      startDaemon();
    }
  );

// 6. TAIL
program
  .command('tail')
  .description('Stream live agent activity to the terminal')
  .option('--history', 'Replay recent history then continue live', false)
  .option('--clear', 'Clear the history buffer and exit (does not stream)', false)
  .action(async (options: { history?: boolean; clear?: boolean }) => {
    const { startTail } = await import('./tui/tail.js');
    try {
      await startTail(options);
    } catch (err) {
      console.error(chalk.red(`❌ ${err instanceof Error ? err.message : String(err)}`));
      process.exit(1);
    }
  });

// node9 watch <command...> — runs a command under Node9 supervision with watch-mode daemon
program
  .command('watch')
  .description('Run a command under Node9 watch mode (daemon stays alive for the session)')
  .argument('<command>', 'Command to run')
  .argument('[args...]', 'Arguments for the command')
  .action(async (cmd: string, args: string[]) => {
    // Ensure daemon is running in watch mode (never idle-exits)
    let port = DAEMON_PORT;
    try {
      const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/settings`, {
        signal: AbortSignal.timeout(500),
      });
      if (res.ok) {
        const data = (await res.json()) as { port?: number };
        if (typeof data.port === 'number') port = data.port;
      } else {
        throw new Error('not running');
      }
    } catch {
      // Not running — start it with watch mode enabled
      console.error(chalk.dim('🛡️  Starting Node9 daemon (watch mode)...'));
      const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
        detached: true,
        stdio: 'ignore',
        env: { ...process.env, NODE9_AUTO_STARTED: '1', NODE9_WATCH_MODE: '1' },
      });
      child.unref();
      // Wait up to 5s
      let ready = false;
      for (let i = 0; i < 20; i++) {
        await new Promise((r) => setTimeout(r, 250));
        try {
          const r = await fetch(`http://127.0.0.1:${DAEMON_PORT}/settings`, {
            signal: AbortSignal.timeout(500),
          });
          if (r.ok) {
            ready = true;
            break;
          }
        } catch {}
      }
      if (!ready) {
        console.error(chalk.red('❌ Daemon failed to start. Try: node9 daemon start'));
        process.exit(1);
      }
    }

    console.error(
      chalk.cyan.bold('🛡️  Node9 watch') +
        chalk.dim(` → localhost:${port}`) +
        chalk.dim(
          '\n   Tip: run `node9 tail` in another terminal to review and approve AI actions.\n'
        )
    );

    const result = spawnSync(cmd, args, {
      stdio: 'inherit',
      env: { ...process.env, NODE9_WATCH_MODE: '1' },
    });
    if (result.error) {
      console.error(chalk.red(`❌ Failed to run command: ${result.error.message}`));
      process.exit(1);
    }
    process.exit(result.status ?? 0);
  });

// 7. CHECK (PreToolUse hook) + LOG (PostToolUse hook)
registerCheckCommand(program);
registerLogCommand(program);

// 8. PAUSE
program
  .command('pause')
  .description('Temporarily disable Node9 protection for a set duration')
  .option('-d, --duration <duration>', 'How long to pause (e.g. 15m, 1h, 30s)', '15m')
  .action((options: { duration: string }) => {
    const ms = parseDuration(options.duration);
    if (ms === null) {
      console.error(
        chalk.red(`\n❌  Invalid duration: "${options.duration}". Use format like 15m, 1h, 30s.\n`)
      );
      process.exit(1);
    }
    pauseNode9(ms, options.duration);
    const expiresAt = new Date(Date.now() + ms).toLocaleTimeString();
    console.log(chalk.yellow(`\n⏸  Node9 paused until ${expiresAt}`));
    console.log(chalk.gray(`   All tool calls will be allowed without review.`));
    console.log(chalk.gray(`   Run "node9 resume" to re-enable early.\n`));
  });

// 9. RESUME
program
  .command('resume')
  .description('Re-enable Node9 protection immediately')
  .action(() => {
    const { paused } = checkPause();
    if (!paused) {
      console.log(chalk.gray('\nNode9 is already active — nothing to resume.\n'));
      return;
    }
    resumeNode9();
    console.log(chalk.green('\n▶  Node9 resumed — protection is active.\n'));
  });

// 10. SMART RUNNER
const HOOK_BASED_AGENTS: Record<string, string> = {
  claude: 'claude',
  gemini: 'gemini',
  cursor: 'cursor',
};

program
  .argument('[command...]', 'The agent command to run (e.g., gemini)')
  .action(async (commandArgs) => {
    if (commandArgs && commandArgs.length > 0) {
      const firstArg = commandArgs[0].toLowerCase();

      if (HOOK_BASED_AGENTS[firstArg] !== undefined) {
        const target = HOOK_BASED_AGENTS[firstArg];
        console.error(
          chalk.yellow(`\n⚠️  Node9 proxy mode does not support "${target}" directly.`)
        );
        console.error(chalk.white(`\n   "${target}" uses its own hook system. Use:`));
        console.error(
          chalk.green(`     node9 addto ${target}   `) + chalk.gray('# one-time setup')
        );
        console.error(chalk.green(`     ${target}              `) + chalk.gray('# run normally'));
        process.exit(1);
      }

      // Allow "node9 shell <cmd>" as an alias for "node9 <cmd>"
      const runArgs = firstArg === 'shell' ? commandArgs.slice(1) : commandArgs;
      if (runArgs.length === 0) {
        program.help();
        return;
      }

      const fullCommand = runArgs.join(' ');
      let result = await authorizeHeadless(
        'shell',
        { command: fullCommand },
        {
          agent: 'Terminal',
        }
      );

      if (
        result.noApprovalMechanism &&
        !isDaemonRunning() &&
        !process.env.NODE9_NO_AUTO_DAEMON &&
        getConfig().settings.autoStartDaemon
      ) {
        console.error(chalk.cyan('\n🛡️  Node9: Starting approval daemon automatically...'));
        const daemonReady = await autoStartDaemonAndWait();
        if (daemonReady) result = await authorizeHeadless('shell', { command: fullCommand });
      }

      // Fallback: inline Y/N prompt when no approval channel is available
      if (result.noApprovalMechanism && process.stdout.isTTY) {
        const approved = await confirm({
          message: `🛡️  Node9: Allow "${fullCommand}"?`,
          default: false,
        });
        result = { approved, reason: approved ? undefined : 'Denied by user at terminal.' };
      }

      if (!result.approved) {
        console.error(
          chalk.red(`\n❌ Node9 Blocked: ${result.reason || 'Dangerous command detected.'}`)
        );
        process.exit(1);
      }

      console.error(chalk.green('\n✅ Approved — running command...\n'));
      await runProxy(fullCommand);
    } else {
      program.help();
    }
  });

program
  .command('undo')
  .description(
    'Revert files to a pre-AI snapshot. Shows a diff and asks for confirmation before reverting. Use --steps N to go back N actions, --all to include snapshots from other directories.'
  )
  .option('--steps <n>', 'Number of snapshots to go back (default: 1)', '1')
  .option('--all', 'Show snapshots from all directories, not just the current one')
  .action(async (options: { steps: string; all?: boolean }) => {
    const steps = Math.max(1, parseInt(options.steps, 10) || 1);
    const allHistory = getSnapshotHistory();
    const history = options.all ? allHistory : allHistory.filter((s) => s.cwd === process.cwd());

    if (history.length === 0) {
      if (!options.all && allHistory.length > 0) {
        console.log(
          chalk.yellow(
            `\nℹ️  No snapshots found for the current directory (${process.cwd()}).\n` +
              `    Run ${chalk.cyan('node9 undo --all')} to see snapshots from all projects.\n`
          )
        );
      } else {
        console.log(chalk.yellow('\nℹ️  No undo snapshots found.\n'));
      }
      return;
    }

    // Pick the snapshot N steps back (newest is last in array)
    const idx = history.length - steps;
    if (idx < 0) {
      console.log(
        chalk.yellow(
          `\nℹ️  Only ${history.length} snapshot(s) available, cannot go back ${steps}.\n`
        )
      );
      return;
    }
    const snapshot = history[idx];

    const age = Math.round((Date.now() - snapshot.timestamp) / 1000);
    const ageStr =
      age < 60
        ? `${age}s ago`
        : age < 3600
          ? `${Math.round(age / 60)}m ago`
          : `${Math.round(age / 3600)}h ago`;

    console.log(chalk.magenta.bold(`\n⏪  Node9 Undo${steps > 1 ? ` (${steps} steps back)` : ''}`));
    console.log(
      chalk.white(
        `    Tool:  ${chalk.cyan(snapshot.tool)}${snapshot.argsSummary ? chalk.gray(' → ' + snapshot.argsSummary) : ''}`
      )
    );
    console.log(chalk.white(`    When:  ${chalk.gray(ageStr)}`));
    console.log(chalk.white(`    Dir:   ${chalk.gray(snapshot.cwd)}`));
    if (steps > 1)
      console.log(
        chalk.yellow(`    Note:  This will also undo the ${steps - 1} action(s) after it.`)
      );
    console.log('');

    // Show diff
    const diff = computeUndoDiff(snapshot.hash, snapshot.cwd);
    if (diff) {
      const lines = diff.split('\n');
      for (const line of lines) {
        if (line.startsWith('+++') || line.startsWith('---')) {
          console.log(chalk.bold(line));
        } else if (line.startsWith('+')) {
          console.log(chalk.green(line));
        } else if (line.startsWith('-')) {
          console.log(chalk.red(line));
        } else if (line.startsWith('@@')) {
          console.log(chalk.cyan(line));
        } else {
          console.log(chalk.gray(line));
        }
      }
      console.log('');
    } else {
      console.log(
        chalk.gray('    (no diff available — working tree may already match snapshot)\n')
      );
    }

    const proceed = await confirm({
      message: `Revert to this snapshot?`,
      default: false,
    });

    if (proceed) {
      if (applyUndo(snapshot.hash, snapshot.cwd)) {
        console.log(chalk.green('\n✅ Reverted successfully.\n'));
      } else {
        console.error(chalk.red('\n❌ Undo failed. Ensure you are in a Git repository.\n'));
      }
    } else {
      console.log(chalk.gray('\nCancelled.\n'));
    }
  });

// Shield management + config show
registerShieldCommand(program);
registerConfigShowCommand(program);

// Daemon registers its own keep-alive unhandledRejection handler in startDaemon().
// Skip registration here entirely for daemon mode to avoid any ordering dependency
// between this handler and the daemon's handler.
// Note: process.argv[2] is evaluated at module load time — this is intentional,
// cli.ts is always the process entry point, never imported as a library.
if (process.argv[2] !== 'daemon') {
  process.on('unhandledRejection', (reason) => {
    const isCheckHook = process.argv[2] === 'check';
    if (isCheckHook) {
      if (process.env.NODE9_DEBUG === '1' || getConfig().settings.enableHookLogDebug) {
        const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
        const msg = reason instanceof Error ? reason.message : String(reason);
        fs.appendFileSync(logPath, `[${new Date().toISOString()}] UNHANDLED: ${msg}\n`);
      }
      process.exit(0);
    } else {
      console.error('[Node9] Unhandled error:', reason);
      process.exit(1);
    }
  });
}

// If the first argument is not a known node9 subcommand and doesn't start with
// '-', we are in proxy mode (e.g. `node9 npx -y @pkg`). Inject '--' before the
// command so Commander stops parsing options and passes everything — including
// flags like -y, --config, --nexus-url — through to the action handler intact.
// Without this, Commander errors on unknown flags before the handler ever runs.
//
// Derived from registered commands at runtime so it stays in sync automatically
// when new subcommands are added — no hand-maintained allowlist to forget to update.
// Note: c.name() returns the primary name; aliases (c.aliases()) are not included.
// No subcommands currently use aliases, so this is safe. If aliases are added later,
// extend this set with: program.commands.flatMap(c => [c.name(), ...c.aliases()])
const knownSubcommands = new Set(program.commands.map((c) => c.name()));
const firstArg = process.argv[2];
if (firstArg && firstArg !== '--' && !firstArg.startsWith('-') && !knownSubcommands.has(firstArg)) {
  process.argv.splice(2, 0, '--');
}

program.parse();
