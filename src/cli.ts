#!/usr/bin/env node
import { Command } from 'commander';
import {
  authorizeHeadless,
  isDaemonRunning,
  getConfig,
  explainPolicy,
  pauseNode9,
  resumeNode9,
  checkPause,
} from './core';
import {
  setupClaude,
  setupGemini,
  setupCursor,
  setupHud,
  teardownClaude,
  teardownGemini,
  teardownCursor,
  teardownHud,
} from './setup';
import { stopDaemon } from './daemon/index';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { confirm } from '@inquirer/prompts';
import { parseDuration } from './utils/duration';
import { runProxy } from './proxy';
import { autoStartDaemonAndWait } from './cli/daemon-starter';
import { registerCheckCommand } from './cli/commands/check';
import { registerLogCommand } from './cli/commands/log';
import { registerShieldCommand, registerConfigShowCommand } from './cli/commands/shield';
import { registerDoctorCommand } from './cli/commands/doctor';
import { registerAuditCommand } from './cli/commands/audit';
import { registerReportCommand } from './cli/commands/report';
import { registerDaemonCommand } from './cli/commands/daemon-cmd';
import { registerStatusCommand } from './cli/commands/status';
import { registerInitCommand } from './cli/commands/init';
import { registerUndoCommand } from './cli/commands/undo';
import { registerWatchCommand } from './cli/commands/watch';
import { registerMcpGatewayCommand } from './cli/commands/mcp-gateway';
import { registerMcpServerCommand } from './cli/commands/mcp-server';
import { registerTrustCommand } from './cli/commands/trust';
import { registerMcpPinCommand } from './cli/commands/mcp-pin';

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
  .addHelpText('after', '\n  Supported targets:  claude  gemini  cursor  hud')
  .argument('<target>', 'The agent to protect: claude | gemini | cursor | hud')
  .action(async (target: string) => {
    if (target === 'gemini') return await setupGemini();
    if (target === 'claude') return await setupClaude();
    if (target === 'cursor') return await setupCursor();
    if (target === 'hud') return setupHud();
    console.error(chalk.red(`Unknown target: "${target}". Supported: claude, gemini, cursor, hud`));
    process.exit(1);
  });

// 2b. SETUP (alias for addto)
program
  .command('setup')
  .description('Alias for "addto" — integrate Node9 with an AI agent')
  .addHelpText('after', '\n  Supported targets:  claude  gemini  cursor  hud')
  .argument('[target]', 'The agent to protect: claude | gemini | cursor | hud')
  .action(async (target?: string) => {
    if (!target) {
      console.log(chalk.cyan('\n🛡️  Node9 Setup — integrate with your AI agent\n'));
      console.log('  Usage:  ' + chalk.white('node9 setup <target>') + '\n');
      console.log('  Targets:');
      console.log('    ' + chalk.green('claude') + '   — Claude Code (hook mode)');
      console.log('    ' + chalk.green('gemini') + '   — Gemini CLI (hook mode)');
      console.log('    ' + chalk.green('cursor') + '   — Cursor (hook mode)');
      process.stdout.write(
        '    ' + chalk.green('hud') + '     — Claude Code security statusline\n'
      );
      console.log('');
      return;
    }
    const t = target.toLowerCase();
    if (t === 'gemini') return await setupGemini();
    if (t === 'claude') return await setupClaude();
    if (t === 'cursor') return await setupCursor();
    if (t === 'hud') return setupHud();
    console.error(chalk.red(`Unknown target: "${target}". Supported: claude, gemini, cursor, hud`));
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
    else if (target === 'hud') fn = teardownHud;
    else {
      console.error(
        chalk.red(`Unknown target: "${target}". Supported: claude, gemini, cursor, hud`)
      );
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
registerDoctorCommand(program, version);

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

// 3. INIT
registerInitCommand(program);

// 4. AUDIT
registerAuditCommand(program);
registerReportCommand(program);

// 5. STATUS
registerStatusCommand(program);

// 5. DAEMON
registerDaemonCommand(program);

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

// node9 watch
registerWatchCommand(program);

// node9 mcp-gateway + mcp pin
registerMcpGatewayCommand(program);
registerMcpServerCommand(program);
registerMcpPinCommand(program);

// 7. CHECK (PreToolUse hook) + LOG (PostToolUse hook)
registerCheckCommand(program);
registerLogCommand(program);

// HUD — statusLine subprocess for Claude Code
program
  .command('hud')
  .description('Render node9 security statusline (spawned by Claude Code statusLine)')
  .addHelpText(
    'after',
    `
Outputs up to 3 lines to stdout, then exits:

  Line 1 — Security state (always shown):
    🛡 node9 | <mode> [shields] | ✅ allowed  🛑 blocked  🚨 dlp  ~$cost
    Shows "offline" if the node9 daemon is not running.

  Line 2 — Claude context & rate limits (shown when available):
    <model>  │ ctx ██████░░░░ 61%  │ 5h ████░░░░░░ 40% (2h 10m left)
    Only appears when Claude Code passes context_window / rate_limits data via stdin.

  Line 3 — Environment counts (shown when non-zero):
    2 CLAUDE.md | 5 rules | 4 MCPs | 3 hooks
    Counts CLAUDE.md files, rules/, MCP servers, and hook entries across user + project scope.
    Disable with: { "settings": { "hud": { "showEnvironmentCounts": false } } } in node9.config.json

Claude Code spawns this command every ~300ms and writes a JSON payload to stdin.
Run "node9 addto claude" to register it as the statusLine.`
  )
  .argument('[subcommand]', 'Optional: "debug on" / "debug off" to toggle stdin logging')
  .argument('[state]', 'on|off — used with "debug" subcommand')
  .action(async (subcommand?: string, state?: string) => {
    if (subcommand === 'debug') {
      const flagFile = path.join(os.homedir(), '.node9', 'hud-debug');
      if (state === 'on') {
        fs.mkdirSync(path.dirname(flagFile), { recursive: true });
        fs.writeFileSync(flagFile, '');
        console.log('HUD debug logging enabled → ~/.node9/hud-debug.log');
        console.log('Tail it with: tail -f ~/.node9/hud-debug.log');
      } else if (state === 'off') {
        if (fs.existsSync(flagFile)) fs.unlinkSync(flagFile);
        console.log('HUD debug logging disabled.');
      } else {
        console.error('Usage: node9 hud debug on|off');
        process.exit(1);
      }
      return;
    }
    const { main } = await import('./cli/hud.js');
    await main();
  });

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

// UNDO
registerUndoCommand(program);

// Shield management + config show
registerShieldCommand(program);
registerConfigShowCommand(program);

// Trusted-host allowlist
registerTrustCommand(program);

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
