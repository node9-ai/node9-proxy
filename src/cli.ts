#!/usr/bin/env node
import { Command } from 'commander';
import {
  authorizeAction,
  authorizeHeadless,
  redactSecrets,
  DANGEROUS_WORDS,
  isDaemonRunning,
  getGlobalSettings,
  getCredentials,
  listCredentialProfiles,
} from './core';
import { setupClaude, setupGemini, setupCursor } from './setup';
import { startDaemon, stopDaemon, daemonStatus, DAEMON_PORT, DAEMON_HOST } from './daemon/index';
import { spawn, execSync } from 'child_process';
import { parseCommandString } from 'execa';
import { execa } from 'execa';
import chalk from 'chalk';
import readline from 'readline';
import fs from 'fs';
import path from 'path';
import os from 'os';

const { version } = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../package.json'), 'utf-8')
) as { version: string };

function sanitize(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x1F\x7F]/g, '');
}

function openBrowserLocal() {
  const url = `http://${DAEMON_HOST}:${DAEMON_PORT}/`;
  try {
    const opts = { stdio: 'ignore' as const };
    if (process.platform === 'darwin') execSync(`open "${url}"`, opts);
    else if (process.platform === 'win32') execSync(`cmd /c start "" "${url}"`, opts);
    else execSync(`xdg-open "${url}"`, opts);
  } catch {}
}

/** Spawn the daemon detached and poll until it's ready (up to 3 s). */
async function autoStartDaemonAndWait(): Promise<boolean> {
  try {
    const child = spawn('node9', ['daemon'], {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, NODE9_AUTO_STARTED: '1' },
    });
    child.unref();
    for (let i = 0; i < 12; i++) {
      await new Promise((r) => setTimeout(r, 250));
      if (isDaemonRunning()) return true;
    }
  } catch {
    /* ignore */
  }
  return false;
}

const program = new Command();

program.name('node9').description('The Sudo Command for AI Agents').version(version);

// Helper for the Proxy logic
async function runProxy(targetCommand: string) {
  const commandParts = parseCommandString(targetCommand);
  const cmd = commandParts[0];
  const args = commandParts.slice(1);

  // NEW: Try to resolve the full path of the command
  let executable = cmd;
  try {
    const { stdout } = await execa('which', [cmd]);
    if (stdout) executable = stdout.trim();
  } catch {
    // Fallback to original cmd if which fails
  }

  console.log(chalk.green(`🚀 Node9 Proxy Active: Monitoring [${targetCommand}]`));

  const child = spawn(executable, args, {
    stdio: ['pipe', 'pipe', 'inherit'],
    shell: true,
    env: { ...process.env, FORCE_COLOR: '1', TERM: process.env.TERM || 'xterm-256color' },
  });

  // Handle stdin: Forward everything to child immediately
  process.stdin.pipe(child.stdin);

  const childOut = readline.createInterface({ input: child.stdout, terminal: false });
  childOut.on('line', async (line) => {
    try {
      const message = JSON.parse(line);
      if (
        message.method === 'call_tool' ||
        message.method === 'tools/call' ||
        message.method === 'use_tool'
      ) {
        const name = message.params?.name || message.params?.tool_name || 'unknown';
        const toolArgs = message.params?.arguments || message.params?.tool_input || {};
        const approved = await authorizeAction(sanitize(name), toolArgs);
        if (!approved) {
          const errorResponse = {
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32000, message: 'Node9: Action denied.' },
          };
          child.stdin.write(JSON.stringify(errorResponse) + '\n');
          return;
        }
      }
      process.stdout.write(line + '\n');
    } catch {
      process.stdout.write(line + '\n');
    }
  });
  child.on('exit', (code) => process.exit(code || 0));
}

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

    // Load existing credentials and migrate flat format → multi-profile if needed
    let existingCreds: Record<string, unknown> = {};
    try {
      if (fs.existsSync(credPath)) {
        const raw = JSON.parse(fs.readFileSync(credPath, 'utf-8')) as Record<string, unknown>;
        if (raw.apiKey) {
          // Migrate legacy flat format to multi-profile
          existingCreds = {
            default: { apiKey: raw.apiKey, apiUrl: raw.apiUrl || DEFAULT_API_URL },
          };
        } else {
          existingCreds = raw;
        }
      }
    } catch {
      /* ignore */
    }

    existingCreds[profileName] = { apiKey, apiUrl: DEFAULT_API_URL };
    fs.writeFileSync(credPath, JSON.stringify(existingCreds, null, 2), { mode: 0o600 });

    // Update agentMode in global config — only for the default profile
    if (profileName === 'default') {
      const configPath = path.join(os.homedir(), '.node9', 'config.json');
      let config: Record<string, unknown> = {};
      try {
        if (fs.existsSync(configPath))
          config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
      } catch {
        /* ignore */
      }
      if (!config.settings || typeof config.settings !== 'object') config.settings = {};
      (config.settings as Record<string, unknown>).agentMode = !options.local;
      if (!fs.existsSync(path.dirname(configPath)))
        fs.mkdirSync(path.dirname(configPath), { recursive: true });
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
    }

    if (options.profile && profileName !== 'default') {
      console.log(chalk.green(`✅ Profile "${profileName}" saved`));
      console.log(chalk.gray(`   Switch to it per-session:  NODE9_PROFILE=${profileName} claude`));
      console.log(
        chalk.gray(
          `   Or lock a project to it:   add "apiKey": "<your-api-key>" to node9.config.json`
        )
      );
    } else if (options.local) {
      console.log(chalk.green(`✅ Privacy mode 🛡️`));
      console.log(chalk.gray(`   All decisions stay on this machine.`));
      console.log(
        chalk.gray(`   No data is sent to the cloud. Local config is the only authority.`)
      );
      console.log(chalk.gray(`   To enable cloud enforcement: node9 login <apiKey>`));
    } else {
      console.log(chalk.green(`✅ Logged in — agent mode`));
      console.log(chalk.gray(`   Team policy enforced for all calls via Node9 cloud.`));
      console.log(chalk.gray(`   To keep local control only: node9 login <apiKey> --local`));
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

// 3. INIT
program
  .command('init')
  .description('Create ~/.node9/config.json with default policy (safe to run multiple times)')
  .option('--force', 'Overwrite existing config')
  .action((options) => {
    const configPath = path.join(os.homedir(), '.node9', 'config.json');

    if (fs.existsSync(configPath) && !options.force) {
      console.log(chalk.yellow(`ℹ️  Global config already exists: ${configPath}`));
      console.log(chalk.gray(`   Run with --force to overwrite.`));
      return;
    }
    const defaultConfig = {
      version: '1.0',
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
          shell: 'command',
          run_shell_command: 'command',
          'terminal.execute': 'command',
        },
        rules: [
          {
            action: 'rm',
            allowPaths: ['**/node_modules/**', 'dist/**', 'build/**', '.DS_Store'],
          },
        ],
      },
    };
    if (!fs.existsSync(path.dirname(configPath)))
      fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2));
    console.log(chalk.green(`✅ Global config created: ${configPath}`));
    console.log(chalk.gray(`   Edit this file to add custom tool inspection or security rules.`));
  });

// 4. STATUS
program
  .command('status')
  .description('Show current Node9 mode, policy source, and persistent decisions')
  .action(() => {
    const creds = getCredentials();
    const daemonRunning = isDaemonRunning();
    const settings = getGlobalSettings();

    console.log('');

    // ── Policy authority ────────────────────────────────────────────────────
    if (creds && settings.agentMode) {
      console.log(chalk.green('  ● Agent mode') + chalk.gray(' — cloud team policy enforced'));
      console.log(chalk.gray('    All calls → Node9 cloud → Policy Studio rules apply'));
      console.log(chalk.gray('    Switch to local control: node9 login <apiKey> --local'));
    } else if (creds && !settings.agentMode) {
      console.log(
        chalk.blue('  ● Privacy mode 🛡️') + chalk.gray(' — all decisions stay on this machine')
      );
      console.log(
        chalk.gray('    No data is sent to the cloud. Local config is the only authority.')
      );
      console.log(chalk.gray('    Enable cloud enforcement: node9 login <apiKey>'));
    } else {
      console.log(chalk.yellow('  ○ Privacy mode 🛡️') + chalk.gray(' — no API key'));
      console.log(chalk.gray('    All decisions stay on this machine.'));
      console.log(chalk.gray('    Connect to your team: node9 login <apiKey>'));
    }

    // ── Daemon ──────────────────────────────────────────────────────────────
    console.log('');
    if (daemonRunning) {
      console.log(
        chalk.green('  ● Daemon running') + chalk.gray(` → http://127.0.0.1:${DAEMON_PORT}/`)
      );
    } else {
      console.log(chalk.gray('  ○ Daemon stopped'));
      console.log(chalk.gray('    Start: node9 daemon --background'));
    }

    // ── Local config ────────────────────────────────────────────────────────
    console.log('');
    console.log(`  Mode:    ${chalk.white(settings.mode)}`);
    const projectConfig = path.join(process.cwd(), 'node9.config.json');
    const globalConfig = path.join(os.homedir(), '.node9', 'config.json');
    const configSource = fs.existsSync(projectConfig)
      ? projectConfig
      : fs.existsSync(globalConfig)
        ? globalConfig
        : chalk.gray('none (built-in defaults)');
    console.log(`  Config:  ${chalk.gray(configSource)}`);

    // ── Profiles ─────────────────────────────────────────────────────────────
    const profiles = listCredentialProfiles();
    if (profiles.length > 1) {
      const activeProfile = process.env.NODE9_PROFILE || 'default';
      console.log('');
      console.log(`  Active profile:  ${chalk.white(activeProfile)}`);
      console.log(
        `  All profiles:    ${profiles.map((p) => (p === activeProfile ? chalk.green(p) : chalk.gray(p))).join(chalk.gray(', '))}`
      );
      console.log(chalk.gray(`  Switch:  NODE9_PROFILE=<name> claude`));
    }

    // ── Persistent decisions ────────────────────────────────────────────────
    const decisionsFile = path.join(os.homedir(), '.node9', 'decisions.json');
    let decisions: Record<string, string> = {};
    try {
      if (fs.existsSync(decisionsFile))
        decisions = JSON.parse(fs.readFileSync(decisionsFile, 'utf-8')) as Record<string, string>;
    } catch {
      /* ignore */
    }

    const keys = Object.keys(decisions);
    console.log('');
    if (keys.length > 0) {
      console.log(`  Persistent decisions (${keys.length}):`);
      keys.forEach((tool) => {
        const d = decisions[tool];
        const badge = d === 'allow' ? chalk.green('allow') : chalk.red('deny');
        console.log(`    ${chalk.gray('·')} ${tool.padEnd(35)} ${badge}`);
      });
      console.log(chalk.gray('\n    Manage: node9 daemon --openui → Decisions tab'));
    } else {
      console.log(chalk.gray('  No persistent decisions set'));
    }

    // ── Audit log ────────────────────────────────────────────────────────────
    const auditLogPath = path.join(os.homedir(), '.node9', 'audit.log');
    try {
      if (fs.existsSync(auditLogPath)) {
        const lines = fs
          .readFileSync(auditLogPath, 'utf-8')
          .split('\n')
          .filter((l) => l.trim().length > 0);
        console.log('');
        console.log(
          `  📋 Local Audit Log: ` +
            chalk.white(`${lines.length} agent action${lines.length !== 1 ? 's' : ''} recorded`) +
            chalk.gray(`  (cat ~/.node9/audit.log to view)`)
        );
      }
    } catch {
      /* ignore */
    }

    console.log('');
  });

// 5. DAEMON — localhost browser UI for free-tier HITL
program
  .command('daemon')
  .description('Run the local approval server (browser HITL for free tier)')
  .addHelpText(
    'after',
    '\n  Subcommands: start (default), stop, status' +
      '\n  Options:' +
      '\n    --background  (-b)  start detached, no second terminal needed' +
      '\n    --openui      (-o)  start in background and open the browser (or just open if already running)' +
      '\n  Example:     node9 daemon --background'
  )
  .argument('[action]', 'start | stop | status (default: start)')
  .option('-b, --background', 'Start the daemon in the background (detached)')
  .option(
    '-o, --openui',
    'Start in background and open browser (or just open browser if already running)'
  )
  .action(
    async (action: string | undefined, options: { background?: boolean; openui?: boolean }) => {
      const cmd = (action ?? 'start').toLowerCase();
      if (cmd === 'stop') return stopDaemon();
      if (cmd === 'status') return daemonStatus();
      if (cmd !== 'start' && action !== undefined) {
        console.error(chalk.red(`Unknown daemon action: "${action}". Use: start | stop | status`));
        process.exit(1);
      }

      if (options.openui) {
        if (isDaemonRunning()) {
          // Daemon already running — just open the browser
          openBrowserLocal();
          console.log(chalk.green(`🌐  Opened browser: http://${DAEMON_HOST}:${DAEMON_PORT}/`));
          process.exit(0);
        }
        // Start in background, wait for it, then open browser
        const child = spawn('node9', ['daemon'], { detached: true, stdio: 'ignore' });
        child.unref();
        for (let i = 0; i < 12; i++) {
          await new Promise((r) => setTimeout(r, 250));
          if (isDaemonRunning()) break;
        }
        openBrowserLocal();
        console.log(chalk.green(`\n🛡️  Node9 daemon started + browser opened`));
        console.log(chalk.gray(`   http://${DAEMON_HOST}:${DAEMON_PORT}/`));
        process.exit(0);
      }

      if (options.background) {
        const child = spawn('node9', ['daemon'], { detached: true, stdio: 'ignore' });
        child.unref();
        console.log(chalk.green(`\n🛡️  Node9 daemon started in background  (PID ${child.pid})`));
        console.log(chalk.gray(`   http://${DAEMON_HOST}:${DAEMON_PORT}/`));
        console.log(chalk.gray(`   node9 daemon status  — check if running`));
        console.log(chalk.gray(`   node9 daemon stop    — stop it\n`));
        process.exit(0);
      }

      startDaemon();
    }
  );

// 6. CHECK (Internal Hook)
program
  .command('check')
  .description('Hook handler — evaluates a tool call before execution')
  .argument('[data]', 'JSON string of the tool call')
  .action(async (data) => {
    const processPayload = async (raw: string) => {
      try {
        if (!raw || raw.trim() === '') process.exit(0);

        // Debug logging — only when NODE9_DEBUG=1 to avoid filling disk
        if (process.env.NODE9_DEBUG === '1') {
          const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
          if (!fs.existsSync(path.dirname(logPath)))
            fs.mkdirSync(path.dirname(logPath), { recursive: true });
          fs.appendFileSync(logPath, `[${new Date().toISOString()}] STDIN: ${raw}\n`);
          fs.appendFileSync(
            logPath,
            `[${new Date().toISOString()}] TTY: ${process.stdout.isTTY}\n`
          );
        }

        // Support both Claude Code format { tool_name, tool_input }
        // and Gemini CLI format           { name, args }
        const payload = JSON.parse(raw) as {
          tool_name?: string;
          tool_input?: unknown; // Claude Code / standard
          name?: string;
          args?: unknown; // Gemini CLI BeforeTool
        };
        const toolName = sanitize(payload.tool_name ?? payload.name ?? '');
        const toolInput = payload.tool_input ?? payload.args ?? {};

        // Detect which AI agent invoked this hook from the payload format.
        // Claude Code sends { tool_name, tool_input }; Gemini CLI sends { name, args }.
        const agent =
          payload.tool_name !== undefined
            ? 'Claude Code'
            : payload.name !== undefined
              ? 'Gemini CLI'
              : 'Terminal';

        // Detect MCP server from Claude Code's tool name format: mcp__<server>__<tool>
        const mcpMatch = toolName.match(/^mcp__([^_](?:[^_]|_(?!_))*?)__/i);
        const mcpServer = mcpMatch?.[1];

        const sendBlock = (msg: string, result?: { blockedBy?: string; changeHint?: string }) => {
          const BLOCKED_BY_LABELS: Record<string, string> = {
            'team-policy': 'team policy (set by your admin)',
            'persistent-deny': 'you set this tool to always deny',
            'local-config': 'your local config (dangerousWords / rules)',
            'local-decision': 'you denied it in the browser',
            'no-approval-mechanism': 'no approval method is configured',
          };
          console.error(chalk.red(`\n🛑 Node9 blocked "${toolName}"`));
          if (result?.blockedBy) {
            console.error(
              chalk.gray(
                `   Blocked by: ${BLOCKED_BY_LABELS[result.blockedBy] ?? result.blockedBy}`
              )
            );
          }
          if (result?.changeHint) {
            console.error(chalk.cyan(`   To change:  ${result.changeHint}`));
          }
          console.error('');
          // Full Claude Code & Gemini compatibility format
          process.stdout.write(
            JSON.stringify({
              decision: 'block',
              reason: msg,
              hookSpecificOutput: {
                hookEventName: 'PreToolUse',
                permissionDecision: 'deny',
                permissionDecisionReason: msg,
              },
            }) + '\n'
          );
          process.exit(0);
        };

        // Unrecognised payload format — fail closed, don't silently allow.
        if (!toolName) {
          sendBlock('Node9: unrecognised hook payload — tool name missing.');
          return;
        }

        const meta = { agent, mcpServer };
        const result = await authorizeHeadless(toolName, toolInput, false, meta);
        if (result.approved) {
          if (result.checkedBy) {
            process.stderr.write(`✓ node9 [${result.checkedBy}]: "${toolName}" allowed\n`);
          }
          process.exit(0);
        }

        // No approval mechanism (no API key, daemon not running) — auto-start daemon and retry.
        // Skipped when:
        //   NODE9_NO_AUTO_DAEMON=1   — CI / test environments
        //   process.stdout.isTTY     — human at terminal, terminal prompt is more appropriate
        //   autoStartDaemon: false   — user preference in ~/.node9/config.json (toggled via daemon UI)
        if (
          result.noApprovalMechanism &&
          !isDaemonRunning() &&
          !process.env.NODE9_NO_AUTO_DAEMON &&
          !process.stdout.isTTY &&
          getGlobalSettings().autoStartDaemon
        ) {
          console.error(chalk.cyan('\n🛡️  Node9: Starting approval daemon automatically...'));
          const daemonReady = await autoStartDaemonAndWait();
          if (daemonReady) {
            const retry = await authorizeHeadless(toolName, toolInput, false, meta);
            if (retry.approved) {
              if (retry.checkedBy) {
                process.stderr.write(`✓ node9 [${retry.checkedBy}]: "${toolName}" allowed\n`);
              }
              process.exit(0);
            }
            sendBlock(retry.reason ?? `Node9 blocked "${toolName}".`, retry);
            return;
          }
        }

        sendBlock(result.reason ?? `Node9 blocked "${toolName}".`, result);
      } catch (err: unknown) {
        // On any parse error, fail open — never block Claude due to a Node9 bug.
        // Write to debug log only if NODE9_DEBUG=1, otherwise silently exit 0.
        if (process.env.NODE9_DEBUG === '1') {
          const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
          const errMsg = err instanceof Error ? err.message : String(err);
          fs.appendFileSync(logPath, `[${new Date().toISOString()}] ERROR: ${errMsg}\n`);
        }
        process.exit(0);
      }
    };

    if (data) {
      await processPayload(data);
    } else {
      let raw = '';
      let processed = false;
      const done = async () => {
        if (processed) return;
        processed = true;
        if (!raw.trim()) return process.exit(0);
        await processPayload(raw);
      };
      process.stdin.setEncoding('utf-8');
      process.stdin.on('data', (chunk) => (raw += chunk));
      process.stdin.on('end', () => void done());
      // Safety net: if stdin never closes (agent bug), process whatever we have
      // after 5 s rather than hanging forever and stalling the AI agent.
      setTimeout(() => void done(), 5000);
    }
  });

// 7. LOG (Audit Trail Hook)
program
  .command('log')
  .description('PostToolUse hook — records executed tool calls')
  .argument('[data]', 'JSON string of the tool call')
  .action(async (data) => {
    const logPayload = (raw: string) => {
      try {
        if (!raw || raw.trim() === '') process.exit(0);
        const payload = JSON.parse(raw) as { tool_name?: string; tool_input?: unknown };

        // Redact secrets from the input before stringifying for the log
        const entry = {
          ts: new Date().toISOString(),
          tool: sanitize(payload.tool_name ?? 'unknown'),
          input: JSON.parse(redactSecrets(JSON.stringify(payload.tool_input || {}))),
        };

        const logPath = path.join(os.homedir(), '.node9', 'audit.log');
        if (!fs.existsSync(path.dirname(logPath)))
          fs.mkdirSync(path.dirname(logPath), { recursive: true });
        fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');
      } catch {
        // Ignored
      }
      process.exit(0);
    };

    if (data) {
      logPayload(data);
    } else {
      let raw = '';
      process.stdin.setEncoding('utf-8');
      process.stdin.on('data', (chunk) => (raw += chunk));
      process.stdin.on('end', () => logPayload(raw));
      setTimeout(() => {
        if (!raw) process.exit(0);
      }, 500);
    }
  });

// 8. SMART RUNNER
// Agent CLIs that use the hook system — proxy mode does not work for these.
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

      // Friendly error for known agent CLIs that need hook-based integration
      if (HOOK_BASED_AGENTS[firstArg] !== undefined) {
        const target = HOOK_BASED_AGENTS[firstArg];
        console.error(
          chalk.yellow(`\n⚠️  Node9 proxy mode does not support "${target}" directly.`)
        );
        console.error(
          chalk.white(`\n   "${target}" is an interactive terminal app — it needs a real`)
        );
        console.error(
          chalk.white(`   TTY and communicates via its own hook system, not JSON-RPC.\n`)
        );
        console.error(chalk.bold(`   Use the hook-based integration instead:\n`));
        console.error(
          chalk.green(`     node9 addto ${target}   `) + chalk.gray('# one-time setup')
        );
        console.error(
          chalk.green(`     ${target}              `) +
            chalk.gray('# run normally — Node9 hooks fire automatically')
        );
        console.error(chalk.white(`\n   For browser approval popups (no API key required):`));
        console.error(
          chalk.green(`     node9 daemon --background`) +
            chalk.gray('# start (no second terminal needed)')
        );
        console.error(
          chalk.green(`     ${target}              `) +
            chalk.gray('# Node9 will open browser on dangerous actions\n')
        );
        process.exit(1);
      }

      const fullCommand = commandArgs.join(' ');

      // Check the command against policy.
      // First pass: no terminal fallback — prefer daemon/browser over a plain Y/N prompt.
      let result = await authorizeHeadless('shell', { command: fullCommand });

      // No approval mechanism → try to auto-start the daemon so the browser opens.
      // The daemon will open the browser itself when the next request arrives.
      if (
        result.noApprovalMechanism &&
        !isDaemonRunning() &&
        !process.env.NODE9_NO_AUTO_DAEMON &&
        getGlobalSettings().autoStartDaemon
      ) {
        console.error(chalk.cyan('\n🛡️  Node9: Starting approval daemon automatically...'));
        const daemonReady = await autoStartDaemonAndWait();
        if (daemonReady) result = await authorizeHeadless('shell', { command: fullCommand });
      }

      // Daemon unavailable but a human is at the terminal — fall back to a Y/N prompt.
      if (result.noApprovalMechanism && process.stdout.isTTY) {
        result = await authorizeHeadless('shell', { command: fullCommand }, true);
      }

      if (!result.approved) {
        console.error(
          chalk.red(`\n❌ Node9 Blocked: ${result.reason || 'Dangerous command detected.'}`)
        );
        if (result.blockedBy) {
          const BLOCKED_BY_LABELS: Record<string, string> = {
            'team-policy': 'Team policy (Node9 cloud)',
            'persistent-deny': 'Persistent deny rule',
            'local-config': 'Local config',
            'local-decision': 'Browser UI decision',
            'no-approval-mechanism': 'No approval mechanism available',
          };
          console.error(
            chalk.gray(`   Blocked by: ${BLOCKED_BY_LABELS[result.blockedBy] ?? result.blockedBy}`)
          );
        }
        if (result.changeHint) {
          console.error(chalk.cyan(`   To change:  ${result.changeHint}`));
        }
        process.exit(1);
      }

      console.error(chalk.green('\n✅ Approved — running command...\n'));
      await runProxy(fullCommand);
    } else {
      program.help();
    }
  });

// Safety net: catch unhandled promise rejections that escape individual try/catch blocks.
// For the `check` command (hook) these log to the debug file and exit 0 (fail-open) so
// a Node9 bug never blocks the AI agent. For all other commands they surface the error.
process.on('unhandledRejection', (reason) => {
  const isCheckHook = process.argv[2] === 'check';
  if (isCheckHook) {
    if (process.env.NODE9_DEBUG === '1') {
      const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
      const msg = reason instanceof Error ? reason.message : String(reason);
      fs.appendFileSync(logPath, `[${new Date().toISOString()}] UNHANDLED: ${msg}\n`);
    }
    process.exit(0); // fail-open: never stall the AI agent due to a Node9 bug
  } else {
    console.error('[Node9] Unhandled error:', reason);
    process.exit(1);
  }
});

program.parse();
