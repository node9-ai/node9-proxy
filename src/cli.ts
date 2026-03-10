#!/usr/bin/env node
import { Command } from 'commander';
import {
  authorizeHeadless,
  redactSecrets,
  DANGEROUS_WORDS,
  isDaemonRunning,
  getCredentials,
  checkPause,
  pauseNode9,
  resumeNode9,
  getConfig,
  _resetConfigCache,
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
import { createShadowSnapshot, applyUndo, getLatestSnapshotHash } from './undo';
import { confirm } from '@inquirer/prompts';

const { version } = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../package.json'), 'utf-8')
) as { version: string };

/** Parse a duration string like "15m", "1h", "30s" → milliseconds, or null if invalid. */
function parseDuration(str: string): number | null {
  const m = str.trim().match(/^(\d+(?:\.\d+)?)\s*(s|m|h|d)?$/i);
  if (!m) return null;
  const n = parseFloat(m[1]);
  switch ((m[2] ?? 'm').toLowerCase()) {
    case 's':
      return Math.round(n * 1_000);
    case 'm':
      return Math.round(n * 60_000);
    case 'h':
      return Math.round(n * 3_600_000);
    case 'd':
      return Math.round(n * 86_400_000);
    default:
      return null;
  }
}

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

async function autoStartDaemonAndWait(): Promise<boolean> {
  try {
    const child = spawn('node9', ['daemon'], {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, NODE9_AUTO_STARTED: '1' },
    });
    child.unref();
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 250));
      if (!isDaemonRunning()) continue;
      // Verify the HTTP server is actually accepting connections, not just that
      // the process is alive. isDaemonRunning() only checks the PID file, which
      // could be stale (OS PID reuse) or written before the socket is fully ready.
      try {
        const res = await fetch('http://127.0.0.1:7391/settings', {
          signal: AbortSignal.timeout(500),
        });
        if (res.ok) {
          // Open the browser NOW — before the approval request is registered —
          // so the browser has time to connect SSE. If we wait until POST /check,
          // broadcast('add') fires with sseClients.size === 0 and the request
          // depends on the async openBrowser() inside the daemon, which can lose
          // the race with the browser's own page-load timing.
          openBrowserLocal();
          return true;
        }
      } catch {
        // HTTP not ready yet — keep polling
      }
    }
  } catch {}
  return false;
}

const program = new Command();
program.name('node9').description('The Sudo Command for AI Agents').version(version);

async function runProxy(targetCommand: string) {
  const commandParts = parseCommandString(targetCommand);
  const cmd = commandParts[0];
  const args = commandParts.slice(1);

  let executable = cmd;
  try {
    const { stdout } = await execa('which', [cmd]);
    if (stdout) executable = stdout.trim();
  } catch {}

  console.log(chalk.green(`🚀 Node9 Proxy Active: Monitoring [${targetCommand}]`));

  // Spawn the MCP Server / Shell command
  const child = spawn(executable, args, {
    stdio: ['pipe', 'pipe', 'inherit'], // We control STDIN and STDOUT
    shell: true,
    env: { ...process.env, FORCE_COLOR: '1' },
  });

  // ── INTERCEPT INPUT (Agent -> Server) ──
  // This is where 'tools/call' requests come from
  const agentIn = readline.createInterface({ input: process.stdin, terminal: false });

  agentIn.on('line', async (line) => {
    let message;

    // 1. Safely attempt to parse JSON first
    try {
      message = JSON.parse(line);
    } catch {
      // If it's not JSON (raw shell usage), just forward it immediately
      child.stdin.write(line + '\n');
      return;
    }

    // 2. Check if it's an MCP tool call
    if (
      message.method === 'call_tool' ||
      message.method === 'tools/call' ||
      message.method === 'use_tool'
    ) {
      // PAUSE the stream so we don't process the next request while waiting for the human
      agentIn.pause();

      try {
        const name = message.params?.name || message.params?.tool_name || 'unknown';
        const toolArgs = message.params?.arguments || message.params?.tool_input || {};

        // Use our Race Engine to authorize
        const result = await authorizeHeadless(sanitize(name), toolArgs, true, {
          agent: 'Proxy/MCP',
        });

        if (!result.approved) {
          // If denied, send the MCP error back to the Agent and DO NOT forward to the server
          const errorResponse = {
            jsonrpc: '2.0',
            id: message.id,
            error: {
              code: -32000,
              message: `Node9: Action denied. ${result.reason || ''}`,
            },
          };
          process.stdout.write(JSON.stringify(errorResponse) + '\n');
          return; // Stop here! (The 'finally' block will handle the resume)
        }
      } catch {
        // FAIL CLOSED SECURITY: If the auth engine crashes, deny the action!
        const errorResponse = {
          jsonrpc: '2.0',
          id: message.id,
          error: {
            code: -32000,
            message: `Node9: Security engine encountered an error. Action blocked for safety.`,
          },
        };
        process.stdout.write(JSON.stringify(errorResponse) + '\n');
        return;
      } finally {
        // 3. GUARANTEE RESUME: Whether approved, denied, or errored, always wake up the stream
        agentIn.resume();
      }
    }

    // If approved or not a tool call, forward it to the real server's STDIN
    child.stdin.write(line + '\n');
  });

  // ── FORWARD OUTPUT (Server -> Agent) ──
  // We just pass the server's responses back to the agent as-is
  child.stdout.pipe(process.stdout);

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
      approvers.cloud = !options.local;
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

// 3. INIT (Upgraded with Enterprise Schema)
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
      settings: {
        mode: 'standard',
        autoStartDaemon: true,
        enableUndo: true,
        enableHookLogDebug: false,
        approvers: { native: true, browser: true, cloud: true, terminal: true },
      },
      policy: {
        sandboxPaths: ['/tmp/**', '**/sandbox/**', '**/test-results/**'],
        dangerousWords: DANGEROUS_WORDS,
        ignoredTools: [
          'list_*',
          'get_*',
          'read_*',
          'describe_*',
          'read',
          'write',
          'edit',
          'glob',
          'grep',
          'ls',
          'notebookread',
          'notebookedit',
          'webfetch',
          'websearch',
          'exitplanmode',
          'askuserquestion',
          'agent',
          'task*',
        ],
        toolInspection: {
          bash: 'command',
          shell: 'command',
          run_shell_command: 'command',
          'terminal.execute': 'command',
          'postgres:query': 'sql',
        },
        rules: [
          {
            action: 'rm',
            allowPaths: [
              '**/node_modules/**',
              'dist/**',
              'build/**',
              '.next/**',
              'coverage/**',
              '.cache/**',
              'tmp/**',
              'temp/**',
              '.DS_Store',
            ],
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

// 4. STATUS (Upgraded to show Waterfall & Undo status)
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
          openBrowserLocal();
          console.log(chalk.green(`🌐  Opened browser: http://${DAEMON_HOST}:${DAEMON_PORT}/`));
          process.exit(0);
        }
        const child = spawn('node9', ['daemon'], { detached: true, stdio: 'ignore' });
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
        const child = spawn('node9', ['daemon'], { detached: true, stdio: 'ignore' });
        child.unref();
        console.log(chalk.green(`\n🛡️  Node9 daemon started in background  (PID ${child.pid})`));
        process.exit(0);
      }

      startDaemon();
    }
  );

// 6. CHECK (Internal Hook - Upgraded with AI Negotiation Loop)
program
  .command('check')
  .description('Hook handler — evaluates a tool call before execution')
  .argument('[data]', 'JSON string of the tool call')
  .action(async (data) => {
    const processPayload = async (raw: string) => {
      try {
        if (!raw || raw.trim() === '') process.exit(0);

        let payload = JSON.parse(raw) as {
          tool_name?: string;
          tool_input?: unknown;
          name?: string;
          args?: unknown;
          cwd?: string;
          session_id?: string;
          hook_event_name?: string; // Claude: "PreToolUse" | Gemini: "BeforeTool"
          tool_use_id?: string; // Claude-only
          permission_mode?: string; // Claude-only
          timestamp?: string; // Gemini-only
        };

        try {
          payload = JSON.parse(raw);
        } catch (err) {
          // If JSON is broken (e.g. half-sent due to timeout), log it and fail open.
          // We load config temporarily just to check if debug logging is on.
          const tempConfig = getConfig();
          if (process.env.NODE9_DEBUG === '1' || tempConfig.settings.enableHookLogDebug) {
            const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
            const errMsg = err instanceof Error ? err.message : String(err);
            fs.appendFileSync(
              logPath,
              `[${new Date().toISOString()}] JSON_PARSE_ERROR: ${errMsg}\nRAW: ${raw}\n`
            );
          }
          process.exit(0);
          return;
        }

        // Change to the project cwd from the hook payload BEFORE loading config,
        // so getConfig() finds the correct node9.config.json for that project.
        if (payload.cwd) {
          try {
            process.chdir(payload.cwd);
            // Crucial: Reset the config cache so we look for node9.config.json
            // in the project folder we just moved into.
            _resetConfigCache();
          } catch {
            // ignore if cwd doesn't exist
          }
        }

        const config = getConfig();

        // Debug logging — controlled by Env Var OR new Settings config
        if (process.env.NODE9_DEBUG === '1' || config.settings.enableHookLogDebug) {
          const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
          if (!fs.existsSync(path.dirname(logPath)))
            fs.mkdirSync(path.dirname(logPath), { recursive: true });
          fs.appendFileSync(logPath, `[${new Date().toISOString()}] STDIN: ${raw}\n`);
        }
        const toolName = sanitize(payload.tool_name ?? payload.name ?? '');
        const toolInput = payload.tool_input ?? payload.args ?? {};

        // Both Claude and Gemini send session_id + hook_event_name, but with different values:
        //   Claude:  hook_event_name = "PreToolUse" | "PostToolUse", also sends tool_use_id
        //   Gemini:  hook_event_name = "BeforeTool" | "AfterTool",   also sends timestamp
        const agent =
          payload.hook_event_name === 'PreToolUse' ||
          payload.hook_event_name === 'PostToolUse' ||
          payload.tool_use_id !== undefined ||
          payload.permission_mode !== undefined
            ? 'Claude Code'
            : payload.hook_event_name === 'BeforeTool' ||
                payload.hook_event_name === 'AfterTool' ||
                payload.timestamp !== undefined
              ? 'Gemini CLI'
              : payload.tool_name !== undefined || payload.name !== undefined
                ? 'Unknown Agent'
                : 'Terminal';
        const mcpMatch = toolName.match(/^mcp__([^_](?:[^_]|_(?!_))*?)__/i);
        const mcpServer = mcpMatch?.[1];

        // ── THE NEGOTIATION LOOP (TALKING BACK TO THE AI) ───────────────
        // src/cli.ts -> inside the check command action

        const sendBlock = (
          msg: string,
          result?: { blockedBy?: string; changeHint?: string; blockedByLabel?: string }
        ) => {
          // 1. Determine the context (User vs Policy)
          const blockedByContext =
            result?.blockedByLabel || result?.blockedBy || 'Local Security Policy';

          // 2. Identify if it was a human decision or an automated rule
          const isHumanDecision =
            blockedByContext.toLowerCase().includes('user') ||
            blockedByContext.toLowerCase().includes('daemon') ||
            blockedByContext.toLowerCase().includes('decision');

          // 3. Print to the human terminal for visibility
          console.error(chalk.red(`\n🛑 Node9 blocked "${toolName}"`));
          console.error(chalk.gray(`   Triggered by: ${blockedByContext}`));
          if (result?.changeHint) console.error(chalk.cyan(`   To change:  ${result.changeHint}`));
          console.error('');

          // 4. THE NEGOTIATION PROMPT: This is what the LLM actually reads
          let aiFeedbackMessage = '';

          if (isHumanDecision) {
            // Voice for User Rejection
            aiFeedbackMessage = `NODE9 SECURITY INTERVENTION: The human user specifically REJECTED this action.
        REASON: ${msg || 'No specific reason provided by user.'}

        INSTRUCTIONS FOR AI AGENT:
        - Do NOT retry this exact command immediately.
        - Explain to the user that you understand they blocked the action.
        - Ask the user if there is an alternative approach they would prefer, or if they intended to block this action entirely.
        - If you believe this action is critical, explain your reasoning to the user and ask them to run 'node9 pause 15m' to allow you to proceed.`;
          } else {
            // Voice for Policy/Rule Rejection
            aiFeedbackMessage = `NODE9 SECURITY INTERVENTION: Action blocked by automated policy [${blockedByContext}].
        REASON: ${msg}

        INSTRUCTIONS FOR AI AGENT:
        - This command violates the current security configuration.
        - Do NOT attempt to bypass this rule with bash syntax tricks; it will be blocked again.
        - Pivot to a non-destructive or read-only alternative.
        - Inform the user which security rule was triggered.`;
          }

          // 5. Send the structured JSON back to the LLM agent
          process.stdout.write(
            JSON.stringify({
              decision: 'block',
              reason: aiFeedbackMessage, // This is the core instruction
              hookSpecificOutput: {
                hookEventName: 'PreToolUse',
                permissionDecision: 'deny',
                permissionDecisionReason: aiFeedbackMessage,
              },
            }) + '\n'
          );
          process.exit(0);
        };
        if (!toolName) {
          sendBlock('Node9: unrecognised hook payload — tool name missing.');
          return;
        }

        const meta = { agent, mcpServer };

        // Snapshot BEFORE the tool runs (PreToolUse) so undo can restore to
        // the state prior to this change. Snapshotting after (PostToolUse)
        // captures the changed state, making undo a no-op.
        const STATE_CHANGING_TOOLS_PRE = [
          'bash',
          'shell',
          'write_file',
          'edit_file',
          'replace',
          'terminal.execute',
          'str_replace_based_edit_tool',
          'create_file',
        ];
        if (
          config.settings.enableUndo &&
          STATE_CHANGING_TOOLS_PRE.includes(toolName.toLowerCase())
        ) {
          await createShadowSnapshot();
        }

        // Pass to Headless authorization
        const result = await authorizeHeadless(toolName, toolInput, false, meta);

        if (result.approved) {
          if (result.checkedBy)
            process.stderr.write(`✓ node9 [${result.checkedBy}]: "${toolName}" allowed\n`);
          process.exit(0);
        }

        // Auto-start daemon if allowed
        if (
          result.noApprovalMechanism &&
          !isDaemonRunning() &&
          !process.env.NODE9_NO_AUTO_DAEMON &&
          !process.stdout.isTTY &&
          config.settings.autoStartDaemon
        ) {
          console.error(chalk.cyan('\n🛡️  Node9: Starting approval daemon automatically...'));
          const daemonReady = await autoStartDaemonAndWait();
          if (daemonReady) {
            const retry = await authorizeHeadless(toolName, toolInput, false, meta);
            if (retry.approved) {
              if (retry.checkedBy)
                process.stderr.write(`✓ node9 [${retry.checkedBy}]: "${toolName}" allowed\n`);
              process.exit(0);
            }
            // Add the dynamic label so we know if it was Cloud, Config, etc.
            sendBlock(retry.reason ?? `Node9 blocked "${toolName}".`, {
              ...retry,
              blockedByLabel: retry.blockedByLabel,
            });
            return;
          }
        }

        // Add the dynamic label to the final block
        sendBlock(result.reason ?? `Node9 blocked "${toolName}".`, {
          ...result,
          blockedByLabel: result.blockedByLabel,
        });
      } catch (err: unknown) {
        if (process.env.NODE9_DEBUG === '1') {
          const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
          const errMsg = err instanceof Error ? err.message : String(err);
          fs.appendFileSync(logPath, `[${new Date().toISOString()}] ERROR: ${errMsg}\n`);
        }
        process.exit(0); // Fail open so we never break Claude on a parse error
      }
    };

    if (data) {
      await processPayload(data);
    } else {
      // ── THIS IS THE SECTION YOU ARE REPLACING ──
      let raw = '';
      let processed = false;
      let inactivityTimer: NodeJS.Timeout | null = null;

      const done = async () => {
        // Atomic check: prevents double-processing if 'end' and 'timeout' fire together
        if (processed) return;
        processed = true;

        // Kill the timer so it doesn't fire while we are waiting for human approval
        if (inactivityTimer) clearTimeout(inactivityTimer);

        if (!raw.trim()) return process.exit(0);

        await processPayload(raw);
      };

      process.stdin.setEncoding('utf-8');

      process.stdin.on('data', (chunk) => {
        raw += chunk;

        // Sliding window: reset timer every time data arrives
        if (inactivityTimer) clearTimeout(inactivityTimer);
        inactivityTimer = setTimeout(() => void done(), 2000);
      });

      process.stdin.on('end', () => {
        void done();
      });

      // Initial safety: if no data arrives at all within 5s, exit.
      inactivityTimer = setTimeout(() => void done(), 5000);
    }
  });

// 7. LOG (Audit Trail Hook)
program
  .command('log')
  .description('PostToolUse hook — records executed tool calls')
  .argument('[data]', 'JSON string of the tool call')
  .action(async (data) => {
    // 1. Added 'async' here to allow 'await' (Fixes Error 1308)
    const logPayload = async (raw: string) => {
      try {
        if (!raw || raw.trim() === '') process.exit(0);
        const payload = JSON.parse(raw) as {
          tool_name?: string;
          name?: string;
          tool_input?: unknown;
          args?: unknown;
        };

        // Handle both Claude (tool_name) and Gemini (name)
        const tool = sanitize(payload.tool_name ?? payload.name ?? 'unknown');
        const rawInput = payload.tool_input ?? payload.args ?? {};

        const entry = {
          ts: new Date().toISOString(),
          tool: tool,
          args: JSON.parse(redactSecrets(JSON.stringify(rawInput))),
          decision: 'allowed',
          source: 'post-hook',
        };

        const logPath = path.join(os.homedir(), '.node9', 'audit.log');
        if (!fs.existsSync(path.dirname(logPath)))
          fs.mkdirSync(path.dirname(logPath), { recursive: true });
        fs.appendFileSync(logPath, JSON.stringify(entry) + '\n');

        const config = getConfig();
        const STATE_CHANGING_TOOLS = [
          'bash',
          'shell',
          'write_file',
          'edit_file',
          'replace',
          'terminal.execute',
        ];

        if (config.settings.enableUndo && STATE_CHANGING_TOOLS.includes(tool.toLowerCase())) {
          await createShadowSnapshot();
        }
      } catch {
        /* ignore */
      }
      process.exit(0);
    };

    if (data) {
      await logPayload(data);
    } else {
      let raw = '';
      process.stdin.setEncoding('utf-8');
      process.stdin.on('data', (chunk) => (raw += chunk));
      process.stdin.on('end', () => {
        // Use void to fire the async function from the sync event emitter
        void logPayload(raw);
      });
      setTimeout(() => {
        if (!raw) process.exit(0);
      }, 500);
    }
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

      const fullCommand = commandArgs.join(' ');
      let result = await authorizeHeadless('shell', { command: fullCommand });

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

      if (result.noApprovalMechanism && process.stdout.isTTY) {
        result = await authorizeHeadless('shell', { command: fullCommand }, true);
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
  .description('Revert the project to the state before the last AI action')
  .action(async () => {
    const hash = getLatestSnapshotHash();

    if (!hash) {
      console.log(chalk.yellow('\nℹ️  No Undo snapshot found for this machine.\n'));
      return;
    }

    console.log(chalk.magenta.bold('\n⏪ NODE9 UNDO ENGINE'));
    console.log(chalk.white(`Target Snapshot: ${chalk.gray(hash.slice(0, 7))}`));

    const proceed = await confirm({
      message: 'Revert all files to the state before the last AI action?',
      default: false,
    });

    if (proceed) {
      if (applyUndo(hash)) {
        console.log(chalk.green('✅ Project reverted successfully.\n'));
      } else {
        console.error(chalk.red('❌ Undo failed. Ensure you are in a Git repository.\n'));
      }
    }
  });

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

program.parse();
