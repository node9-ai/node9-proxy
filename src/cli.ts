#!/usr/bin/env node
import { Command } from 'commander';
import {
  authorizeHeadless,
  redactSecrets,
  DEFAULT_CONFIG,
  isDaemonRunning,
  getCredentials,
  checkPause,
  pauseNode9,
  resumeNode9,
  getConfig,
  _resetConfigCache,
  explainPolicy,
  shouldSnapshot,
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
import { createShadowSnapshot, applyUndo, getSnapshotHistory, computeUndoDiff } from './undo';
import {
  getShield,
  listShields,
  readActiveShields,
  writeActiveShields,
  resolveShieldName,
} from './shields';
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

/**
 * Builds a context-specific negotiation message for the AI agent.
 * Instead of a generic "blocked" message, the AI gets actionable instructions
 * based on WHY it was blocked so it can pivot intelligently.
 */
function buildNegotiationMessage(
  blockedByLabel: string,
  isHumanDecision: boolean,
  humanReason?: string
): string {
  if (isHumanDecision) {
    return `NODE9: The human user rejected this action.
REASON: ${humanReason || 'No specific reason provided.'}
INSTRUCTIONS:
- Do NOT retry this exact command.
- Acknowledge the block to the user and ask if there is an alternative approach.
- If you believe this action is critical, explain your reasoning and ask them to run "node9 pause 15m" to proceed.`;
  }

  const label = blockedByLabel.toLowerCase();

  if (
    label.includes('dlp') ||
    label.includes('secret detected') ||
    label.includes('credential review')
  ) {
    return `NODE9 SECURITY ALERT: A sensitive credential (API key, token, or private key) was found in your tool call arguments.
CRITICAL INSTRUCTION: Do NOT retry this action.
REQUIRED ACTIONS:
1. Remove the hardcoded credential from your command or code.
2. Use an environment variable or a dedicated secrets manager instead.
3. Treat the leaked credential as compromised and rotate it immediately.
Do NOT attempt to bypass this check or pass the credential through another tool.`;
  }

  if (label.includes('sql safety') && label.includes('delete without where')) {
    return `NODE9: Blocked — DELETE without WHERE clause would wipe the entire table.
INSTRUCTION: Add a WHERE clause to scope the deletion (e.g. WHERE id = <value>).
Do NOT retry without a WHERE clause.`;
  }

  if (label.includes('sql safety') && label.includes('update without where')) {
    return `NODE9: Blocked — UPDATE without WHERE clause would update every row.
INSTRUCTION: Add a WHERE clause to scope the update (e.g. WHERE id = <value>).
Do NOT retry without a WHERE clause.`;
  }

  if (label.includes('dangerous word')) {
    const match = blockedByLabel.match(/dangerous word: "([^"]+)"/i);
    const word = match?.[1] ?? 'a dangerous keyword';
    return `NODE9: Blocked — command contains forbidden keyword "${word}".
INSTRUCTION: Do NOT use "${word}". Use a non-destructive alternative.
Do NOT attempt to bypass this with shell tricks or aliases — it will be blocked again.`;
  }

  if (label.includes('path blocked') || label.includes('sandbox')) {
    return `NODE9: Blocked — operation targets a path outside the allowed sandbox.
INSTRUCTION: Move your output to an allowed directory such as /tmp/ or the project directory.
Do NOT retry on the same path.`;
  }

  if (label.includes('inline execution')) {
    return `NODE9: Blocked — inline code execution (e.g. bash -c "...") is not allowed.
INSTRUCTION: Use individual tool calls instead of embedding code in a shell string.`;
  }

  if (label.includes('strict mode')) {
    return `NODE9: Blocked — strict mode is active. All tool calls require explicit human approval.
INSTRUCTION: Inform the user this action is pending approval. Wait for them to approve via the dashboard or run "node9 pause".`;
  }

  if (label.includes('rule') && label.includes('default block')) {
    const match = blockedByLabel.match(/rule "([^"]+)"/i);
    const rule = match?.[1] ?? 'a policy rule';
    return `NODE9: Blocked — action "${rule}" is forbidden by security policy.
INSTRUCTION: Do NOT use "${rule}". Find a read-only or non-destructive alternative.
Do NOT attempt to bypass this rule.`;
  }

  // Generic fallback
  return `NODE9: Action blocked by security policy [${blockedByLabel}].
INSTRUCTIONS:
- Do NOT retry this exact command or attempt to bypass the rule.
- Pivot to a non-destructive or read-only alternative.
- Inform the user which security rule was triggered and ask how to proceed.`;
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
    shell: false,
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
          // 1. Talk to the human
          console.error(chalk.red(`\n🛑 Node9 Sudo: Action Blocked`));
          console.error(chalk.gray(`   Tool: ${name}`));
          console.error(chalk.gray(`   Reason: ${result.reason || 'Security Policy'}\n`));

          // 2. Talk to the AI with a context-specific negotiation message
          const blockedByLabel = result.blockedByLabel ?? result.reason ?? 'Security Policy';
          const isHuman =
            blockedByLabel.toLowerCase().includes('user') ||
            blockedByLabel.toLowerCase().includes('daemon') ||
            blockedByLabel.toLowerCase().includes('decision');
          const aiInstruction = buildNegotiationMessage(blockedByLabel, isHuman, result.reason);

          const errorResponse = {
            jsonrpc: '2.0',
            id: message.id ?? null,
            error: {
              code: -32000,
              message: aiInstruction,
              data: {
                reason: result.reason,
                blockedBy: result.blockedByLabel,
              },
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

// 2c. DOCTOR
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
      const which = execSync('which node9', { encoding: 'utf-8' }).trim();
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
      const gitVersion = execSync('git --version', { encoding: 'utf-8' }).trim();
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
          if (
            blockedByContext.includes('DLP') ||
            blockedByContext.includes('Secret Detected') ||
            blockedByContext.includes('Credential Review')
          ) {
            console.error(chalk.bgRed.white.bold(`\n 🚨 NODE9 DLP ALERT — CREDENTIAL DETECTED `));
            console.error(chalk.red.bold(`   A sensitive secret was found in the tool arguments!`));
          } else {
            console.error(chalk.red(`\n🛑 Node9 blocked "${toolName}"`));
          }
          console.error(chalk.gray(`   Triggered by: ${blockedByContext}`));
          if (result?.changeHint) console.error(chalk.cyan(`   To change:  ${result.changeHint}`));
          console.error('');

          // 4. THE NEGOTIATION PROMPT: Context-specific instruction for the AI
          const aiFeedbackMessage = buildNegotiationMessage(blockedByContext, isHumanDecision, msg);

          console.error(chalk.dim(`   (Detailed instructions sent to AI agent)`));

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
        if (shouldSnapshot(toolName, toolInput, config)) {
          await createShadowSnapshot(toolName, toolInput);
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

        // PostToolUse snapshot is a fallback for tools not covered by PreToolUse.
        // Uses the same configurable snapshot policy.
        if (shouldSnapshot(tool, {}, config)) {
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
      let result = await authorizeHeadless('shell', { command: fullCommand }, true, {
        agent: 'Terminal',
      });

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

// ---------------------------------------------------------------------------
// node9 shield — manage pre-packaged security rule templates
// ---------------------------------------------------------------------------
// Shields are applied dynamically at getConfig() load time by reading
// ~/.node9/shields.json and merging the catalog rules into the runtime policy.
// enable/disable only update shields.json — config.json is never touched.

const shieldCmd = program
  .command('shield')
  .description('Manage pre-packaged security shield templates');

shieldCmd
  .command('enable <service>')
  .description('Enable a security shield for a specific service')
  .action((service: string) => {
    const name = resolveShieldName(service);
    if (!name) {
      console.error(chalk.red(`\n❌ Unknown shield: "${service}"\n`));
      console.log(`Run ${chalk.cyan('node9 shield list')} to see available shields.\n`);
      process.exit(1);
    }
    const shield = getShield(name!)!;

    const active = readActiveShields();
    if (active.includes(name!)) {
      console.log(chalk.yellow(`\nℹ️  Shield "${name}" is already active.\n`));
      return;
    }
    writeActiveShields([...active, name!]);

    console.log(chalk.green(`\n🛡️  Shield "${name}" enabled.`));
    console.log(chalk.gray(`   ${shield.smartRules.length} smart rules now active.`));
    if (shield.dangerousWords.length > 0)
      console.log(chalk.gray(`   ${shield.dangerousWords.length} dangerous words now active.`));
    if (name === 'filesystem') {
      console.log(
        chalk.yellow(
          `\n   ⚠️  Note: filesystem rules cover common rm -rf patterns but not all variants.\n` +
            `      Tools like unlink, find -delete, or language-level file ops are not intercepted.`
        )
      );
    }
    console.log('');
  });

shieldCmd
  .command('disable <service>')
  .description('Disable a security shield')
  .action((service: string) => {
    const name = resolveShieldName(service);
    if (!name) {
      console.error(chalk.red(`\n❌ Unknown shield: "${service}"\n`));
      console.log(`Run ${chalk.cyan('node9 shield list')} to see available shields.\n`);
      process.exit(1);
    }

    const active = readActiveShields();
    if (!active.includes(name!)) {
      console.log(chalk.yellow(`\nℹ️  Shield "${name}" is not active.\n`));
      return;
    }

    writeActiveShields(active.filter((s) => s !== name));

    console.log(chalk.green(`\n🛡️  Shield "${name}" disabled.\n`));
  });

shieldCmd
  .command('list')
  .description('Show all available shields')
  .action(() => {
    const active = new Set(readActiveShields());
    console.log(chalk.bold('\n🛡️  Available Shields\n'));
    for (const shield of listShields()) {
      const status = active.has(shield.name) ? chalk.green('● enabled') : chalk.gray('○ disabled');
      console.log(`  ${status}  ${chalk.cyan(shield.name.padEnd(12))} ${shield.description}`);
      if (shield.aliases.length > 0)
        console.log(chalk.gray(`              aliases: ${shield.aliases.join(', ')}`));
    }
    console.log('');
  });

shieldCmd
  .command('status')
  .description('Show which shields are currently active')
  .action(() => {
    const active = readActiveShields();
    if (active.length === 0) {
      console.log(chalk.yellow('\nℹ️  No shields are active.\n'));
      console.log(`Run ${chalk.cyan('node9 shield list')} to see available shields.\n`);
      return;
    }
    console.log(chalk.bold('\n🛡️  Active Shields\n'));
    for (const name of active) {
      const shield = getShield(name);
      if (!shield) continue;
      console.log(`  ${chalk.green('●')} ${chalk.cyan(name)}`);
      console.log(
        chalk.gray(
          `    ${shield.smartRules.length} smart rules · ${shield.dangerousWords.length} dangerous words`
        )
      );
    }
    console.log('');
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
