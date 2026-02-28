#!/usr/bin/env node
import { Command } from 'commander';
import { authorizeAction, authorizeHeadless } from './core';
import { setupClaude, setupGemini, setupCursor } from './setup';
import { spawn } from 'child_process';
import { parseCommandString } from 'execa';
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

const program = new Command();

program.name('node9').description('The Sudo Command for AI Agents').version(version);

// Helper for the Proxy logic
async function runProxy(targetCommand: string) {
  console.log(chalk.green(`🚀 Node9 Proxy Active: Monitoring [${targetCommand}]`));
  const commandParts = parseCommandString(targetCommand);
  const cmd = commandParts[0];
  const args = commandParts.slice(1);

  const child = spawn(cmd, args, {
    stdio: ['pipe', 'pipe', 'inherit'],
    shell: true,
  });

  const rl = readline.createInterface({ input: process.stdin, terminal: true });
  rl.on('line', (line) => {
    child.stdin.write(line + '\n');
  });

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
  .action((apiKey) => {
    const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
    if (!fs.existsSync(path.dirname(credPath)))
      fs.mkdirSync(path.dirname(credPath), { recursive: true });
    fs.writeFileSync(
      credPath,
      JSON.stringify({ apiKey, apiUrl: 'https://api.node9.ai/api/v1/intercept' }, null, 2)
    );
    console.log(chalk.green(`✅ Logged in.`));
  });

// 2. ADDTO
program
  .command('addto')
  .argument('<target>')
  .action(async (target) => {
    if (target === 'gemini') return await setupGemini();
    if (target === 'claude') return await setupClaude();
    if (target === 'cursor') return await setupCursor();
  });
// 3. INIT
program
  .command('init')
  .description('Create ~/.node9/config.json with default policy')
  .action(() => {
    const configPath = path.join(os.homedir(), '.node9', 'config.json');
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

// 4. CHECK (Internal Hook)
program
  .command('check')
  .description('Hook handler — evaluates a tool call before execution')
  .argument('[data]', 'JSON string of the tool call')
  .action(async (data) => {
    const processPayload = async (raw: string) => {
      const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
      try {
        if (!raw || raw.trim() === '') process.exit(0);

        // Debug: Log raw input and TTY status
        if (!fs.existsSync(path.dirname(logPath)))
          fs.mkdirSync(path.dirname(logPath), { recursive: true });
        fs.appendFileSync(logPath, `[${new Date().toISOString()}] STDIN: ${raw}\n`);
        fs.appendFileSync(logPath, `[${new Date().toISOString()}] TTY: ${process.stdout.isTTY}\n`);

        const payload = JSON.parse(raw) as { tool_name?: string; tool_input?: unknown };
        const toolName = sanitize(payload.tool_name ?? '');
        const toolInput = payload.tool_input ?? {};

        const { approved, reason } = await authorizeHeadless(toolName, toolInput);
        if (approved) process.exit(0);

        const msg = reason ?? `Node9 blocked "${toolName}".`;

        // Ensure block reason is visible in terminal even if Gemini swallows stdout
        console.error(chalk.red(`\n🛡️  Node9 Security Block: ${msg}\n`));

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
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        fs.appendFileSync(logPath, `[${new Date().toISOString()}] ERROR: ${errMsg}\n`);
        process.exit(0); // Fail open on parse error
      }
    };

    if (data) {
      await processPayload(data);
    } else {
      let raw = '';
      process.stdin.setEncoding('utf-8');
      process.stdin.on('data', (chunk) => (raw += chunk));
      process.stdin.on('end', async () => await processPayload(raw));
      setTimeout(() => {
        if (!raw) process.exit(0);
      }, 500);
    }
  });

// 5. LOG (Audit Trail Hook)
program
  .command('log')
  .description('PostToolUse hook — records executed tool calls')
  .argument('[data]', 'JSON string of the tool call')
  .action(async (data) => {
    const logPayload = (raw: string) => {
      try {
        if (!raw || raw.trim() === '') process.exit(0);
        const payload = JSON.parse(raw) as { tool_name?: string; tool_input?: unknown };
        const entry = {
          ts: new Date().toISOString(),
          tool: sanitize(payload.tool_name ?? 'unknown'),
          input: payload.tool_input,
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

// 6. SMART RUNNER
program
  .argument('[command...]', 'The agent command to run (e.g., gemini)')
  .action(async (commandArgs) => {
    if (commandArgs && commandArgs.length > 0) {
      const fullCommand = commandArgs.join(' ');

      // NEW: Check the command itself against policy before running
      // We treat the initial command as a 'shell' tool call
      const { approved, reason } = await authorizeHeadless('shell', { command: fullCommand });
      if (!approved) {
        console.error(chalk.red(`\n❌ Node9 Blocked: ${reason || 'Dangerous command detected.'}`));
        process.exit(1);
      }

      await runProxy(fullCommand);
    } else {
      program.help();
    }
  });

import { DANGEROUS_WORDS } from './core';
program.parse();
