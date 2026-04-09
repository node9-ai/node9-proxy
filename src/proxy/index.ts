// src/proxy/index.ts
// MCP / JSON-RPC stdio proxy: intercepts tool calls from an AI agent, runs them
// through the Node9 authorization engine, and forwards approved calls to the
// real MCP server process. Blocked calls get a structured JSON-RPC error back.
import readline from 'readline';
import chalk from 'chalk';
import { spawn } from 'child_process';
import { execa } from 'execa';
import { parseCommandString } from 'execa';
import { authorizeHeadless } from '../auth/orchestrator';
import { buildNegotiationMessage } from '../policy/negotiation';

function sanitize(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x1F\x7F]/g, '');
}

export async function runProxy(targetCommand: string) {
  const commandParts = parseCommandString(targetCommand);
  const cmd = commandParts[0];
  const args = commandParts.slice(1);

  let executable = cmd;
  let useShell = false;
  try {
    const { stdout } = await execa('which', [cmd]);
    if (stdout) executable = stdout.trim();
  } catch {
    // Command not found as a standalone binary — may be a shell builtin or alias.
    // Fall back to shell mode so the system shell can resolve it.
    useShell = true;
  }

  // stderr only — stdout must stay clean for stdio protocols (JSON-RPC, MCP)
  console.error(chalk.green(`🚀 Node9 Proxy Active: Monitoring [${targetCommand}]`));

  // Spawn the MCP Server / Shell command.
  // Use bash (not /bin/sh) for shell fallback so that bash builtins and
  // bash-specific syntax work correctly — /bin/sh is dash on many systems.
  const spawnEnv = { ...process.env, FORCE_COLOR: '1' };
  const child = useShell
    ? spawn('/bin/bash', ['-c', targetCommand], {
        stdio: ['pipe', 'pipe', 'inherit'],
        shell: false,
        env: spawnEnv,
      })
    : spawn(executable, args, { stdio: ['pipe', 'pipe', 'inherit'], shell: false, env: spawnEnv });

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
        const result = await authorizeHeadless(sanitize(name), toolArgs, {
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
