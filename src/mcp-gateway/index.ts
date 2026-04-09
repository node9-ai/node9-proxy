// src/mcp-gateway/index.ts
// Node9 MCP Gateway — transparent stdio proxy that intercepts MCP tool calls,
// runs them through the Node9 authorization engine, and forwards approved calls
// to the real upstream MCP server. Blocked calls receive a structured JSON-RPC
// error response that the agent can reason about.
//
// Architecture:
//   Agent (MCP client)
//     ↓ stdin/stdout
//   Node9 MCP Gateway  ← this file
//     ↓ child stdin/stdout
//   Upstream MCP server (spawned as child process)
//
// Backpressure: readline is paused during each authorization call so that a
// second tools/call cannot be processed concurrently. MCP clients are expected
// to wait for a response before sending the next request.
import readline from 'readline';
import chalk from 'chalk';
import { spawn } from 'child_process';
import { execa } from 'execa';
import { authorizeHeadless } from '../auth/orchestrator';
import { buildNegotiationMessage } from '../policy/negotiation';
import { checkProvenance } from '../utils/provenance.js';

function sanitize(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x1F\x7F]/g, '');
}

/**
 * JSON-RPC error codes used by the gateway.
 * -32600: Invalid Request (id type rejected before processing)
 * -32000: Server Error — implementation-defined range (-32000 to -32099 per spec)
 *         Used for security blocks (policy, DLP, auth engine failures).
 */
const RPC_INVALID_REQUEST = -32600;
const RPC_SERVER_ERROR = -32000;

/** Validate JSON-RPC id — must be string, number, or null (per spec). */
function isValidId(id: unknown): id is string | number | null {
  return id === null || typeof id === 'string' || typeof id === 'number';
}

/** Extract the MCP server name from a namespaced tool name (mcp__<server>__<tool>). */
function extractMcpServer(toolName: string): string | undefined {
  const match = toolName.match(/^mcp__([^_](?:[^_]|_(?!_))*?)__/i);
  return match?.[1];
}

/**
 * Shell-style tokenizer: splits on whitespace, respects double-quoted strings
 * and backslash escapes. Does NOT spawn a shell — no injection risk.
 * Example: `node "/path with spaces/server.js"` → `['node', '/path with spaces/server.js']`
 *
 * Exported for unit testing — callers outside this module should not use it directly.
 */
export function tokenize(cmd: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inDouble = false;
  let i = 0;
  while (i < cmd.length) {
    const ch = cmd[i];
    if (inDouble) {
      if (ch === '"') {
        inDouble = false;
      } else if (ch === '\\' && i + 1 < cmd.length) {
        current += cmd[++i];
      } else {
        current += ch;
      }
    } else {
      if (ch === '"') {
        inDouble = true;
      } else if (ch === ' ' || ch === '\t') {
        if (current) {
          tokens.push(current);
          current = '';
        }
      } else if (ch === '\\' && i + 1 < cmd.length) {
        current += cmd[++i];
      } else {
        current += ch;
      }
    }
    i++;
  }
  if (current) tokens.push(current);
  return tokens;
}

export async function runMcpGateway(upstreamCommand: string): Promise<void> {
  // tokenize() performs shell-style word splitting (handles double-quoted strings
  // and backslash escapes) without spawning a shell — no injection risk.
  // The result is passed to spawn() with shell:false.
  const commandParts = tokenize(upstreamCommand);
  const cmd = commandParts[0];
  const cmdArgs = commandParts.slice(1);

  let executable = cmd;
  try {
    const { stdout } = await execa('which', [cmd]);
    if (stdout) executable = stdout.trim();
  } catch {}

  // Check binary provenance before spawning — warn if the upstream server binary
  // is in a suspicious location (temp dir, world-writable).
  // The gateway warns but does NOT exit: the upstream is human-configured (the user
  // wrote the --upstream flag or .mcp.json), so we surface the concern without
  // blocking a legitimate setup. The hard block (process.exit) applies to
  // AI-initiated bash commands via the policy engine, not to configured servers.
  const prov = checkProvenance(executable);
  if (prov.trustLevel === 'suspect') {
    console.error(
      chalk.red(
        `⚠️  Node9: Upstream MCP server binary is suspect — ${prov.reason} (${prov.resolvedPath})`
      )
    );
    console.error(chalk.red('   Verify this binary is trusted before proceeding.'));
  }

  // stderr only — stdout must stay clean for the JSON-RPC stdio protocol
  console.error(chalk.green(`🚀 Node9 MCP Gateway: Monitoring [${upstreamCommand}]`));

  // Strip env vars that can inject code into the upstream subprocess.
  // This matters most when the upstream is a Python, Ruby, or Node.js server —
  // an attacker who controls these vars could load arbitrary modules/libraries.
  //   NODE_OPTIONS / NODE_PATH     — Node.js require-hook and module-path injection
  //   LD_PRELOAD / LD_LIBRARY_PATH — shared-library injection on Linux
  //   DYLD_INSERT_LIBRARIES        — shared-library injection on macOS
  //   PYTHONPATH / PYTHONSTARTUP   — Python module-path and startup-script injection
  //   PERL5LIB / PERL5OPT          — Perl module-path and option injection
  //   RUBYLIB / RUBYOPT            — Ruby load-path and option injection
  //   JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS — JVM agent injection for Java MCP servers
  const UPSTREAM_INJECTOR_VARS = new Set([
    'NODE_OPTIONS',
    'NODE_PATH',
    'LD_PRELOAD',
    'LD_LIBRARY_PATH',
    'DYLD_INSERT_LIBRARIES',
    'PYTHONPATH',
    'PYTHONSTARTUP',
    'PERL5LIB',
    'PERL5OPT',
    'RUBYLIB',
    'RUBYOPT',
    'JAVA_TOOL_OPTIONS',
    'JDK_JAVA_OPTIONS',
  ]);
  const safeEnv = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !UPSTREAM_INJECTOR_VARS.has(k))
  );

  const child = spawn(executable, cmdArgs, {
    stdio: ['pipe', 'pipe', 'inherit'], // control stdin/stdout; inherit stderr
    shell: false,
    env: { ...safeEnv, FORCE_COLOR: '1' },
  });

  // Track whether an authorization is in flight. If the upstream exits (or
  // agent stdin closes) while auth is pending, we defer the corresponding
  // action until auth completes so the response is flushed first.
  let authPending = false;
  let deferredExitCode: number | null = null;
  let deferredStdinEnd = false;

  // ── INTERCEPT INPUT (Agent → Gateway → Upstream) ──────────────────────────
  const agentIn = readline.createInterface({ input: process.stdin, terminal: false });

  agentIn.on('line', async (line) => {
    let message: { method?: string; id?: string | number | null; params?: Record<string, unknown> };

    try {
      const parsed = JSON.parse(line) as {
        method?: string;
        id?: unknown;
        params?: Record<string, unknown>;
      };
      // Reject messages with invalid id types — protects downstream from
      // reflected objects/arrays that could cause issues in MCP clients.
      if ('id' in parsed && !isValidId(parsed.id)) {
        const errorResponse = {
          jsonrpc: '2.0',
          id: null,
          error: {
            code: RPC_INVALID_REQUEST,
            message: 'Invalid Request: id must be string, number, or null',
          },
        };
        process.stdout.write(JSON.stringify(errorResponse) + '\n');
        return;
      }
      message = { ...parsed, id: parsed.id as string | number | null | undefined };
    } catch {
      // Non-JSON line — forward as-is (handles raw shell or malformed input)
      child.stdin.write(line + '\n');
      return;
    }

    // Only intercept tool call requests — all other messages pass through unchanged
    if (
      message.method === 'tools/call' ||
      message.method === 'call_tool' ||
      message.method === 'use_tool'
    ) {
      // Pause the stream so we don't process the next request while waiting for approval
      agentIn.pause();
      authPending = true;

      try {
        const toolName = sanitize(
          String(message.params?.name ?? message.params?.tool_name ?? 'unknown')
        );
        const toolArgs = (message.params?.arguments ?? message.params?.tool_input ?? {}) as unknown;
        const mcpServer = extractMcpServer(toolName);

        const result = await authorizeHeadless(toolName, toolArgs, {
          agent: 'MCP-Gateway',
          mcpServer,
        });

        if (!result.approved) {
          console.error(chalk.red(`\n🛑 Node9 MCP Gateway: Action Blocked`));
          console.error(chalk.gray(`   Tool: ${toolName}`));
          console.error(chalk.gray(`   Reason: ${result.reason ?? 'Security Policy'}\n`));

          const blockedByLabel = result.blockedByLabel ?? result.reason ?? 'Security Policy';
          const isHumanDecision =
            blockedByLabel.toLowerCase().includes('user') ||
            blockedByLabel.toLowerCase().includes('daemon') ||
            blockedByLabel.toLowerCase().includes('decision');

          const aiInstruction = buildNegotiationMessage(
            blockedByLabel,
            isHumanDecision,
            result.reason
          );

          const errorResponse = {
            jsonrpc: '2.0',
            id: message.id ?? null,
            error: {
              code: RPC_SERVER_ERROR,
              message: aiInstruction,
              data: { reason: result.reason, blockedBy: result.blockedByLabel },
            },
          };
          process.stdout.write(JSON.stringify(errorResponse) + '\n');
          return; // 'finally' guarantees resume + deferred exit check
        }

        // Approved — forward to upstream inside the try block so child.stdin.write
        // happens BEFORE the finally block can call child.stdin.end().
        child.stdin.write(line + '\n');
      } catch {
        // FAIL CLOSED: auth engine error → deny, never pass through
        const errorResponse = {
          jsonrpc: '2.0',
          id: message.id ?? null,
          error: {
            code: -32000,
            message: 'Node9: Security engine encountered an error. Action blocked for safety.',
          },
        };
        process.stdout.write(JSON.stringify(errorResponse) + '\n');
        return;
      } finally {
        authPending = false;
        // If agent stdin closed while we were authorizing, end the child's stdin now.
        // The approved write above (if any) has already been queued before this runs.
        // Do NOT call agentIn.resume() in this case — readline auto-closes when its
        // input stream closes, so resume() would throw ERR_USE_AFTER_CLOSE.
        if (deferredStdinEnd) {
          child.stdin.end();
        } else {
          agentIn.resume();
        }
        // If upstream exited while we were authorizing, exit now that the
        // response has been written to stdout.
        if (deferredExitCode !== null) process.exit(deferredExitCode);
      }
      return; // already forwarded inside the try block
    }

    // Non-tool-call → forward to upstream unchanged
    child.stdin.write(line + '\n');
  });

  // ── FORWARD OUTPUT (Upstream → Agent) ─────────────────────────────────────
  child.stdout.pipe(process.stdout);

  // ── LIFECYCLE ──────────────────────────────────────────────────────────────
  // Agent disconnected → close the child's stdin so it knows input is done,
  // then let it flush its remaining output and exit naturally.
  // (child.kill() would race with in-flight responses still being piped.)
  // Defer if auth is in flight — we must write the forwarded message first.
  process.stdin.on('close', () => {
    if (authPending) {
      deferredStdinEnd = true;
    } else {
      child.stdin.end();
    }
  });

  // Upstream exited → exit with the same code, but defer if auth is in flight.
  child.on('exit', (code) => {
    if (authPending) {
      deferredExitCode = code ?? 0;
    } else {
      process.exit(code ?? 0);
    }
  });
}
