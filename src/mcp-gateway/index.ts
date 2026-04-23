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
import { hashToolDefinitions, getServerKey, checkPin, updatePin } from '../mcp-pin';
import type { McpToolInfo } from '../daemon/mcp-tools';
import { getServerConfig } from '../daemon/mcp-tools';
import { DAEMON_PORT, DAEMON_HOST, isDaemonRunning, getInternalToken } from '../auth/daemon';
import { readActiveShields } from '../shields';

/** Wait for human approval of new MCP tools. Polls daemon for status change. */
async function waitForMcpApproval(
  serverKey: string
): Promise<{ status: string; disabled: string[] }> {
  const token = getInternalToken();
  const start = Date.now();
  const timeout = 60_000; // 60s timeout

  while (Date.now() - start < timeout) {
    try {
      const res = await fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/mcp/status/${serverKey}`, {
        headers: token ? { 'x-node9-internal': token } : {},
      });
      if (res.ok) {
        const config = (await res.json()) as { status: string; disabled: string[] };
        if (config.status === 'approved') return config;
      }
    } catch {
      // Daemon might be down — fail open after timeout
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return { status: 'timed-out', disabled: [] };
}

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

  // ── Tool pinning state ────────────────────────────────────────────────────
  // Track tools/list request IDs so we can intercept the upstream's response
  // and verify tool definitions against the pinned hash.
  const pendingToolsListIds = new Set<string | number | null>();
  const serverKey = getServerKey(upstreamCommand);

  // Session quarantine: tracks whether pin validation has passed for this session.
  // 'pending'    — no tools/list response checked yet; tools/call blocked
  // 'validated'  — pin check passed (new or match); tools/call allowed
  // 'quarantined' — pin mismatch or corrupt pin file; tools/call permanently blocked
  let pinState: 'pending' | 'validated' | 'quarantined' = 'pending';

  // Queue for tool call lines that arrive while pin validation is pending.
  // These are replayed (in order) once pin validation completes.
  const pendingToolCalls: string[] = [];

  // Maps in-flight tool call id → tool name so the response handler can
  // attribute large responses to the tool that triggered them.
  const pendingCallNames = new Map<string | number, string>();

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

    // Track tools/list request IDs so we can verify the response against pinned hashes.
    if (message.method === 'tools/list' && message.id !== undefined && message.id !== null) {
      pendingToolsListIds.add(message.id);
    }

    // Only intercept tool call requests — all other messages pass through unchanged
    if (
      message.method === 'tools/call' ||
      message.method === 'call_tool' ||
      message.method === 'use_tool'
    ) {
      // ── Session quarantine gate ──────────────────────────────────────────
      // Block tool calls if pin validation hasn't passed or if the session
      // is quarantined due to a mismatch / corrupt pin file.
      if (pinState === 'quarantined') {
        // Notifications (no id) must not receive a response per JSON-RPC spec.
        if (message.id === undefined || message.id === null) return;
        const errorResponse = {
          jsonrpc: '2.0',
          id: message.id,
          error: {
            code: RPC_SERVER_ERROR,
            message:
              'Node9 Security: This MCP session is quarantined due to a tool definition mismatch or corrupt pin state. ' +
              'The human operator must review and approve changes before tool calls are allowed. ' +
              `Run: node9 mcp pin update ${serverKey}`,
            data: { reason: 'pin-quarantine', serverKey, pinState },
          },
        };
        process.stdout.write(JSON.stringify(errorResponse) + '\n');
        return;
      }
      if (pinState === 'pending') {
        if (pendingToolsListIds.size > 0) {
          // A tools/list is in flight — queue and replay after pin validation.
          pendingToolCalls.push(line);
          return;
        }
        // No tools/list in flight — client skipped verification entirely.
        // Notifications (no id) are silently dropped per JSON-RPC spec.
        if (message.id === undefined || message.id === null) return;
        const errorResponse = {
          jsonrpc: '2.0',
          id: message.id,
          error: {
            code: RPC_SERVER_ERROR,
            message:
              'Node9 Security: Tool calls are blocked until MCP tool definitions have been verified. ' +
              'The client must issue a tools/list request before calling tools.',
            data: { reason: 'pin-quarantine', serverKey, pinState },
          },
        };
        process.stdout.write(JSON.stringify(errorResponse) + '\n');
        return;
      }

      // Pause the stream so we don't process the next request while waiting for approval.
      // Guard against ERR_USE_AFTER_CLOSE: when drainPendingToolCalls replays queued calls
      // after stdin has already closed, agentIn is closed and pause() would throw.
      if (!deferredStdinEnd) agentIn.pause();
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
        if (message.id !== undefined && message.id !== null) {
          pendingCallNames.set(message.id as string | number, toolName);
        }
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

  // ── Queue drain ────────────────────────────────────────────────────────────
  // Replay tool call lines that were queued while pin validation was pending.
  // Called from the upstream output handler after pin state is resolved.
  function drainPendingToolCalls(): void {
    if (pendingToolCalls.length === 0) {
      // No queued calls. If stdin already closed, end child stdin now.
      if (deferredStdinEnd && !authPending) child.stdin.end();
      return;
    }
    const lines = pendingToolCalls.splice(0);
    for (const queuedLine of lines) {
      // Re-emit the line so the agentIn handler processes it again.
      // pinState is now resolved, so the quarantine gate will either
      // allow (validated) or block (quarantined) each queued call.
      agentIn.emit('line', queuedLine);
    }
    // If all queued calls were blocked (quarantined) and no auth is pending,
    // end child stdin since the deferred close was never resolved.
    if (deferredStdinEnd && !authPending) child.stdin.end();
  }

  // ── FORWARD OUTPUT (Upstream → Agent) ─────────────────────────────────────
  // Replaced pipe with readline to intercept tools/list responses for pin checking.
  // All non-tools/list messages pass through unchanged (transparent proxy).
  const upstreamOut = readline.createInterface({ input: child.stdout, terminal: false });
  upstreamOut.on('line', async (line) => {
    // Try to parse as JSON to check for tools/list response
    type UpstreamMessage = {
      id?: string | number | null;
      result?: { tools?: unknown[] };
      error?: unknown;
    };
    let parsed: UpstreamMessage | undefined;
    try {
      parsed = JSON.parse(line) as UpstreamMessage;
    } catch {
      // Not JSON — forward as-is (transparent proxy contract)
    }

    if (!parsed) {
      process.stdout.write(line + '\n');
      return;
    }

    // Check if this is a response to a tracked tools/list request
    if (parsed.id !== undefined && pendingToolsListIds.has(parsed.id!)) {
      pendingToolsListIds.delete(parsed.id!);

      // Only check pins and apply filtering on successful responses that contain tools
      if (parsed.result && Array.isArray(parsed.result.tools)) {
        const tools = (parsed.result.tools as McpToolInfo[]) || [];
        const currentHash = hashToolDefinitions(tools);
        const pinStatus = checkPin(serverKey, currentHash);
        const token = getInternalToken();

        // 1. Notify daemon of discovery (handles drift & new servers)
        if (isDaemonRunning() && process.env.NODE9_TESTING !== '1') {
          const toolSummary = tools.map((t) => ({ name: t.name, description: t.description }));
          fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/mcp/discovered`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(token && { 'x-node9-internal': token }),
            },
            body: JSON.stringify({ serverKey, tools: toolSummary }),
          }).catch(() => {
            /* silent */
          });
        }

        // 2. Intercept & Hold — only when mcp-tool-gating shield is active
        const serverCfg = getServerConfig(serverKey);
        const gatingEnabled = readActiveShields().includes('mcp-tool-gating');
        if (gatingEnabled && isDaemonRunning() && (!serverCfg || serverCfg.status === 'pending')) {
          const config = await waitForMcpApproval(serverKey);
          if (config.disabled.length > 0) {
            parsed.result.tools = tools.filter((t) => !config.disabled.includes(t.name));
            line = JSON.stringify(parsed);
          }
        } else if (serverCfg?.disabled && serverCfg.disabled.length > 0) {
          // Already approved — apply persisted filter immediately
          parsed.result.tools = tools.filter((t) => !serverCfg.disabled.includes(t.name));
          line = JSON.stringify(parsed);
        }

        if (pinStatus === 'new') {
          // First connection — pin the tool definitions
          const toolNames = tools
            .map((t: unknown) => ((t as Record<string, unknown>).name as string) ?? 'unknown')
            .sort();
          updatePin(serverKey, upstreamCommand, currentHash, toolNames);
          pinState = 'validated';

          console.error(
            chalk.green(
              `🔒 Node9: Pinned ${toolNames.length} tool definition(s) for this MCP server`
            )
          );
          // Forward the response — first use is trusted
          process.stdout.write(line + '\n');
          drainPendingToolCalls();
        } else if (pinStatus === 'match') {
          // Pin matches — forward unchanged
          pinState = 'validated';
          process.stdout.write(line + '\n');
          drainPendingToolCalls();
        } else if (pinStatus === 'corrupt') {
          // Pin file is corrupt — fail closed, quarantine the session
          pinState = 'quarantined';
          console.error(
            chalk.red('\n🚨 Node9: MCP pin file is corrupt or unreadable — session quarantined!')
          );
          console.error(chalk.red('   Tool calls are blocked until the pin file is repaired.'));
          console.error(
            chalk.yellow(`   Run: node9 mcp pin reset  (to clear and re-pin on next connect)\n`)
          );
          const errorResponse = {
            jsonrpc: '2.0',
            id: parsed.id,
            error: {
              code: RPC_SERVER_ERROR,
              message:
                'Node9 Security: MCP pin file is corrupt or unreadable. ' +
                'Tool definitions cannot be verified. Session quarantined. ' +
                'The human operator must repair or reset the pin file. ' +
                'Run: node9 mcp pin reset',
              data: { reason: 'pin-file-corrupt', serverKey },
            },
          };
          process.stdout.write(JSON.stringify(errorResponse) + '\n');
          drainPendingToolCalls();
        } else {
          // MISMATCH — possible rug pull attack. Block the response, quarantine session.
          pinState = 'quarantined';
          console.error(
            chalk.red('\n🚨 Node9: MCP tool definitions have changed since last verified!')
          );
          console.error(
            chalk.red('   This could indicate a supply chain attack (tool poisoning / rug pull).')
          );
          console.error(chalk.red('   Session quarantined — all tool calls blocked.'));
          console.error(chalk.yellow(`   Run: node9 mcp pin update ${serverKey}\n`));
          const errorResponse = {
            jsonrpc: '2.0',
            id: parsed.id,
            error: {
              code: RPC_SERVER_ERROR,
              message:
                'Node9 Security: MCP server tool definitions have changed since they were last pinned. ' +
                'This could indicate a supply chain attack (tool poisoning / rug pull). ' +
                'Session quarantined — all tool calls are blocked. ' +
                'The human operator must review and approve the changes. ' +
                `Run: node9 mcp pin update ${serverKey}`,
              data: { reason: 'tool-pin-mismatch', serverKey },
            },
          };
          process.stdout.write(JSON.stringify(errorResponse) + '\n');
          drainPendingToolCalls();
        }
        return;
      }
    }

    // Detect oversized tool call responses and notify the daemon dashboard.
    // Threshold: 500KB — only fires on genuinely large payloads (full DB dumps,
    // massive directory listings). Normal responses are a few KB at most.
    const LARGE_RESPONSE_THRESHOLD = 500_000;
    if (parsed?.result && line.length > LARGE_RESPONSE_THRESHOLD) {
      const callId = parsed.id as string | number | undefined;
      const toolName =
        callId !== undefined ? (pendingCallNames.get(callId) ?? 'unknown') : 'unknown';
      if (callId !== undefined) pendingCallNames.delete(callId);
      console.error(
        chalk.yellow(
          `⚡ Node9: Large MCP response from '${toolName}' (${(line.length / 1024).toFixed(0)}KB) — context window enlarged`
        )
      );
      if (isDaemonRunning() && process.env.NODE9_TESTING !== '1') {
        const token = getInternalToken();
        fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/mcp/large-response`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(token && { 'x-node9-internal': token }),
          },
          body: JSON.stringify({ toolName, serverKey, originalBytes: line.length }),
        }).catch(() => {});
      }
    } else if (parsed?.id !== undefined && parsed.id !== null) {
      pendingCallNames.delete(parsed.id as string | number);
    }

    // All other messages — forward unchanged
    process.stdout.write(line + '\n');
  });

  // ── LIFECYCLE ──────────────────────────────────────────────────────────────
  // Agent disconnected → close the child's stdin so it knows input is done,
  // then let it flush its remaining output and exit naturally.
  // (child.kill() would race with in-flight responses still being piped.)
  // Defer if auth is in flight — we must write the forwarded message first.
  process.stdin.on('close', () => {
    if (authPending || pendingToolCalls.length > 0) {
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
