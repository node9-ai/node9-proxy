/**
 * Integration tests for `node9 mcp-gateway`.
 *
 * Verifies the gateway's core contract:
 *   1. stdout stays clean JSON-RPC — no banner or log lines on stdout
 *   2. Non-tool-call messages (initialize, tools/list) pass through unchanged
 *   3. tools/call for a blocked tool → JSON-RPC error on stdout, not a crash
 *   4. tools/call for an allowed tool → forwarded to upstream, result returned
 *   5. Startup banner goes to stderr, never stdout
 *
 * The upstream MCP server is a small Node.js script written to a temp file
 * so there are no shell escaping issues with --upstream.
 *
 * Requirements:
 *   - `npm run build` must be run before these tests (suite checks for dist/cli.js)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const NODE = process.execPath;

// Two conditions skip the entire suite:
//   1. dist/cli.js not built yet — warn and skip rather than a confusing suite-level failure.
//   2. Windows — stdio piping behaviour and spawnSync input handling differ; not supported.
// Log both explicitly so CI doesn't silently report zero tests executed.
const cliExists = fs.existsSync(CLI);
if (!cliExists) {
  console.warn(
    `[mcp-gateway] All integration tests skipped — dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`
  );
}
if (process.platform === 'win32') {
  console.warn(
    '[mcp-gateway] All integration tests skipped on Windows — stdio piping not supported'
  );
}
const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);

let mockScriptDir: string;
let mockScriptPath: string;

beforeAll(() => {
  if (!cliExists) return; // already warned above

  // Write the mock upstream MCP server to a file — avoids all shell-escaping issues.
  // The mock uses process.stdout.write (unbuffered in Node.js) so the gateway's
  // pipe always receives responses without needing an explicit flush. Tests that
  // replace this mock with a custom upstream must preserve this property.
  mockScriptDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gw-mock-'));
  mockScriptPath = path.join(mockScriptDir, 'upstream.js');
  fs.writeFileSync(
    mockScriptPath,
    `
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.method === 'tools/list') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0', id: msg.id,
        result: { tools: [{ name: 'echo', description: 'Echo', inputSchema: { type: 'object' } }] }
      }) + '\\n');
    } else if (msg.method === 'tools/call') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0', id: msg.id,
        result: { content: [{ type: 'text', text: 'upstream:' + JSON.stringify(msg.params) }] }
      }) + '\\n');
    } else if (msg.id !== undefined && msg.id !== null) {
      // Only respond to requests (have an id). Notifications have no id and
      // must not get a response — writing one would be invalid JSON-RPC.
      // Note: id===0 is a valid JSON-RPC id; it passes both checks correctly.
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: {} }) + '\\n');
    }
  } catch (err) {
    // Write to stderr so test failures surface the actual parse error rather
    // than hanging on a missing response. Never write to stdout (breaks protocol).
    process.stderr.write('[mock-upstream] line parse error: ' + err + '\\n');
  }
});
`
  );
});

afterAll(() => {
  // mockScriptDir is only set when cliExists — guard to avoid a noisy
  // "path must be a string" error in afterAll when the suite is skipped.
  if (!mockScriptDir) return;
  try {
    fs.rmSync(mockScriptDir, { recursive: true, force: true });
  } catch (e) {
    // Don't silently swallow — leaked temp dirs accumulate in CI.
    process.stderr.write(`[node9-gw-test] afterAll cleanup failed: ${e}\n`);
  }
});

function makeTempHome(config: object): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gw-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(path.join(node9Dir, 'config.json'), JSON.stringify(config));
  return tmpHome;
}

function cleanupDir(dir: string) {
  // force:true suppresses ENOENT (already gone — fine). Any other error (EBUSY,
  // ENOTEMPTY, EPERM) propagates and surfaces as a test isolation failure.
  fs.rmSync(dir, { recursive: true, force: true });
}

/** Shared shape for every JSON-RPC message on stdout. */
type GatewayResponse = {
  id?: unknown;
  jsonrpc?: string;
  // Index signature first, then named properties — avoids the redundant
  // `Record<string, unknown> & {...}` intersection pattern.
  result?: { [key: string]: unknown; tools?: unknown[]; ok?: boolean };
  error?: { code: number; message: string; data?: unknown };
};

/** Parse all non-empty stdout lines as JSON-RPC responses. */
function parseResponses(stdout: string): GatewayResponse[] {
  return stdout
    .split('\n')
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l) as GatewayResponse;
      } catch (e) {
        throw new Error(
          `parseResponses: non-JSON line on gateway stdout: ${JSON.stringify(l)}\n  cause: ${e}`
        );
      }
    });
}

function runGateway(
  inputLines: string[],
  homeDir: string,
  timeoutMs = 5000,
  upstreamScript = mockScriptPath
): { stdout: string; stderr: string; status: number | null } {
  // Strip vars that could inject code into the gateway subprocess:
  //   NODE9_*                  — prevent local developer config leaking in
  //   NODE_OPTIONS / NODE_PATH — Node.js require-hook and module-path injection
  //   LD_PRELOAD / LD_LIBRARY_PATH — shared-library injection on Linux
  //   DYLD_INSERT_LIBRARIES    — shared-library injection on macOS
  //   PYTHONPATH / PYTHONSTARTUP — Python module-path and startup-script injection
  //   PERL5LIB / PERL5OPT      — Perl module-path and option injection
  //   RUBYLIB / RUBYOPT        — Ruby load-path and option injection
  //   JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS — JVM agent injection for Java MCP servers
  //   XDG_CONFIG_HOME / XDG_DATA_HOME — XDG base dirs; some tools resolve config
  //     through these instead of HOME; strip to prevent local config bleed-in
  // PATH is kept: all spawns use absolute paths (NODE, CLI) so the ambient
  // PATH cannot inject a different binary.
  // TMPDIR is intentionally kept — os.tmpdir() uses it to create test temp dirs.
  const INJECTOR_VARS = new Set([
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
    'XDG_CONFIG_HOME',
    'XDG_DATA_HOME',
  ]);
  const cleanEnv = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !k.startsWith('NODE9_') && !INJECTOR_VARS.has(k))
  );
  // NODE9_TESTING=1: suppresses native/browser/terminal UI approvers so tests
  // don't open dialogs. Policy evaluation, DLP, smart rules, and shields all run
  // unchanged — see src/auth/orchestrator.ts isTestEnv block for the exact effect.
  // Quote both tokens so paths with spaces (e.g. macOS home dirs) don't confuse the tokenizer.
  // Known limitation: spawnSync buffers stdin before the process starts. If the upstream's
  // response exceeds the OS pipe buffer (~64 KB) before stdin is consumed, a deadlock is
  // theoretically possible. The mock upstream responses are small so this is not a concern
  // in practice, but real upstream servers with large outputs should use spawn() instead.
  const result = spawnSync(
    NODE,
    [CLI, 'mcp-gateway', '--upstream', `"${NODE}" "${upstreamScript}"`],
    {
      input: inputLines.join('\n') + '\n',
      encoding: 'utf-8',
      timeout: timeoutMs,
      env: {
        ...cleanEnv,
        HOME: homeDir,
        USERPROFILE: homeDir,
        NODE9_TESTING: '1',
      },
    }
  );

  // A spawnSync error (e.g. ETIMEDOUT) means the process was killed — fail fast.
  if (result.error) throw result.error;
  // status===null means the process was killed by a signal or timed out.
  // On some platforms signal may also be null in this case — treat both as failure
  // so a hung/killed gateway doesn't silently appear to pass.
  // Include partial output to make timeout failures diagnosable.
  if (result.status === null) {
    // signal===null with status===null means the process timed out (spawnSync timeout
    // hit), not that it was killed by a signal. Distinguish the two for clear CI output.
    const reason =
      result.signal != null ? `killed by signal ${result.signal}` : `timed out (>${timeoutMs}ms)`;
    throw new Error(
      `Gateway process did not exit cleanly (${reason})\n` +
        `  stdout: ${result.stdout ? JSON.stringify(result.stdout.slice(0, 500)) : '(empty)'}\n` +
        `  stderr: ${result.stderr ? result.stderr.slice(0, 500) : '(empty)'}`
    );
  }

  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    status: result.status,
  };
}

// ── stdout cleanliness ─────────────────────────────────────────────────────────

describe('mcp-gateway stdout cleanliness', () => {
  itUnix('startup banner goes to stderr, not stdout', () => {
    const home = makeTempHome({ settings: { mode: 'audit' } });
    try {
      const r = runGateway(
        [JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })],
        home
      );
      expect(r.status).toBe(0);
      expect(r.stderr).toMatch(/MCP Gateway/);
      // stdout must only contain valid JSON lines — no banner text
      for (const line of r.stdout.split('\n').filter(Boolean)) {
        expect(() => JSON.parse(line), `stdout line is not JSON: ${line}`).not.toThrow();
      }
    } finally {
      cleanupDir(home);
    }
  });
});

// ── pass-through messages ──────────────────────────────────────────────────────

describe('mcp-gateway pass-through', () => {
  itUnix('tools/list passes through to upstream and returns tool list', () => {
    const home = makeTempHome({ settings: { mode: 'audit' } });
    try {
      const r = runGateway(
        [JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })],
        home
      );
      expect(r.status).toBe(0);
      const responses = parseResponses(r.stdout);
      const listResponse = responses.find((resp) => resp.result && 'tools' in resp.result);
      expect(listResponse).toBeDefined();
      expect(listResponse!.result!.tools).toBeDefined();
      expect(Array.isArray(listResponse!.result!.tools)).toBe(true);
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('initialize message passes through unchanged', () => {
    const home = makeTempHome({ settings: { mode: 'audit' } });
    try {
      const r = runGateway(
        [
          JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: { protocolVersion: '2024-11-05', capabilities: {} },
          }),
        ],
        home
      );
      expect(r.status).toBe(0);
      const responses = parseResponses(r.stdout);
      expect(responses.some((resp) => resp.id === 1)).toBe(true);
    } finally {
      cleanupDir(home);
    }
  });
});

// ── tool call interception ─────────────────────────────────────────────────────

describe('mcp-gateway tool call interception', () => {
  itUnix('allowed tool call (ignored tool) is forwarded and returns upstream result', () => {
    // 'read_file' is explicitly in ignoredTools — passes through without approval prompt
    const home = makeTempHome({
      settings: { mode: 'standard', autoStartDaemon: false },
      policy: { ignoredTools: ['read_file'] },
    });
    try {
      const r = runGateway(
        [
          JSON.stringify({
            jsonrpc: '2.0',
            id: 42,
            method: 'tools/call',
            params: { name: 'read_file', arguments: { path: '/nonexistent/node9-test-only' } },
          }),
        ],
        home
      );
      // The mock upstream echoes back whatever params it receives — it never reads
      // from disk, so the path argument is irrelevant. /nonexistent/node9-test-only
      // makes it explicit that this is a synthetic test path with no real target.
      expect(r.status).toBe(0);
      const responses = parseResponses(r.stdout);
      const callResponse = responses.find((resp) => resp.id === 42);
      expect(callResponse).toBeDefined();
      // Should have a result (forwarded to upstream), not an error
      expect(callResponse!.result).toBeDefined();
      expect(callResponse!.error).toBeUndefined();
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('blocked tool call returns JSON-RPC error with code -32000', () => {
    // In test env (NODE9_TESTING=1) all UI is disabled and no daemon runs —
    // a dangerous tool with no approval mechanism returns noApprovalMechanism:true
    // which the gateway converts to a JSON-RPC error.
    const home = makeTempHome({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        // approvalTimeoutMs is 100ms; give the gateway 2000ms total to leave
        // enough overhead while keeping the test tight. If the auth engine hangs
        // instead of rejecting, the test will fail with a clear timeout error.
        approvalTimeoutMs: 100,
        approvers: { native: false, browser: false, terminal: false, cloud: false },
      },
    });
    try {
      const r = runGateway(
        [
          JSON.stringify({
            jsonrpc: '2.0',
            id: 7,
            method: 'tools/call',
            params: { name: 'mkfs_format', arguments: { device: '/dev/sda' } },
          }),
        ],
        home,
        2000
      );
      expect(r.status).toBe(0);
      const responses = parseResponses(r.stdout);
      const errorResponse = responses.find((resp) => resp.id === 7);
      expect(errorResponse).toBeDefined();
      expect(errorResponse!.error).toBeDefined();
      expect(errorResponse!.error!.code).toBe(-32000);
      expect(errorResponse!.result).toBeUndefined();
      // Upstream isolation: only one response for this id — if the gateway also
      // forwarded the message, the mock upstream would echo back a second response
      // with a `result`, which would appear as a duplicate id=7 on stdout.
      expect(responses.filter((resp) => resp.id === 7)).toHaveLength(1);
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('error response preserves original request id', () => {
    const home = makeTempHome({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 100,
        approvers: { native: false, browser: false, terminal: false, cloud: false },
      },
    });
    try {
      const requestId = 'test-uuid-123';
      const r = runGateway(
        [
          JSON.stringify({
            jsonrpc: '2.0',
            id: requestId,
            method: 'tools/call',
            params: { name: 'mkfs_format', arguments: {} },
          }),
        ],
        home,
        2000
      );
      expect(r.status).toBe(0);
      const responses = parseResponses(r.stdout);
      const errorResponse = responses.find((resp) => resp.id === requestId);
      expect(errorResponse?.error).toBeDefined();
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('DLP blocks tool call containing a credential in arguments', () => {
    // Build the fake key at runtime so the DLP scanner doesn't flag this source file.
    // The gateway's DLP sees the assembled string and blocks it.
    const fakeKey = ['sk-ant-', 'api03-', 'A'.repeat(40)].join('');
    const home = makeTempHome({ settings: { mode: 'standard', autoStartDaemon: false } });
    try {
      const r = runGateway(
        [
          JSON.stringify({
            jsonrpc: '2.0',
            id: 99,
            method: 'tools/call',
            params: { name: 'write_file', arguments: { path: '/tmp/x.txt', content: fakeKey } },
          }),
        ],
        home
      );
      expect(r.status).toBe(0);
      const responses = parseResponses(r.stdout);
      const errorResponse = responses.find((resp) => resp.id === 99);
      expect(errorResponse?.error).toBeDefined();
      expect(errorResponse!.error!.code).toBe(-32000);
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('id: 0 is a valid JSON-RPC id and gets a normal response', () => {
    // id===0 is a valid JSON-RPC id (number). Must not be treated as a notification
    // (id===undefined) or rejected — both would be protocol violations.
    const home = makeTempHome({ settings: { mode: 'audit' } });
    try {
      const r = runGateway(
        [JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'tools/list', params: {} })],
        home
      );
      expect(r.status).toBe(0);
      const responses = parseResponses(r.stdout);
      const resp = responses.find((r) => r.id === 0);
      expect(resp).toBeDefined();
      expect(resp!.result).toBeDefined();
      expect(resp!.error).toBeUndefined();
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('invalid JSON-RPC id type returns -32600 error with id:null', () => {
    const home = makeTempHome({ settings: { mode: 'audit' } });
    try {
      // id is an object — invalid per JSON-RPC spec; gateway must not reflect it
      const r = runGateway(
        [
          JSON.stringify({
            jsonrpc: '2.0',
            id: { nested: 'object' },
            method: 'tools/list',
            params: {},
          }),
        ],
        home
      );
      expect(r.status).toBe(0);
      const responses = parseResponses(r.stdout);
      const errorResponse = responses.find((resp) => resp.error?.code === -32600);
      expect(errorResponse).toBeDefined();
      expect(errorResponse!.id).toBeNull();
    } finally {
      cleanupDir(home);
    }
  });
});

// ── resilience ─────────────────────────────────────────────────────────────────

describe('mcp-gateway resilience', () => {
  itUnix('upstream emitting invalid JSON is forwarded as-is (transparent proxy)', () => {
    // The gateway is a transparent proxy for upstream output — it does not parse
    // or validate upstream responses. Invalid JSON from upstream reaches the client
    // so the client can handle or log it. This is intentional: we only intercept
    // inbound tool calls, never outbound responses.
    const home = makeTempHome({ settings: { mode: 'audit' } });
    const badUpstreamScript = path.join(mockScriptDir, 'bad-upstream.js');
    fs.writeFileSync(badUpstreamScript, `process.stdout.write('not-valid-json\\n');\n`);
    try {
      const r = runGateway(
        [JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })],
        home,
        8000,
        badUpstreamScript
      );
      // Gateway must not crash — exit 0 or propagate upstream's code
      expect(r.status).not.toBeNull();
      // The invalid line is forwarded unchanged (transparent proxy contract)
      expect(r.stdout).toContain('not-valid-json');
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('upstream script path with spaces is handled correctly', () => {
    // parseCommandString must handle quoted paths — space in script path must not
    // be split into two separate arguments.
    const spaceyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9 gw spaces '));
    const spaceyScript = path.join(spaceyDir, 'upstream.js');
    fs.writeFileSync(
      spaceyScript,
      `const rl = require('readline').createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.id !== undefined && msg.id !== null) {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { ok: true } }) + '\\n');
    }
  } catch {}
});
`
    );
    const home = makeTempHome({ settings: { mode: 'audit' } });
    try {
      // Wrap the path in quotes so parseCommandString treats it as one token
      const quotedPath = `"${spaceyScript}"`;
      const result = spawnSync(
        NODE,
        [CLI, 'mcp-gateway', '--upstream', `"${NODE}" ${quotedPath}`],
        {
          input: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) + '\n',
          encoding: 'utf-8',
          timeout: 8000,
          env: { ...process.env, HOME: home, USERPROFILE: home, NODE9_TESTING: '1' },
        }
      );
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(0);
      const responses = parseResponses(result.stdout);
      expect(responses.some((resp) => resp.id === 1)).toBe(true);
    } finally {
      cleanupDir(home);
      cleanupDir(spaceyDir);
    }
  });

  itUnix('upstream that exits immediately produces no gateway crash', () => {
    // Upstream exits before responding to any request.
    // Gateway propagates the exit code and does not crash or hang.
    const home = makeTempHome({ settings: { mode: 'audit' } });
    const crashScript = path.join(mockScriptDir, 'crash-upstream.js');
    fs.writeFileSync(crashScript, `process.exit(1);\n`);
    try {
      const r = runGateway(
        [JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })],
        home,
        8000,
        crashScript
      );
      // Gateway exits cleanly — status is not null (not a timeout/hang)
      expect(r.status).not.toBeNull();
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('malformed (non-JSON) input line is forwarded to upstream as-is', () => {
    // The gateway must not crash on non-JSON stdin — it forwards malformed lines
    // directly to the upstream (transparent proxy contract for non-parseable input).
    const home = makeTempHome({ settings: { mode: 'audit' } });
    try {
      // Send a bad line followed by a valid request so we get stdout output
      const r = runGateway(
        [
          'not-valid-json',
          JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
        ],
        home
      );
      expect(r.status).toBe(0);
      // The valid tools/list request must still get a response
      const responses = parseResponses(r.stdout);
      const listResponse = responses.find((resp) => resp.result && 'tools' in resp.result);
      expect(listResponse).toBeDefined();
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('injection env vars are stripped from the upstream subprocess environment', () => {
    // The gateway must not pass NODE_OPTIONS, PYTHONPATH, PERL5LIB, RUBYLIB, etc.
    // to the upstream child — an attacker who controls these can inject code into
    // any Node.js, Python, Perl, or Ruby MCP server.
    // Verify by running an upstream that echoes its own env into the response.
    const envEchoScript = path.join(mockScriptDir, 'env-echo.js');
    fs.writeFileSync(
      envEchoScript,
      `const rl = require('readline').createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.id !== undefined && msg.id !== null) {
      const envKeys = Object.keys(process.env);
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0', id: msg.id,
        result: { envKeys }
      }) + '\\n');
    }
  } catch {}
});
`
    );
    const home = makeTempHome({ settings: { mode: 'audit' } });
    try {
      // Inject sentinel values for each injection var into the gateway's env.
      // The gateway should strip them before passing env to the upstream.
      // Inject language-specific vars as sentinels — these don't affect the gateway
      // (a Node.js process) but must be stripped before passing env to the upstream.
      // NODE_OPTIONS / LD_PRELOAD are intentionally excluded here: setting them to
      // bad values would crash the gateway subprocess itself, not just the upstream.
      // The production strip list covers all vars; this test validates the mechanism
      // for the interpreter-specific ones that are safe to inject into the test env.
      const result = spawnSync(
        NODE,
        [CLI, 'mcp-gateway', '--upstream', `"${NODE}" "${envEchoScript}"`],
        {
          input: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) + '\n',
          encoding: 'utf-8',
          timeout: 8000,
          env: {
            ...process.env,
            HOME: home,
            USERPROFILE: home,
            NODE9_TESTING: '1',
            // Sentinels — gateway must strip these before spawning upstream
            PYTHONPATH: '/evil/py',
            PYTHONSTARTUP: '/evil/startup.py',
            PERL5LIB: '/evil/perl',
            PERL5OPT: '-M/evil',
            RUBYLIB: '/evil/ruby',
            RUBYOPT: '-r/evil',
          },
        }
      );
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(0);
      const responses = parseResponses(result.stdout);
      const envResponse = responses.find((r) => r.id === 1);
      expect(envResponse?.result).toBeDefined();
      const envKeys = envResponse!.result!['envKeys'] as string[];
      expect(Array.isArray(envKeys)).toBe(true);
      // None of the injected sentinel vars should appear in the upstream's env
      const stripped = [
        'PYTHONPATH',
        'PYTHONSTARTUP',
        'PERL5LIB',
        'PERL5OPT',
        'RUBYLIB',
        'RUBYOPT',
      ];
      for (const v of stripped) {
        expect(envKeys, `${v} should be stripped from upstream env`).not.toContain(v);
      }
    } finally {
      cleanupDir(home);
    }
  });

  itUnix('tools/call notification (no id) is forwarded and generates no gateway response', () => {
    // JSON-RPC notifications have no id. The gateway must forward them to upstream
    // (so the server can act on them) but must not generate a response of its own,
    // because responding to a notification is a protocol violation.
    const home = makeTempHome({
      settings: { mode: 'standard', autoStartDaemon: false },
      policy: { ignoredTools: ['notify_tool'] },
    });
    try {
      const r = runGateway(
        [
          // notification — no id field
          JSON.stringify({
            jsonrpc: '2.0',
            method: 'tools/call',
            params: { name: 'notify_tool', arguments: {} },
          }),
          // follow-up request so we get stdout output to inspect
          JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'tools/list', params: {} }),
        ],
        home
      );
      expect(r.status).toBe(0);
      const responses = parseResponses(r.stdout);
      // The follow-up tools/list must arrive
      expect(responses.some((resp) => resp.result && 'tools' in resp.result)).toBe(true);
      // No response should carry id:null as a result of the notification
      // (an error response with id:null is only valid for parse/invalid-request errors)
      const nullIdResults = responses.filter((resp) => resp.id === null && resp.result);
      expect(nullIdResults).toHaveLength(0);
    } finally {
      cleanupDir(home);
    }
  });
});
