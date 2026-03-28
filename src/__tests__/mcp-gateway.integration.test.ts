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

// Skip on Windows — stdio piping behaviour differs and spawnSync input handling
// for gateway processes is not reliable on Windows CI.
const itUnix = it.skipIf(process.platform === 'win32');

// Temp dir for the mock upstream script — cleaned up in afterAll
let mockScriptDir: string;
let mockScriptPath: string;

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(
      `dist/cli.js not found. Run "npm run build" before running integration tests.\nExpected: ${CLI}`
    );
  }

  // Write the mock upstream MCP server to a file — avoids all shell-escaping issues
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
    } else {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: {} }) + '\\n');
    }
  } catch {}
});
`
  );
});

afterAll(() => {
  try {
    fs.rmSync(mockScriptDir, { recursive: true, force: true });
  } catch {}
});

function makeTempHome(config: object): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gw-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(path.join(node9Dir, 'config.json'), JSON.stringify(config));
  return tmpHome;
}

function cleanupDir(dir: string) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e: unknown) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code !== 'EBUSY' && code !== 'ENOTEMPTY') throw e;
  }
}

function runGateway(
  inputLines: string[],
  homeDir: string,
  timeoutMs = 8000,
  upstreamScript = mockScriptPath
): { stdout: string; stderr: string; status: number | null } {
  const result = spawnSync(NODE, [CLI, 'mcp-gateway', '--upstream', `${NODE} ${upstreamScript}`], {
    input: inputLines.join('\n') + '\n',
    encoding: 'utf-8',
    timeout: timeoutMs,
    env: {
      ...process.env,
      HOME: homeDir,
      USERPROFILE: homeDir,
      NODE9_TESTING: '1',
    },
  });

  // A null status means spawnSync killed the process due to timeout — treat as
  // a test failure so a hung gateway doesn't silently pass.
  if (result.error) throw result.error;

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
      const responses = r.stdout
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as { result?: { tools?: unknown[] } });
      const listResponse = responses.find((r) => r.result && 'tools' in r.result);
      expect(listResponse).toBeDefined();
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
      const responses = r.stdout
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as { id?: number });
      expect(responses.some((r) => r.id === 1)).toBe(true);
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
            params: { name: 'read_file', arguments: { path: '/tmp/test.txt' } },
          }),
        ],
        home
      );
      expect(r.status).toBe(0);
      const responses = r.stdout
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as { id?: number; result?: unknown; error?: unknown });
      const callResponse = responses.find((r) => r.id === 42);
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
        approvalTimeoutMs: 100, // fast timeout so test doesn't hang
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
        5000
      );
      expect(r.status).toBe(0);
      const responses = r.stdout
        .split('\n')
        .filter(Boolean)
        .map(
          (l) =>
            JSON.parse(l) as {
              id?: number;
              error?: { code: number; message: string };
              result?: unknown;
            }
        );
      const errorResponse = responses.find((r) => r.id === 7);
      expect(errorResponse).toBeDefined();
      expect(errorResponse!.error).toBeDefined();
      expect(errorResponse!.error!.code).toBe(-32000);
      expect(errorResponse!.result).toBeUndefined();
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
        5000
      );
      expect(r.status).toBe(0);
      const responses = r.stdout
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as { id?: unknown; error?: unknown });
      const errorResponse = responses.find((r) => r.id === requestId);
      expect(errorResponse?.error).toBeDefined();
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
      const responses = r.stdout
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as { id?: unknown; error?: { code: number } });
      const errorResponse = responses.find((r) => r.error?.code === -32600);
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
});
