/**
 * Enforcement round-trip e2e — the one green that means "a block actually blocks".
 *
 * test-robustness-plan P0a. Every prior test covers one half of the control plane
 * with the other half mocked; this suite exercises the WHOLE local enforcement
 * chain with real components end to end:
 *
 *   dashboard sets a per-tool decision            (simulated: we write the REAL
 *     → sync stores it in ~/.node9/rules-cache.json  sync artifact, byte-shape
 *       under managedConfig.appPermissions           identical — the only mocked
 *     → getConfig() applies it to config.policy      seam is the HTTP fetch)
 *     → the REAL mcp-gateway (dist/cli.js) receives a REAL JSON-RPC tools/call
 *       for the BARE upstream tool name (the shape that killed the dead gate)
 *     → authorizeHeadless denies / forwards
 *     → the audit row records the decision + app-permission attribution.
 *
 * Round trip: block → denied; flip the artifact to allow → forwarded to the
 * upstream. Each phase is a fresh gateway spawn, which mirrors production: a
 * sync updates rules-cache.json and the next authorize reads the new config.
 *
 * Companion suites: gate-contract.matrix.test.ts (P0b — real HOOK payloads per
 * agent) and mcp-gateway.integration.test.ts (protocol/shield behavior).
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const NODE = process.execPath;

const cliExists = fs.existsSync(CLI);
if (!cliExists) {
  console.warn(
    `[enforcement-roundtrip] suite skipped — dist/cli.js not found. Run "npm run build".`
  );
}
if (process.platform === 'win32') {
  console.warn('[enforcement-roundtrip] suite skipped on Windows — stdio piping not supported');
}
const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);

// ── Real-ish upstream MCP server (file-based; same convention as the gateway
//    integration suite: unbuffered stdout writes, newline-delimited JSON-RPC) ──
let upstreamScript: string;
const tmpDirs: string[] = [];

beforeAll(() => {
  if (!cliExists) return;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-roundtrip-mock-'));
  tmpDirs.push(dir);
  upstreamScript = path.join(dir, 'upstream.js');
  fs.writeFileSync(
    upstreamScript,
    `
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    if (msg.method === 'initialize') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id,
        result: { protocolVersion: '2024-11-05', capabilities: { tools: {} },
                  serverInfo: { name: 'roundtrip-upstream', version: '1.0.0' } } }) + '\\n');
    } else if (msg.method === 'tools/list') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id,
        result: { tools: [
          { name: 'read_file',  description: 'Read a file',  inputSchema: { type: 'object' } },
          { name: 'write_file', description: 'Write a file', inputSchema: { type: 'object' } }
        ] } }) + '\\n');
    } else if (msg.method === 'tools/call') {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id,
        result: { content: [{ type: 'text', text: 'UPSTREAM-EXECUTED:' + msg.params.name }] } }) + '\\n');
    } else if (msg.id !== undefined && msg.id !== null) {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: {} }) + '\\n');
    }
  } catch (e) { process.stderr.write('[mock] ' + e + '\\n'); }
});
`
  );
});

afterEach(() => {
  for (const d of tmpDirs.splice(1)) {
    try {
      fs.rmSync(d, { recursive: true, force: true });
    } catch {
      /* non-fatal leak */
    }
  }
});

/** The gateway keys everything by sha256(upstreamCommand)[:16] — the SAME string
 *  passed to --upstream. This is the serverKey the dashboard's Connected Apps
 *  page stores decisions under (pin hash). */
function serverKeyFor(upstreamCmd: string): string {
  return crypto.createHash('sha256').update(upstreamCmd).digest('hex').slice(0, 16);
}

/** Write a temp HOME whose rules-cache.json is the REAL sync artifact shape:
 *  what /policies/sync stores after an admin sets a decision in Connected Apps. */
function makeHome(appPermissions: Record<string, Record<string, string>> | null): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-roundtrip-home-'));
  tmpDirs.push(home);
  const node9Dir = path.join(home, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(
    path.join(node9Dir, 'config.json'),
    JSON.stringify({ settings: { mode: 'standard', autoStartDaemon: false } })
  );
  if (appPermissions) {
    fs.writeFileSync(
      path.join(node9Dir, 'rules-cache.json'),
      JSON.stringify({ rules: [], managedConfig: { appPermissions } })
    );
  }
  return home;
}

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

interface RpcResponse {
  id?: number;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
}

function runGateway(inputLines: string[], home: string): { responses: RpcResponse[]; raw: string } {
  const cleanEnv = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !k.startsWith('NODE9_') && !INJECTOR_VARS.has(k))
  );
  const upstreamCmd = `"${NODE}" "${upstreamScript}"`;
  const r = spawnSync(NODE, [CLI, 'mcp-gateway', '--upstream', upstreamCmd], {
    input: inputLines.join('\n') + '\n',
    encoding: 'utf-8',
    timeout: 20000,
    env: { ...cleanEnv, HOME: home, USERPROFILE: home, NODE9_TESTING: '1' },
  });
  if (r.error) throw r.error;
  if (r.status === null) {
    throw new Error(
      `gateway did not exit: ${r.signal ?? 'timeout'}\nstderr: ${(r.stderr ?? '').slice(0, 400)}`
    );
  }
  const responses = (r.stdout ?? '')
    .split('\n')
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l) as RpcResponse;
      } catch {
        return null;
      }
    })
    .filter((x): x is RpcResponse => x !== null);
  return { responses, raw: r.stdout ?? '' };
}

const CALL_SEQUENCE = (tool: string) => [
  JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
  JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
  JSON.stringify({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    // BARE tool name + arbitrary args — exactly what a stdio gateway forwards.
    params: { name: tool, arguments: { path: '/tmp/x' } },
  }),
];

function lastAuditRows(home: string, n: number): Array<Record<string, unknown>> {
  const p = path.join(home, '.node9', 'audit.log');
  if (!fs.existsSync(p)) return [];
  const lines = fs.readFileSync(p, 'utf-8').trim().split('\n');
  return lines.slice(-n).map((l) => JSON.parse(l) as Record<string, unknown>);
}

describe('enforcement round-trip: managed app-permission → real gateway', () => {
  itUnix('block decision denies the real tools/call — and the flip to allow forwards it', () => {
    const upstreamCmd = `"${NODE}" "${upstreamScript}"`;
    const serverKey = serverKeyFor(upstreamCmd);

    // ── Phase 1: the dashboard set read_file → block; the sync stored it. ──
    const homeBlocked = makeHome({ [serverKey]: { read_file: 'block' } });
    const blocked = runGateway(CALL_SEQUENCE('read_file'), homeBlocked);

    const callResp = blocked.responses.find((resp) => resp.id === 3);
    expect(callResp, `no tools/call response.\nraw: ${blocked.raw}`).toBeDefined();
    // Denied at the gate: a JSON-RPC ERROR, and the upstream must never run.
    expect(callResp!.error, `expected deny, got: ${JSON.stringify(callResp)}`).toBeDefined();
    expect(blocked.raw).not.toContain('UPSTREAM-EXECUTED:read_file');

    // The deny is attributable: audit row carries the app-permission rule.
    const denyRow = lastAuditRows(homeBlocked, 3).find((row) => row.decision === 'deny');
    expect(denyRow, 'blocked call must write a deny audit row').toBeDefined();
    expect(JSON.stringify(denyRow)).toContain('app-permission:read_file');

    // A sibling tool with NO decision passes through — the block is per-tool,
    // not per-server (the failure mode where a gate over-blocks).
    const siblingHome = makeHome({ [serverKey]: { read_file: 'block' } });
    const sibling = runGateway(CALL_SEQUENCE('write_file'), siblingHome);
    expect(sibling.raw).toContain('UPSTREAM-EXECUTED:write_file');

    // ── Phase 2: the admin flips read_file → allow; the next sync applies. ──
    const homeAllowed = makeHome({ [serverKey]: { read_file: 'allow' } });
    const allowed = runGateway(CALL_SEQUENCE('read_file'), homeAllowed);

    const allowResp = allowed.responses.find((resp) => resp.id === 3);
    expect(allowResp, `no tools/call response.\nraw: ${allowed.raw}`).toBeDefined();
    expect(allowResp!.error, `expected allow, got error: ${JSON.stringify(allowResp)}`).toBe(
      undefined
    );
    // The upstream really executed — enforcement released, end to end.
    expect(allowed.raw).toContain('UPSTREAM-EXECUTED:read_file');
  });

  itUnix('a decision for a DIFFERENT serverKey does not leak onto this server', () => {
    // Cross-server isolation: the dead-gate bug family includes key-mismatch
    // (decisions keyed one way, gate looking them up another). A block stored
    // under some other server's key must NOT deny this server's call.
    const otherKey = serverKeyFor('"node" "/some/other/server.js"');
    const home = makeHome({ [otherKey]: { read_file: 'block' } });
    const r = runGateway(CALL_SEQUENCE('read_file'), home);
    expect(r.raw).toContain('UPSTREAM-EXECUTED:read_file');
  });

  itUnix('no managed artifact at all → tools/call passes through (fail-open sync)', () => {
    // A machine that has never synced has no rules-cache.json. The gate must
    // not deny on the ABSENCE of the artifact (fail-open on missing config —
    // availability), only on an explicit decision.
    const home = makeHome(null);
    const r = runGateway(CALL_SEQUENCE('read_file'), home);
    expect(r.raw).toContain('UPSTREAM-EXECUTED:read_file');
  });
});
