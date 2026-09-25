/**
 * DLP-3 at the real gate: `node9 mcp-gateway`, a fake upstream MCP server that
 * COUNTS the tool calls it executes, and a fake SaaS standing in for the cloud
 * approver. The unit spec (dlp-review-survives-routing.spec.ts) proves each
 * guard on the authorizer with a mocked cloud; this file proves the property
 * the guards exist for, on the shipped binary:
 *
 *   no upstream execution before a genuine approval,
 *   none on a denial,
 *   exactly one after a human approves.
 *
 * Three runs, one per cloud answer:
 *   1. {pending:false, approved:true}  the "no org rule matched" auto-allow
 *      that used to resolve a DLP review -> the call is denied, count 0
 *   2. {pending:true} then status DENIED -> denied, count 0
 *   3. {pending:true} then status APPROVED -> forwarded, count exactly 1
 *
 * Both fakes are separate processes: the gateway is driven with spawnSync,
 * which blocks this process's event loop, so an in-process HTTP server could
 * never answer it. Design: doc/roadmap/active/dlp-fixes-design.md, 2.5.
 *
 * Requirements: `npm run build` first (dist/cli.js); skipped on Windows like
 * its sibling (stdio piping).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const NODE = process.execPath;

const cliExists = fs.existsSync(CLI);
if (!cliExists) {
  console.warn(
    `[mcp-gateway-dlp] All integration tests skipped — dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`
  );
}
if (process.platform === 'win32') {
  console.warn(
    '[mcp-gateway-dlp] All integration tests skipped on Windows — stdio piping not supported'
  );
}
const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);

// Review-severity pattern (Bearer Token), by construction so no scanner reads
// this file as a leak. NOT in assignment context: contextBoost would promote
// it to block severity and the gate would deny before the cloud is consulted.
const FAKE_BEARER = 'Bearer ' + 'Xm7Kp3Qn9Bt2Vc6' + 'Wr1Ys4Zh8Pq5Nv3M';

let scriptDir: string;
let upstreamScript: string;
let saasScript: string;

beforeAll(() => {
  if (!cliExists) return;
  scriptDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gw-dlp-'));

  // The upstream: lists one tool, and appends one line to COUNT_FILE for every
  // tools/call it EXECUTES. The count file is the whole point of the suite.
  upstreamScript = path.join(scriptDir, 'upstream.js');
  fs.writeFileSync(
    upstreamScript,
    `
const fs = require('fs');
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
      fs.appendFileSync(process.env.COUNT_FILE, 'executed\\n');
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0', id: msg.id,
        result: { content: [{ type: 'text', text: 'upstream:' + JSON.stringify(msg.params) }] }
      }) + '\\n');
    } else if (msg.id !== undefined && msg.id !== null) {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: {} }) + '\\n');
    }
  } catch {}
});
`
  );

  // The SaaS: argv[2] is the answer it gives, argv[3] the file it writes its
  // port to once listening, argv[4] a log of every request (method, path, and
  // whether the intercept carried forceReview). Any bearer is accepted; there
  // is no credential here to protect.
  saasScript = path.join(scriptDir, 'saas.js');
  fs.writeFileSync(
    saasScript,
    `
const http = require('http');
const fs = require('fs');
const [mode, portFile, logFile] = process.argv.slice(2);
const log = (o) => fs.appendFileSync(logFile, JSON.stringify(o) + '\\n');
const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const send = (o) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (req.method === 'POST') {
      let parsed = {};
      try { parsed = JSON.parse(body); } catch {}
      log({ method: 'POST', path: req.url, forceReview: parsed.forceReview === true, toolName: parsed.toolName });
      if (mode === 'immediate-allow') return send({ pending: false, approved: true });
      return send({ pending: true, requestId: 'req-' + mode });
    }
    if (req.method === 'GET' && req.url.includes('/status/')) {
      log({ method: 'GET', path: req.url });
      return send({ status: mode === 'pending-approve' ? 'APPROVED' : 'DENIED', reason: 'fake saas' });
    }
    log({ method: req.method, path: req.url });
    return send({ ok: true });
  });
});
server.listen(0, '127.0.0.1', () => {
  fs.writeFileSync(portFile, String(server.address().port));
});
`
  );
});

afterAll(() => {
  if (!scriptDir) return;
  fs.rmSync(scriptDir, { recursive: true, force: true });
});

type SaasHandle = { proc: ChildProcess; port: number; logFile: string };

/** Start the fake SaaS in its own process and wait for its port. */
async function startSaas(mode: string, dir: string): Promise<SaasHandle> {
  const portFile = path.join(dir, `saas-${mode}.port`);
  const logFile = path.join(dir, `saas-${mode}.log`);
  fs.writeFileSync(logFile, '');
  const proc = spawn(NODE, [saasScript, mode, portFile, logFile], { stdio: 'ignore' });
  const deadline = Date.now() + 5000;
  while (!fs.existsSync(portFile)) {
    if (Date.now() > deadline) {
      proc.kill();
      throw new Error('fake SaaS did not start');
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  return { proc, port: Number(fs.readFileSync(portFile, 'utf-8')), logFile };
}

/** A temp HOME with the cloud approver on and every local approver off.
 *  `localOnly` keeps the machine on its local config (the `node9 login
 *  --local` shape), so these settings are the ones that apply. A short
 *  approval timeout lets a refused cloud answer resolve as a deny instead of
 *  waiting for an approver that does not exist. */
function makeHome(port: number): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gw-dlp-home-'));
  const dir = path.join(home, '.node9');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'config.json'),
    JSON.stringify({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 2500,
        approvers: { native: false, browser: false, cloud: true, terminal: false },
      },
      policy: { dlp: { enabled: true, scanIgnoredTools: true } },
    })
  );
  fs.writeFileSync(
    path.join(dir, 'credentials.json'),
    JSON.stringify({
      default: {
        apiKey: 'nk_test_0000',
        apiUrl: `http://127.0.0.1:${port}/api/v1/intercept`,
        localOnly: true,
      },
    })
  );
  return home;
}

type GatewayResponse = {
  id?: unknown;
  result?: { [key: string]: unknown; content?: unknown[] };
  error?: { code: number; message: string };
};

function runGateway(
  home: string,
  countFile: string
): { responses: GatewayResponse[]; stderr: string; status: number | null } {
  // Same env hygiene as mcp-gateway.integration.test.ts: no NODE9_* leaking
  // in from the developer's shell, no module-injection variables.
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
  const lines = [
    // Pin validation: tools/list must come before any tools/call.
    JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    JSON.stringify({
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'echo', arguments: { text: FAKE_BEARER } },
    }),
  ];
  const result = spawnSync(
    NODE,
    [CLI, 'mcp-gateway', '--upstream', `"${NODE}" "${upstreamScript}"`],
    {
      input: lines.join('\n') + '\n',
      encoding: 'utf-8',
      timeout: 20000,
      env: {
        ...cleanEnv,
        HOME: home,
        USERPROFILE: home,
        NODE9_TESTING: '1',
        COUNT_FILE: countFile,
      },
    }
  );
  if (result.error) throw result.error;
  if (result.status === null) {
    throw new Error(
      `Gateway did not exit cleanly\n  stdout: ${JSON.stringify((result.stdout ?? '').slice(0, 500))}\n  stderr: ${(result.stderr ?? '').slice(0, 500)}`
    );
  }
  const responses = (result.stdout ?? '')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as GatewayResponse);
  return { responses, stderr: result.stderr ?? '', status: result.status };
}

const executions = (countFile: string): number =>
  fs.existsSync(countFile)
    ? fs.readFileSync(countFile, 'utf-8').split('\n').filter(Boolean).length
    : 0;

const saasLog = (h: SaasHandle): Array<Record<string, unknown>> =>
  fs
    .readFileSync(h.logFile, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);

const auditRows = (home: string): Array<Record<string, unknown>> => {
  const file = path.join(home, '.node9', 'audit.log');
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
};

describe('mcp-gateway: a DLP credential review reaches a human, at the real gate', () => {
  async function scenario(mode: string) {
    const saas = await startSaas(mode, scriptDir);
    const home = makeHome(saas.port);
    const countFile = path.join(home, 'executions.log');
    try {
      const r = runGateway(home, countFile);
      return {
        r,
        saas,
        home,
        count: executions(countFile),
        log: saasLog(saas),
        audit: auditRows(home),
      };
    } finally {
      saas.proc.kill();
      // home is removed by the caller after its assertions
    }
  }

  itUnix(
    'the SaaS auto-allow ("no org rule matched") does not run the tool',
    async () => {
      const s = await scenario('immediate-allow');
      try {
        expect(s.r.status).toBe(0);
        const call = s.r.responses.find((x) => x.id === 7);
        expect(call?.error).toBeDefined();
        expect(call?.result).toBeUndefined();
        expect(s.count).toBe(0);
        // and the gateway asked for a genuine pending entry
        // The first POST is the shipper's tool-pin row on /audit; the intercept
        // is the one that names the tool.
        const intercept = s.log.find((e) => e.method === 'POST' && e.toolName === 'echo');
        expect(intercept?.forceReview).toBe(true);
        expect(intercept?.toolName).toBe('echo');
        // the audit trail says what was found, before and after the decision
        expect(s.audit.some((row) => row.checkedBy === 'dlp-review-flagged')).toBe(true);
        expect(
          s.audit.some((row) => row.decision === 'deny' && row.dlpPattern === 'Bearer Token')
        ).toBe(true);
        // and never the secret
        expect(JSON.stringify(s.audit)).not.toContain(FAKE_BEARER.slice('Bearer '.length));
      } finally {
        fs.rmSync(s.home, { recursive: true, force: true });
      }
    },
    30000
  );

  itUnix(
    'a human denial does not run the tool',
    async () => {
      const s = await scenario('pending-deny');
      try {
        expect(s.r.status).toBe(0);
        const call = s.r.responses.find((x) => x.id === 7);
        expect(call?.error).toBeDefined();
        expect(s.count).toBe(0);
        expect(s.log.some((e) => e.method === 'GET')).toBe(true); // it polled the pending entry
      } finally {
        fs.rmSync(s.home, { recursive: true, force: true });
      }
    },
    30000
  );

  itUnix(
    'a human approval runs the tool exactly once',
    async () => {
      const s = await scenario('pending-approve');
      try {
        expect(s.r.status).toBe(0);
        const call = s.r.responses.find((x) => x.id === 7);
        expect(call?.error).toBeUndefined();
        expect(call?.result?.content).toBeDefined();
        expect(s.count).toBe(1);
      } finally {
        fs.rmSync(s.home, { recursive: true, force: true });
      }
    },
    30000
  );
});
