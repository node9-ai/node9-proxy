/**
 * node9Firewall#376 item 6, phase 3, at the real gateway: `node9 mcp-gateway`
 * in front of a fake upstream that COUNTS the tool calls it executes, in a
 * HOME whose policy cache holds the workspace's approved list of add-ons.
 * The server's identity is the one the add-ons report gives it (here
 * `script:upstream.js`, from the upstream launch command).
 *
 *   blocked server       -> JSON-RPC error, nothing executed
 *   approved server      -> executed once, even under the `block` rule
 *   unapproved + block   -> JSON-RPC error that says how to get it approved
 *
 * Requirements: `npm run build` first (dist/cli.js); skipped on Windows.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { indexKey, shardOf, writeMeta, writeShard } from '../supply-chain/osv-index';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const NODE = process.execPath;
const cliExists = fs.existsSync(CLI);
const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);

let scriptDir: string;
let upstreamScript: string;

beforeAll(() => {
  scriptDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gw-addon-'));
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
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id,
        result: { tools: [{ name: 'echo', description: 'Echo', inputSchema: { type: 'object' } }] } }) + '\\n');
    } else if (msg.method === 'tools/call') {
      fs.appendFileSync(process.env.COUNT_FILE, 'executed\\n');
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id,
        result: { content: [{ type: 'text', text: 'ok' }] } }) + '\\n');
    } else if (msg.id !== undefined && msg.id !== null) {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: {} }) + '\\n');
    }
  } catch {}
});
`
  );
});

afterAll(() => {
  fs.rmSync(scriptDir, { recursive: true, force: true });
});

function makeHome(addons: object): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gw-addon-home-'));
  const dir = path.join(home, '.node9');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'config.json'),
    JSON.stringify({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 0,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
      policy: {},
    })
  );
  fs.writeFileSync(
    path.join(dir, 'rules-cache.json'),
    JSON.stringify({
      fetchedAt: new Date().toISOString(),
      rules: [],
      managedConfig: { addons, locked: [] },
    })
  );
  return home;
}

type Response = { id?: unknown; result?: unknown; error?: { message: string } };

function runGateway(home: string, countFile: string): Response[] {
  const cleanEnv = Object.fromEntries(
    Object.entries(process.env).filter(
      ([k]) => !k.startsWith('NODE9_') && k !== 'NODE_OPTIONS' && k !== 'LD_PRELOAD'
    )
  );
  const input =
    [
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      JSON.stringify({
        jsonrpc: '2.0',
        id: 7,
        method: 'tools/call',
        params: { name: 'echo', arguments: { text: 'hi' } },
      }),
    ].join('\n') + '\n';
  const r = spawnSync(NODE, [CLI, 'mcp-gateway', '--upstream', `"${NODE}" "${upstreamScript}"`], {
    input,
    encoding: 'utf-8',
    timeout: 20000,
    env: { ...cleanEnv, HOME: home, USERPROFILE: home, NODE9_TESTING: '1', COUNT_FILE: countFile },
  });
  if (r.error) throw r.error;
  expect(r.status).not.toBeNull();
  return (r.stdout ?? '')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Response);
}

function run(addons: object): { call: Response | undefined; executed: number } {
  const home = makeHome(addons);
  const countFile = path.join(home, 'count');
  try {
    const responses = runGateway(home, countFile);
    const executed = fs.existsSync(countFile)
      ? fs.readFileSync(countFile, 'utf-8').split('\n').filter(Boolean).length
      : 0;
    return { call: responses.find((x) => x.id === 7), executed };
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
}

const list = (p: object) => ({ unapproved: 'log', mcp: {}, skills: {}, plugins: {}, ...p });

describe('the approved list of add-ons at the MCP gateway (phase 3)', () => {
  itUnix('a blocked server: the call errors and the upstream never runs it', () => {
    const { call, executed } = run(list({ mcp: { 'script:upstream.js': 'blocked' } }));
    expect(call?.error?.message).toContain('script:upstream.js');
    expect(executed).toBe(0);
  });

  itUnix('an approved server runs, even when unapproved add-ons are blocked', () => {
    const { call, executed } = run(
      list({ unapproved: 'block', mcp: { 'script:upstream.js': 'approved' } })
    );
    expect(call?.error).toBeUndefined();
    expect(executed).toBe(1);
  });

  itUnix('a server nobody approved, under the block rule: stopped, with the way out', () => {
    const { call, executed } = run(list({ unapproved: 'block' }));
    expect(call?.error?.message).toContain('Add-ons page');
    expect(executed).toBe(0);
  });
});

// Phase 4, check D: the gateway starts the server, so it can refuse to. The
// upstream is the real shape (`npx -y <package>`); a stand-in `npx` first on
// PATH records whether it was ever started.
describe('an MCP server whose package is on the malicious list, at the gateway', () => {
  const PKG = '@node9-test/malicious-mcp';

  function start(seed: (home: string) => void): {
    status: number | null;
    started: boolean;
    err: string;
  } {
    const home = makeHome({});
    fs.rmSync(path.join(home, '.node9', 'rules-cache.json'));
    const bin = path.join(home, 'bin');
    fs.mkdirSync(bin);
    const marker = path.join(home, 'started');
    fs.writeFileSync(path.join(bin, 'npx'), `#!/bin/sh\necho started > "${marker}"\n`, {
      mode: 0o755,
    });
    seed(home);
    const cleanEnv = Object.fromEntries(
      Object.entries(process.env).filter(
        ([k]) => !k.startsWith('NODE9_') && k !== 'NODE_OPTIONS' && k !== 'LD_PRELOAD'
      )
    );
    try {
      const r = spawnSync(NODE, [CLI, 'mcp-gateway', '--upstream', `npx -y ${PKG}`], {
        input: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) + '\n',
        encoding: 'utf-8',
        timeout: 20000,
        env: {
          ...cleanEnv,
          HOME: home,
          USERPROFILE: home,
          NODE9_TESTING: '1',
          PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
        },
      });
      if (r.error) throw r.error;
      return { status: r.status, started: fs.existsSync(marker), err: r.stderr ?? '' };
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  }

  /** A record in the local malicious-package index that covers every version. */
  function indexMalicious(home: string): void {
    const prevHome = process.env.HOME;
    const prevProfile = process.env.USERPROFILE;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    try {
      const key = indexKey('npm', PKG);
      writeShard('npm', shardOf(key), { [key]: [{ id: 'MAL-2026-7', all: true }] });
      writeMeta('npm', {
        syncedAt: new Date().toISOString(),
        lastModifiedMs: Date.now(),
        records: 1,
        mode: 'full',
      });
    } finally {
      process.env.HOME = prevHome;
      process.env.USERPROFILE = prevProfile;
    }
  }

  itUnix('is never started, and the gateway says why', () => {
    const r = start(indexMalicious);
    expect(r.started).toBe(false);
    expect(r.status).toBe(1);
    expect(r.err).toContain('MAL-2026-7');
  });

  itUnix('a package with no record is started as before', () => {
    const r = start(() => {});
    expect(r.started).toBe(true);
  });

  itUnix('is started when the user switched the package check off', () => {
    const r = start((home) => {
      indexMalicious(home);
      const cfg = path.join(home, '.node9', 'config.json');
      const c = JSON.parse(fs.readFileSync(cfg, 'utf-8')) as { policy: object };
      c.policy = { packageCheck: { enabled: false } };
      fs.writeFileSync(cfg, JSON.stringify(c));
    });
    expect(r.started).toBe(true);
  });
});
