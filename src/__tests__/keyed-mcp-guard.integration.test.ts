// src/__tests__/keyed-mcp-guard.integration.test.ts
// PR-2 §G rows G15-G21 + §I rows I7/I11 (MCP transport) — the MCP dispatch
// guard: on a workspace-governed machine EVERY non-readonly tool is refused
// with -32000 BEFORE the weaken gate, so a keyed machine is never advised to
// set mcpAllowWeakening in a file it does not read (matrix §0.8/§0.9).
//
// Spawns `dist/cli.js mcp-server` over stdio JSON-RPC (same harness as
// mcp-server-tools.integration.test.ts; requires `npm run build`).
//
// MUTATION PREP:
//   - removing the dispatch guard                      → every keyed refusal row
//   - guard placed AFTER the weaken gate               → 'refusal text never
//     mentions mcpAllowWeakening' (the weaken gate's text does)
//   - guard covering only 'weaken' tools, not 'add'    → shield_enable /
//     egress_protect / rule_add rows (capability 'add')
//   - mcpAllowWeakening outranking the guard (§0.9)    → G16
//   - refusal still performing the write               → store-file assertions
//   - I7/I11: status/config_get reverting to local
//     labels / readActiveShields                       → readonly keyed rows

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { keySafeEnv, writeKeyedHome } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

interface McpResponse {
  id?: number;
  result?: { content?: { type: string; text: string }[] };
  error?: { code: number; message: string };
}

function driveMcp(requests: object[], homeDir: string): Record<number, McpResponse> {
  const input = requests.map((r) => JSON.stringify(r)).join('\n') + '\n';
  const r = spawnSync(process.execPath, [CLI, 'mcp-server'], {
    input,
    encoding: 'utf-8',
    timeout: 60000,
    cwd: homeDir, // never the repo root — its node9.config.json must not leak in
    env: keySafeEnv({
      HOME: homeDir,
      USERPROFILE: homeDir,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
    }),
  });
  expect(r.error).toBeUndefined();
  const byId: Record<number, McpResponse> = {};
  for (const line of (r.stdout ?? '').split('\n').filter(Boolean)) {
    try {
      const msg = JSON.parse(line) as McpResponse;
      if (typeof msg.id === 'number') byId[msg.id] = msg;
    } catch {
      /* ignore non-JSON lines */
    }
  }
  return byId;
}

const call = (id: number, name: string, args: Record<string, unknown> = {}) => ({
  jsonrpc: '2.0',
  id,
  method: 'tools/call',
  params: { name, arguments: args },
});

const sha = (p: string) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

function makeHome(opts: { keyed: boolean; mcpAllowWeakening?: boolean }): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-mcpguard-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  if (opts.keyed) writeKeyedHome(home);
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({
      version: '1.0',
      settings: {
        autoStartDaemon: false,
        ...(opts.mcpAllowWeakening ? { mcpAllowWeakening: true } : {}),
      },
    })
  );
  fs.writeFileSync(
    path.join(home, '.node9', 'shields.json'),
    JSON.stringify({ active: ['filesystem'], overrides: {} })
  );
  fs.writeFileSync(
    path.join(home, '.node9', 'rules-cache.json'),
    JSON.stringify({
      fetchedAt: '2026-08-01T00:00:00Z',
      rules: [],
      shields: ['redis'],
      managedConfig: { locked: [] },
    })
  );
  return home;
}

const homes: string[] = [];
function home(opts: { keyed: boolean; mcpAllowWeakening?: boolean }): string {
  const h = makeHome(opts);
  homes.push(h);
  return h;
}

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build` first');
});
afterAll(() => {
  for (const h of homes) fs.rmSync(h, { recursive: true, force: true });
});

describe('§G keyed — every non-readonly MCP tool refuses with -32000, stores untouched', () => {
  it('G15/G17/G18/G19/G20: add AND weaken tools all refuse; the stores stay byte-identical', () => {
    const h = home({ keyed: true });
    const cfgSha = sha(path.join(h, '.node9', 'config.json'));
    const shieldsSha = sha(path.join(h, '.node9', 'shields.json'));
    const res = driveMcp(
      [
        call(1, 'node9_shield_enable', { service: 'postgres' }), // add   (G15)
        call(2, 'node9_shield_disable', { service: 'filesystem' }), // weaken
        call(3, 'node9_approver_set', { approver: 'cloud', enabled: false }), // weaken (G17)
        call(4, 'node9_egress_protect', { mode: 'block' }), // add   (G18)
        call(5, 'node9_egress_deny', { host: '*.evil.com' }), // add   (G19)
        call(6, 'node9_rule_add', {
          name: 'x',
          tool: 'bash',
          field: 'command',
          pattern: 'xyz',
          verdict: 'block',
          reason: 'test',
        }), // add (G20, §0.8)
      ],
      h
    );
    for (const id of [1, 2, 3, 4, 5, 6]) {
      expect(res[id]?.error, `tool call ${id} must be refused`).toBeDefined();
      expect(res[id]?.error?.code).toBe(-32000);
      expect(res[id]?.error?.message).toContain('workspace configuration');
      expect(res[id]?.error?.message).toContain('app.node9.ai');
    }
    expect(sha(path.join(h, '.node9', 'config.json'))).toBe(cfgSha);
    expect(sha(path.join(h, '.node9', 'shields.json'))).toBe(shieldsSha);
  });

  it('G21 keyed: the refusal is the guard speaking, never the weaken gate — no mcpAllowWeakening advice', () => {
    // The guard runs BEFORE the weaken gate. The weaken gate's refusal tells
    // the agent to set "mcpAllowWeakening": true in ~/.node9/config.json — a
    // file a keyed machine does not read for policy. That advice must never
    // reach a keyed agent, for the weaken tool most likely to trigger it.
    const h = home({ keyed: true });
    const res = driveMcp([call(1, 'node9_shield_disable', { service: 'redis' })], h);
    expect(res[1]?.error?.code).toBe(-32000);
    expect(res[1]?.error?.message).toContain('workspace configuration');
    expect(res[1]?.error?.message).not.toContain('mcpAllowWeakening');
  });

  it('G16: the guard OUTRANKS a local mcpAllowWeakening=true opt-in (§0.9 — local config is inert)', () => {
    const h = home({ keyed: true, mcpAllowWeakening: true });
    const shieldsSha = sha(path.join(h, '.node9', 'shields.json'));
    const res = driveMcp([call(1, 'node9_shield_disable', { service: 'filesystem' })], h);
    expect(res[1]?.error?.code).toBe(-32000);
    expect(res[1]?.error?.message).toContain('workspace configuration');
    expect(res[1]?.error?.message).not.toContain('mcpAllowWeakening');
    expect(sha(path.join(h, '.node9', 'shields.json'))).toBe(shieldsSha);
  });
});

describe('§G unkeyed twins — the known-true instruments', () => {
  it('G21 unkeyed: shield_disable gets the CLASSIC weaken-gate message, advice included', () => {
    const h = home({ keyed: false });
    const res = driveMcp([call(1, 'node9_shield_disable', { service: 'filesystem' })], h);
    expect(res[1]?.error?.code).toBe(-32000);
    expect(res[1]?.error?.message).toMatch(/weaken/i);
    expect(res[1]?.error?.message).toContain('mcpAllowWeakening');
    expect(res[1]?.error?.message).not.toContain('workspace configuration');
  });

  it('G15 unkeyed: shield_enable (add) works and mutates shields.json', () => {
    const h = home({ keyed: false });
    const res = driveMcp([call(1, 'node9_shield_enable', { service: 'postgres' })], h);
    expect(res[1]?.error).toBeUndefined();
    expect(fs.readFileSync(path.join(h, '.node9', 'shields.json'), 'utf-8')).toContain('postgres');
  });

  it('G20 unkeyed: rule_add works and lands the rule in config.json', () => {
    const h = home({ keyed: false });
    const res = driveMcp(
      [
        call(1, 'node9_rule_add', {
          name: 'block-xyz',
          tool: 'bash',
          field: 'command',
          pattern: 'xyz',
          verdict: 'block',
          reason: 'test',
        }),
      ],
      h
    );
    expect(res[1]?.error).toBeUndefined();
    expect(fs.readFileSync(path.join(h, '.node9', 'config.json'), 'utf-8')).toContain('block-xyz');
  });
});

describe('§I over MCP — readonly tools still answer, and tell the workspace truth', () => {
  it('I7 keyed: node9_status names the source, reports the ENFORCED shields, marks configs ignored', () => {
    const h = home({ keyed: true });
    const res = driveMcp(
      [call(1, 'node9_status'), call(2, 'node9_config_get'), call(3, 'node9_egress_status')],
      h
    );
    const status = res[1]?.result?.content?.[0]?.text ?? '';
    expect(status).toContain('Policy source: workspace config (app.node9.ai)');
    // appliedShields (mandated redis), NOT the local enable store (filesystem):
    expect(status).toContain('Active shields: redis');
    expect(status).not.toContain('filesystem');
    expect(status).toContain('present — ignored (workspace config governs)');
    // I11:
    const cfgGet = res[2]?.result?.content?.[0]?.text ?? '';
    expect(cfgGet).toContain('source: workspace config (app.node9.ai)');
    // I5 (MCP transport):
    const egress = res[3]?.result?.content?.[0]?.text ?? '';
    expect(egress).toContain('Source: workspace config (app.node9.ai)');
  });

  it('I8 keyed: node9_shield_list marks the mandate active and the local-only enable ignored', () => {
    const h = home({ keyed: true });
    const res = driveMcp([call(1, 'node9_shield_list')], h);
    const text = res[1]?.result?.content?.[0]?.text ?? '';
    expect(text).toContain('(workspace config governs)');
    const redisLine = text.split('\n').find((l) => /\bredis\b/.test(l)) ?? '';
    expect(redisLine).toContain('[active]');
    const fsLine = text.split('\n').find((l) => l.includes('filesystem')) ?? '';
    expect(fsLine).toContain('enabled locally, ignored');
  });

  it('I7/I8 unkeyed twins: no workspace labels; shield list renders the local enable store', () => {
    const h = home({ keyed: false });
    const res = driveMcp([call(1, 'node9_status'), call(2, 'node9_shield_list')], h);
    const status = res[1]?.result?.content?.[0]?.text ?? '';
    expect(status).not.toContain('Policy source: workspace config');
    expect(status).not.toContain('ignored (workspace config governs)');
    const list = res[2]?.result?.content?.[0]?.text ?? '';
    const fsLine = list.split('\n').find((l) => l.includes('filesystem')) ?? '';
    expect(fsLine).toContain('[active]');
    expect(list).not.toContain('workspace config governs');
  });
});
