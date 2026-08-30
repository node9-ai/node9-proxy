// src/__tests__/keyed-write-guard.integration.test.ts
// PR-2 §G — the CLI write-guard, end to end (rows G1-G14, G23, G24 of
// doc/roadmap/active/one-config-pr2-test-matrix.md).
//
// Contract per KEYED row: exit code ≠ 0, the refusal names the workspace
// configuration + the dashboard, and the target store is byte-identical
// (sha256 of every file under ~/.node9 — the standing sha256-not-diff-stat
// rule; a refusal may not even CREATE a store). Per UNKEYED row the same
// command works exactly as today (exit 0, store mutated) — the known-true
// instruments that make every "refused" row meaningful.
//
// Spawns the real dist/cli.js (requires `npm run build`), temp HOME per
// describe, keyedness by FILE via writeKeyedHome (§0.12 — never by env
// inheritance).
//
// MUTATION PREP:
//   - guard removed from ONE command family (the gauntlet
//     lesson: a floor keyed on one mandate type)          → one row per family
//   - "guard prints but exits 0"                          → status !== 0 rows
//   - guard checks rules-cache presence, not policySource → keyed-NO-cache row
//   - guard re-derives keyedness ignoring localOnly       → G23
//   - guard reads only the creds file, missing env keys   → G24
//   - refusal still performs the write                    → sha256 snapshots
//
// NOT covered here (needs a live daemon / real cloud): none — every §G CLI row
// is spawnable. MCP rows G15-G21 live in keyed-mcp-guard.integration.test.ts.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { keySafeEnv, writeKeyedHome } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(home: string, args: string[], extraEnv: Record<string, string> = {}): RunResult {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: home, // never the repo root — its node9.config.json must not leak in
    env: keySafeEnv({
      HOME: home,
      USERPROFILE: home,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      NO_COLOR: '1',
      ...extraEnv,
    }),
  });
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

/** sha256 of every file under <home>/.node9, keyed by relative path — the
 *  refusal contract is "no store changed AND no store appeared". */
function snapshotStores(home: string): Record<string, string> {
  const root = path.join(home, '.node9');
  const out: Record<string, string> = {};
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else
        out[path.relative(root, p)] = crypto
          .createHash('sha256')
          .update(fs.readFileSync(p))
          .digest('hex');
    }
  };
  walk(root);
  return out;
}

/** A keyed home carrying EVERY local policy store the guarded commands target,
 *  so "byte-identical after refusal" is a real assertion for each family. */
function makeKeyedHome(opts: { cache?: boolean } = { cache: true }): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-wguard-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  writeKeyedHome(home);
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ version: '1.0', settings: { autoStartDaemon: false } })
  );
  fs.writeFileSync(
    path.join(home, '.node9', 'shields.json'),
    JSON.stringify({ active: ['filesystem'], overrides: {} })
  );
  fs.writeFileSync(
    path.join(home, '.node9', 'jail-paths.json'),
    JSON.stringify({ paths: [{ path: '/tmp/secrets', verdict: 'block' }] })
  );
  fs.writeFileSync(
    path.join(home, '.node9', 'trusted-hosts.json'),
    JSON.stringify({ hosts: [{ host: 'pre.example.com', addedAt: 1, addedBy: 'user' }] })
  );
  if (opts.cache !== false) {
    fs.writeFileSync(
      path.join(home, '.node9', 'rules-cache.json'),
      JSON.stringify({
        fetchedAt: '2026-08-01T00:00:00Z',
        rules: [],
        shields: ['redis'],
        managedConfig: { locked: [] },
      })
    );
  }
  return home;
}

function makeUnkeyedHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-wguard-un-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  return home;
}

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build` first');
});

describe('§G keyed — every policy-write family refuses and leaves the stores byte-identical', () => {
  let home: string;
  let before: Record<string, string>;

  beforeAll(() => {
    home = makeKeyedHome();
    before = snapshotStores(home);
  });
  afterAll(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  const expectRefused = (r: RunResult) => {
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('workspace configuration');
    expect(r.stderr).toContain('app.node9.ai');
    expect(snapshotStores(home)).toEqual(before);
  };

  // G1-G5 egress (config.json)
  it('G1: egress watch refused', () => expectRefused(runCli(home, ['egress', 'watch'])));
  it('G2: egress lock refused', () => expectRefused(runCli(home, ['egress', 'lock'])));
  it('G3: egress allow refused', () =>
    expectRefused(runCli(home, ['egress', 'allow', 'h.example.com'])));
  it('G4: egress deny refused', () =>
    expectRefused(runCli(home, ['egress', 'deny', 'h.example.com'])));
  it('G5: egress off refused — the weakening direction fails loudly too', () =>
    expectRefused(runCli(home, ['egress', 'off'])));

  // G6-G10 shields (shields.json / shield-overrides / ~/.node9/shields/)
  it('G6: shield enable refused', () =>
    expectRefused(runCli(home, ['shield', 'enable', 'postgres'])));
  it('G7: shield disable refused', () =>
    expectRefused(runCli(home, ['shield', 'disable', 'filesystem'])));
  it('G8: shield set refused', () =>
    expectRefused(runCli(home, ['shield', 'set', 'redis', 'block-flushall', 'allow', '--force'])));
  it('G9: shield unset refused', () =>
    expectRefused(runCli(home, ['shield', 'unset', 'redis', 'block-flushall'])));
  it('G10: shield install refused (before any network fetch)', () =>
    expectRefused(runCli(home, ['shield', 'install', 'some-shield'])));

  // G11-G12 jail (jail-paths.json + user-jail shield)
  it('G11: jail add refused', () => expectRefused(runCli(home, ['jail', 'add', '/tmp/x'])));
  it('G12: jail remove refused', () =>
    expectRefused(runCli(home, ['jail', 'remove', '/tmp/secrets'])));

  // G13-G14 trust (trusted-hosts.json)
  it('G13: trust add refused', () =>
    expectRefused(runCli(home, ['trust', 'add', 'api.example.com'])));
  it('G14: trust remove refused', () =>
    expectRefused(runCli(home, ['trust', 'remove', 'pre.example.com'])));
});

describe('§G keyed variants — how keyedness is detected', () => {
  it('keyed with NO rules-cache still refuses (mutant: guard keyed on cache presence)', () => {
    const home = makeKeyedHome({ cache: false });
    const before = snapshotStores(home);
    const r = runCli(home, ['egress', 'lock']);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('workspace configuration');
    expect(snapshotStores(home)).toEqual(before);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('G24: an env-only key (CI shape — no credentials.json) refuses through the same seam', () => {
    const home = makeUnkeyedHome();
    const r = runCli(home, ['egress', 'lock'], { NODE9_API_KEY: 'n9_ci_key' });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('workspace configuration');
    expect(fs.existsSync(path.join(home, '.node9', 'config.json'))).toBe(false);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('G23: a localOnly key (`login --local`) keeps FULL local write control', () => {
    const home = makeUnkeyedHome();
    writeKeyedHome(home, { localOnly: true });
    const r = runCli(home, ['egress', 'lock']);
    expect(r.status).toBe(0);
    const cfg = JSON.parse(fs.readFileSync(path.join(home, '.node9', 'config.json'), 'utf-8')) as {
      policy?: { egress?: { enabled?: boolean; mode?: string } };
    };
    expect(cfg.policy?.egress?.enabled).toBe(true);
    expect(cfg.policy?.egress?.mode).toBe('block');
    fs.rmSync(home, { recursive: true, force: true });
  });
});

describe('§G unkeyed twins — the known-true instruments (same commands, no key, must mutate)', () => {
  let home: string;
  beforeAll(() => {
    home = makeUnkeyedHome();
  });
  afterAll(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('egress lock works and writes policy.egress into config.json', () => {
    const r = runCli(home, ['egress', 'lock']);
    expect(r.status).toBe(0);
    expect(r.stderr).not.toContain('workspace configuration');
    const cfg = JSON.parse(fs.readFileSync(path.join(home, '.node9', 'config.json'), 'utf-8')) as {
      policy?: { egress?: { enabled?: boolean; mode?: string } };
    };
    expect(cfg.policy?.egress?.enabled).toBe(true);
    expect(cfg.policy?.egress?.mode).toBe('block');
  });

  it('egress off works (the weakening twin — G5 instrument)', () => {
    const r = runCli(home, ['egress', 'off']);
    expect(r.status).toBe(0);
    const cfg = JSON.parse(fs.readFileSync(path.join(home, '.node9', 'config.json'), 'utf-8')) as {
      policy?: { egress?: { enabled?: boolean } };
    };
    expect(cfg.policy?.egress?.enabled).toBe(false);
  });

  it('shield enable postgres works and lands in shields.json', () => {
    const r = runCli(home, ['shield', 'enable', 'postgres']);
    expect(r.status).toBe(0);
    expect(fs.readFileSync(path.join(home, '.node9', 'shields.json'), 'utf-8')).toContain(
      'postgres'
    );
  });

  it('trust add works and lands in trusted-hosts.json', () => {
    const r = runCli(home, ['trust', 'add', 'api.example.com']);
    expect(r.status).toBe(0);
    expect(fs.readFileSync(path.join(home, '.node9', 'trusted-hosts.json'), 'utf-8')).toContain(
      'api.example.com'
    );
  });

  it('jail add works and lands in jail-paths.json', () => {
    const r = runCli(home, ['jail', 'add', '/tmp/x']);
    expect(r.status).toBe(0);
    const store = JSON.parse(
      fs.readFileSync(path.join(home, '.node9', 'jail-paths.json'), 'utf-8')
    ) as { paths?: Array<{ path: string }> };
    expect(store.paths?.some((p) => p.path === '/tmp/x')).toBe(true);
  });
});
