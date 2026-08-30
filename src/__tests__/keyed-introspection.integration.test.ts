// src/__tests__/keyed-introspection.integration.test.ts
// PR-2 §I — introspection tells the ONE truth (getConfig().policySource),
// end to end over the real dist/cli.js (requires `npm run build`).
//
// Rows covered here: I1 (status), I2 (status cloud line — keyed default
// approvers.cloud=true renders Agent mode), I3 (doctor), I5 (egress status
// source line), I8 (shield list / status / config show), I10 (jail list).
// I4 (explain waterfall) is unit-covered in keyed-explain-waterfall.spec.ts.
//
// Rows SKIPPED here, with reasons:
//   - I6 (check fallback label 'Workspace Policy'): the fallback only renders
//     for a verdict with neither blockedByLabel nor blockedBy — the engine
//     always labels its verdicts, so the branch is unreachable from a spawned
//     `node9 check` without a daemon-approval fixture. Left to the daemon lane.
//   - I7 / I11 (MCP node9_status / node9_config_get): covered in
//     keyed-mcp-guard.integration.test.ts (same spawn, MCP transport).
//   - I9 (HUD GET /status mode): needs a LIVE daemon serving HTTP.
//   - I12 (posture scores under cloud policy): posture has its own suite
//     (posture-governance.spec) — the keyed lane there needs scorecard
//     fixtures out of scope for this write-guard PR.
//
// MUTATION PREP:
//   - dropping a wsGoverned branch on any surface   → its keyed row
//   - inverting the branch (unkeyed says ignored)   → the unkeyed twin rows
//   - swapping appliedShields back to
//     readActiveShields in shield status            → 'mandated redis renders'
//   - shield list keyed cloud column losing the
//     enforced set                                  → the it.fails pin below

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { keySafeEnv, writeKeyedHome } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function runCli(home: string, args: string[]): { status: number | null; out: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: home,
    env: keySafeEnv({
      HOME: home,
      USERPROFILE: home,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      NO_COLOR: '1',
    }),
  });
  expect(result.error).toBeUndefined();
  // Several of these surfaces print to stderr by design (shield status,
  // config show) — assert on the combined stream.
  return { status: result.status, out: `${result.stdout ?? ''}${result.stderr ?? ''}` };
}

/** One fixture, two keyednesses: every local policy store present + a cloud
 *  cache mandating redis. The keyed home adds ONLY credentials.json. */
function makeHome(keyed: boolean): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-intro-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  if (keyed) writeKeyedHome(home);
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ version: '1.0', settings: { autoStartDaemon: false } })
  );
  // Project config in cwd (= home) so the status Local: line has a file to name.
  fs.writeFileSync(
    path.join(home, 'node9.config.json'),
    JSON.stringify({ version: '1.0', settings: {} })
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

let keyedHome: string;
let unkeyedHome: string;

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build` first');
  keyedHome = makeHome(true);
  unkeyedHome = makeHome(false);
});
afterAll(() => {
  fs.rmSync(keyedHome, { recursive: true, force: true });
  fs.rmSync(unkeyedHome, { recursive: true, force: true });
});

describe('I1/I2 — node9 status', () => {
  it('keyed: names the workspace source and marks BOTH local config files present-but-ignored', () => {
    const { status, out } = runCli(keyedHome, ['status']);
    expect(status).toBe(0);
    expect(out).toContain('Policy:  Workspace config (app.node9.ai)');
    // Local (node9.config.json in cwd) AND Global (~/.node9/config.json):
    const ignoredLines = out
      .split('\n')
      .filter((l) => l.includes('Present — ignored (workspace config governs)'));
    expect(ignoredLines.some((l) => l.includes('Local:'))).toBe(true);
    expect(ignoredLines.some((l) => l.includes('Global:'))).toBe(true);
    // I2 (§0.3): the keyed default approvers.cloud=true renders as cloud
    // policy enforced — not privacy mode — with a local config that never set it.
    expect(out).toContain('Agent mode');
    expect(out).toContain('cloud team policy enforced');
  });

  it('unkeyed: byte-parity — Active file labels, no Policy: line, no ignored markers', () => {
    const { status, out } = runCli(unkeyedHome, ['status']);
    expect(status).toBe(0);
    expect(out).toContain('Local:   Active (node9.config.json)');
    expect(out).toContain('Global:  Active (~/.node9/config.json)');
    expect(out).not.toContain('Workspace config (app.node9.ai)');
    expect(out).not.toContain('ignored (workspace');
  });
});

describe('I3 — node9 doctor', () => {
  it('keyed: passes a policy-source line and disclaims the local config file', () => {
    const { out } = runCli(keyedHome, ['doctor']);
    expect(out).toContain('Policy source: workspace config (app.node9.ai)');
    expect(out).toContain('policy fields ignored — workspace governs');
  });

  it('unkeyed: no workspace-source line, config file reported plainly valid', () => {
    const { out } = runCli(unkeyedHome, ['doctor']);
    expect(out).not.toContain('Policy source: workspace config');
    expect(out).toContain('~/.node9/config.json found and valid');
    expect(out).not.toContain('policy fields ignored');
  });
});

describe('I5 — node9 egress (status view)', () => {
  it('keyed: names its source and calls local egress settings ignored', () => {
    const { status, out } = runCli(keyedHome, ['egress']);
    expect(status).toBe(0);
    expect(out).toContain('Source: workspace config (app.node9.ai)');
    expect(out).toContain('local egress settings are ignored');
  });

  it('unkeyed: no source line', () => {
    const { status, out } = runCli(unkeyedHome, ['egress']);
    expect(status).toBe(0);
    expect(out).not.toContain('Source: workspace config');
  });
});

describe('I8 — shield list / shield status / config show', () => {
  it('keyed shield list: locally-enabled-but-not-mandated shield is marked ignored', () => {
    const { status, out } = runCli(keyedHome, ['shield', 'list']);
    expect(status).toBe(0);
    expect(out).toContain('Workspace config governs — local enables are ignored.');
    const fsLine = out.split('\n').find((l) => l.includes('filesystem')) ?? '';
    expect(fsLine).toContain('ignored');
    expect(fsLine).toContain('enabled locally — workspace config governs');
  });

  // Was a PRODUCTION BUG, pinned by this row and fixed the same day: the keyed
  // branch of `shield list` computed its "cloud" column from
  // readCloudShields() — a legacy heuristic parsing SHIELD:-tagged rules out of
  // rules-cache.json `rules` — instead of the resolver's own testimony,
  // config.policy.appliedShields. A shield mandated through the cache's
  // `shields` array (the M1 path this same fixture proves ENFORCED via `shield
  // status`) rendered "○  disabled" while it was being enforced. Matrix I8:
  // mandated shields are shown enforced. Mutation twin: reverting the keyed
  // branch to readCloudShields kills this row and no other.
  it('keyed shield list: a cache-mandated shield renders enabled (it IS enforced)', () => {
    const { out } = runCli(keyedHome, ['shield', 'list']);
    const redisLine = out.split('\n').find((l) => /\bredis\b/.test(l)) ?? '';
    expect(redisLine).toContain('enabled');
    expect(redisLine).not.toContain('disabled');
  });

  it('keyed shield status: renders the ENFORCED set (mandated redis) with a workspace source line', () => {
    const { out } = runCli(keyedHome, ['shield', 'status']);
    expect(out).toContain('Source: workspace config (app.node9.ai)');
    // Mutant kill: swapping back to readActiveShields would render filesystem
    // (local enable) and drop redis (the mandate).
    expect(out).toContain('redis');
    expect(out).toContain('block-flushall');
    expect(out).not.toMatch(/●\s*filesystem/);
  });

  it('unkeyed shield status: renders the LOCAL enable store, no source line', () => {
    const { out } = runCli(unkeyedHome, ['shield', 'status']);
    expect(out).not.toContain('Source: workspace config');
    expect(out).toMatch(/●\s*filesystem/);
  });

  it('keyed config show: names the workspace source and shows the enforced shield set', () => {
    const { out } = runCli(keyedHome, ['config', 'show']);
    expect(out).toContain('Source: workspace config (app.node9.ai)');
    expect(out).toContain('local policy files are ignored');
  });

  it('unkeyed config show: no workspace source line', () => {
    const { out } = runCli(unkeyedHome, ['config', 'show']);
    expect(out).not.toContain('Source: workspace config');
  });
});

describe('I10 — node9 jail list', () => {
  it('keyed: user paths render but are marked ignored (workspace governs)', () => {
    const { status, out } = runCli(keyedHome, ['jail', 'list']);
    expect(status).toBe(0);
    expect(out).toContain('Your paths — ignored (workspace config governs):');
    const pathLine = out.split('\n').find((l) => l.includes('/tmp/secrets')) ?? '';
    expect(pathLine).toContain('(ignored)');
  });

  it('unkeyed: user paths render as removable, never marked ignored', () => {
    const { status, out } = runCli(unkeyedHome, ['jail', 'list']);
    expect(status).toBe(0);
    expect(out).toContain('Your paths (removable):');
    expect(out).toContain('/tmp/secrets');
    expect(out).not.toContain('(ignored)');
    expect(out).not.toContain('workspace config governs');
  });
});
