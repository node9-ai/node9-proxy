// src/__tests__/keyed-review-fixes.spec.ts
// Regression rows for the PR-2 ADVERSARIAL REVIEW findings (2026-08-30).
// Every row here failed before its fix — that is the whole point of the file.
//
//   F3 — `shield create --enable` wrote shields.json and printed "Active now."
//        on a workspace-governed machine while enforcing nothing (the write
//        guard's enumeration missed `create`).
//   F5 — `status` / `config show` rendered `observe` as "standard" via an
//        `else → standard` ternary. PR-2 made it load-bearing: a keyed machine
//        applies a cloud `observe` VERBATIM, so the one surface people check
//        reported the opposite of the truth on a machine enforcing nothing.
//   F8 — the keyed commandChecks branch iterated whatever keys the cache
//        carried instead of the known list, so a hand-edited cache could seed
//        arbitrary keys into the policy object.
//
// MUTATION PREP:
//   - guard dropped from `shield create`            → F3 refusal + store rows
//   - `--enable` guard widened to the whole command → F3 authoring row
//   - observe branch removed from either ternary    → the two F5 rows
//   - keyed commandChecks back to Object.entries    → F8 unknown-key row
//
// F1/F2/F4 (keyedness and the cache are decided from attacker-writable local
// inputs) are NOT covered here: the fix is a founder decision plus a
// server-side change, tracked in enforcement-one-config-design.md.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { keySafeEnv, writeKeyedHome } from './helpers/env';
import { getConfig, _resetConfigCache } from '../config';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function runCli(home: string, args: string[]): { status: number | null; out: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
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
  expect(r.error).toBeUndefined();
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

/** Keyed home whose WORKSPACE mandates the given managedConfig. */
function makeKeyedHome(managed: Record<string, unknown> = {}): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-rev-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  writeKeyedHome(home);
  fs.writeFileSync(
    path.join(home, '.node9', 'rules-cache.json'),
    JSON.stringify({
      fetchedAt: '2026-08-01T00:00:00Z',
      rules: [],
      shields: [],
      managedConfig: { locked: [], ...managed },
    })
  );
  return home;
}

const homes: string[] = [];
afterAll(() => {
  for (const h of homes) fs.rmSync(h, { recursive: true, force: true });
});
function keyedHome(managed?: Record<string, unknown>): string {
  const h = makeKeyedHome(managed);
  homes.push(h);
  return h;
}

// ── F3 — shield create --enable is a policy write ────────────────────────────
describe('F3 — `shield create --enable` is guarded', () => {
  it('refuses --enable on a workspace-governed machine and writes NO enable store', () => {
    const home = keyedHome();
    const r = runCli(home, [
      'shield',
      'create',
      'revshield',
      '--block-tool',
      'nothing',
      '--enable',
    ]);
    expect(r.status).not.toBe(0);
    expect(r.out).toMatch(/workspace configuration/i);
    // The bug's signature was a green exit plus this line.
    expect(r.out).not.toMatch(/Active now/i);
    expect(fs.existsSync(path.join(home, '.node9', 'shields.json'))).toBe(false);
  });

  it('still allows AUTHORING without --enable (only the enable half is a write)', () => {
    const home = keyedHome();
    const r = runCli(home, ['shield', 'create', 'draftshield', '--block-tool', 'nothing']);
    expect(r.status).toBe(0);
    expect(fs.existsSync(path.join(home, '.node9', 'shields', 'draftshield.json'))).toBe(true);
    // Authoring must not enable it either.
    expect(fs.existsSync(path.join(home, '.node9', 'shields.json'))).toBe(false);
  });

  it('unkeyed instrument: the same --enable command works and enables (known-true)', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-rev-unkeyed-'));
    homes.push(home);
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    const r = runCli(home, ['shield', 'create', 'okshield', '--block-tool', 'nothing', '--enable']);
    expect(r.status).toBe(0);
    const active = JSON.parse(
      fs.readFileSync(path.join(home, '.node9', 'shields.json'), 'utf-8')
    ) as { active: string[] };
    expect(active.active).toContain('okshield');
  });
});

// ── F5 — observe must never render as "standard" ─────────────────────────────
describe('F5 — a machine enforcing nothing says so', () => {
  it('`status` names observe when the workspace mandates it', () => {
    const home = keyedHome({ mode: 'observe' });
    const r = runCli(home, ['status']);
    expect(r.out).toMatch(/Mode:\s+observe/);
    expect(r.out).not.toMatch(/Mode:\s+standard/);
  });

  it('`config show` names observe too (the second copy of the ternary)', () => {
    const home = keyedHome({ mode: 'observe' });
    const r = runCli(home, ['config', 'show']);
    expect(r.out).toMatch(/Mode:\s+observe/);
    expect(r.out).not.toMatch(/Mode:\s+standard/);
  });

  it('instrument: a standard workspace still renders standard on both surfaces', () => {
    const home = keyedHome({ mode: 'standard' });
    expect(runCli(home, ['status']).out).toMatch(/Mode:\s+standard/);
    expect(runCli(home, ['config', 'show']).out).toMatch(/Mode:\s+standard/);
  });
});

// ── F8 — the keyed commandChecks branch only reads KNOWN keys ────────────────
describe('F8 — a hand-edited cache cannot seed unknown commandChecks keys', () => {
  const saved: Record<string, string | undefined> = {};
  let home: string;

  beforeAll(() => {
    home = keyedHome({
      commandChecks: { inlineExec: 'block', notARealCheck: 'off', anotherFake: 'block' },
    });
    saved.HOME = process.env.HOME;
    saved.USERPROFILE = process.env.USERPROFILE;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    _resetConfigCache();
  });

  afterAll(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v !== undefined) process.env[k] = v;
      else delete process.env[k];
    }
    _resetConfigCache();
  });

  it('applies the known key and drops the invented ones', () => {
    const cc = getConfig().policy.commandChecks ?? {};
    expect(cc.inlineExec).toBe('block');
    expect(Object.keys(cc)).not.toContain('notARealCheck');
    expect(Object.keys(cc)).not.toContain('anotherFake');
  });

  it('Class-B still cannot be turned off through the keyed branch', () => {
    expect(getConfig().policy.commandChecks?.evalDynamic).not.toBe('off');
  });
});
