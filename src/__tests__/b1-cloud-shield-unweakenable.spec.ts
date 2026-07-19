// B1 — a cloud-mandated shield must be un-weakenable by a local override.
//
// The hole: `node9 shield set redis <rule> allow --force` writes a per-rule
// override to ~/.node9/shields.json, and config/index.ts applied it to EVERY
// shield in `local ∪ cloudManagedShields` — so a developer could weaken a
// shield the dashboard mandated fleet-wide. The comment at config/index.ts:751
// promised "a developer can add more locally, never weaken these"; this is the
// test that promise was never backed by.
//
// Driven through the REAL merge (getConfig) with the REAL shield catalog. Only
// the two local-file readers are mocked, because their path
// (SHIELDS_STATE_FILE, shields.ts:95) is a module-load-time const that a HOME
// override in beforeEach cannot move — setting HOME would read this machine's
// real shields.json. The cloud side (rules-cache) IS redirected by HOME,
// because config/index.ts computes that path per-call.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const activeShields = { current: [] as string[] };
const shieldOverrides = {
  current: {} as Record<string, Record<string, string>>,
};

vi.mock('../shields', async () => {
  const actual = await vi.importActual<typeof import('../shields')>('../shields');
  return {
    ...actual,
    readActiveShields: () => activeShields.current,
    readShieldOverrides: () => shieldOverrides.current,
  };
});

import { getConfig, _resetConfigCache } from '../config';
import { evaluatePolicy } from '../core.js';

const RULE = 'shield:redis:block-flushall'; // ships verdict: block

describe('B1 — cloud-mandated shield ignores local overrides', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  const setCloud = (cloudShields: string[] | null) => {
    if (cloudShields) {
      fs.writeFileSync(
        path.join(tmpHome, '.node9', 'rules-cache.json'),
        JSON.stringify({
          fetchedAt: '2026-07-01T00:00:00Z',
          rules: [],
          shields: cloudShields,
        })
      );
    }
    _resetConfigCache();
  };

  const setLocal = (active: string[], overrides: Record<string, Record<string, string>> = {}) => {
    activeShields.current = active;
    shieldOverrides.current = overrides;
    _resetConfigCache();
  };

  /** The enforced verdict for RULE, read off the merged policy. */
  const enforcedVerdict = (): string | undefined =>
    getConfig().policy.smartRules.find((r) => r.name === RULE)?.verdict;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-b1-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    activeShields.current = [];
    shieldOverrides.current = {};
    _resetConfigCache();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    _resetConfigCache();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  // ── Row 0: the mocks actually drive the merge (guards against a vacuous
  //    suite — if the override path is dead, every row below passes for the
  //    wrong reason, which is exactly what a first cut of this file did) ─────
  it('a local override DOES apply to a purely-local shield (control)', () => {
    setLocal(['redis'], { redis: { [RULE]: 'allow' } });
    expect(enforcedVerdict()).toBe('allow');
  });

  // ── Row 1: THE security regression. Must fail against pre-fix code. ────────
  it('does NOT weaken a cloud-mandated shield when a local override says allow', () => {
    setCloud(['redis']);
    setLocal([], { redis: { [RULE]: 'allow' } });
    expect(enforcedVerdict()).toBe('block');
  });

  // ── Row 2: absolute, not "block weakening only" ───────────────────────────
  it('ignores a local TIGHTENING override on a cloud shield too', () => {
    setCloud(['redis']);
    setLocal([], { redis: { [RULE]: 'review' } });
    expect(enforcedVerdict()).toBe('block');
  });

  // ── Row 3: the guard against over-reach ───────────────────────────────────
  it('still honours a local override on a LOCALLY-enabled shield', () => {
    setLocal(['redis'], { redis: { [RULE]: 'allow' } });
    expect(enforcedVerdict()).toBe('allow');
  });

  // ── Row 4: cloud wins the union ───────────────────────────────────────────
  it('cloud mandate wins even if the shield was also enabled locally first', () => {
    setCloud(['redis']);
    setLocal(['redis'], { redis: { [RULE]: 'allow' } });
    expect(enforcedVerdict()).toBe('block');
  });

  // ── Row 6: no regression on the common case ───────────────────────────────
  it('applies the cloud verdict unchanged when there is no local override', () => {
    setCloud(['redis']);
    setLocal([]);
    expect(enforcedVerdict()).toBe('block');
  });

  // ── At the real gate ──────────────────────────────────────────────────────
  // Reading the merged verdict field is the merge output; this proves the
  // ENGINE acts on it. A FLUSHALL, with the shield cloud-mandated and a local
  // override set to allow, must still BLOCK — gate-not-cage, un-weakened.
  it('actually blocks FLUSHALL through the engine despite a local allow override', async () => {
    setCloud(['redis']);
    setLocal([], { redis: { [RULE]: 'allow' } });
    const r = await evaluatePolicy('Bash', { command: 'redis-cli FLUSHALL' });
    expect(r.decision).toBe('block');
  });

  // And the legitimate case is not caught by the gate: a purely-local shield's
  // allow override really does let FLUSHALL through.
  it('lets FLUSHALL through the engine for a purely-local allow override', async () => {
    setLocal(['redis'], { redis: { [RULE]: 'allow' } });
    const r = await evaluatePolicy('Bash', { command: 'redis-cli FLUSHALL' });
    expect(r.decision).not.toBe('block');
  });
});
