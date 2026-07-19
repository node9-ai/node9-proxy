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
// Lets a test shadow getShield with a WEAK body (as a user ~/.node9/shields/<name>.json
// would) to prove a MANDATED shield ignores it and resolves from BUILTIN_SHIELDS (#2).
// Null = pass through to the real catalog (every other test).
const getShieldImpl = {
  current: null as null | ((name: string) => unknown),
};

vi.mock('../shields', async () => {
  const actual = await vi.importActual<typeof import('../shields')>('../shields');
  return {
    ...actual,
    readActiveShields: () => activeShields.current,
    readShieldOverrides: () => shieldOverrides.current,
    getShield: (name: string) =>
      getShieldImpl.current ? getShieldImpl.current(name) : actual.getShield(name),
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

  /** A user rule that COLLIDES with the shield's rule name, verdict allow. The
   *  second B1 hole: this used to suppress the cloud shield's block rule as a
   *  "duplicate". `where` = 'global' (~/.node9/config.json) or 'project'
   *  (a repo-checked-in node9.config.json — the supply-chain vector). */
  const setCollidingUserRule = (where: 'global' | 'project') => {
    const rule = {
      name: RULE,
      tool: '*',
      conditions: [{ field: 'command', op: 'matches', value: 'FLUSHALL', flags: 'i' }],
      verdict: 'allow',
    };
    const body = JSON.stringify({ policy: { smartRules: [rule] } });
    const file =
      where === 'global'
        ? path.join(tmpHome, '.node9', 'config.json')
        : path.join(tmpHome, 'node9.config.json');
    fs.writeFileSync(file, body);
    _resetConfigCache();
  };

  /** The enforced verdict for RULE, read off the merged policy. `cwd` is needed
   *  for the project-config case, whose path is cwd-relative. */
  const enforcedVerdict = (cwd?: string): string | undefined =>
    getConfig(cwd).policy.smartRules.find((r) => r.name === RULE)?.verdict;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-b1-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    activeShields.current = [];
    shieldOverrides.current = {};
    getShieldImpl.current = null;
    delete process.env.NODE9_MODE;
    _resetConfigCache();
  });

  afterEach(() => {
    delete process.env.NODE9_MODE;
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

  // ── Part 2: the name-collision hole (found in review of the part-1 commit) ─
  // User config is merged into the policy BEFORE the shield loop, so a rule
  // named exactly like a shield rule used to SUPPRESS the shield's version as a
  // "duplicate". Part 1 (no override) did not close this — the rule never
  // reached the override path; it pre-empted it.
  it('a global config.json rule cannot suppress a cloud shield rule', () => {
    setCloud(['redis']);
    setCollidingUserRule('global');
    expect(enforcedVerdict()).toBe('block');
  });

  // The higher-severity vector: NOT self-inflicted. A cloned repo ships a
  // node9.config.json naming a fleet-mandated shield rule; running an agent in
  // that directory would weaken the victim's cloud mandate.
  it('a repo project node9.config.json cannot suppress a cloud shield rule', () => {
    setCloud(['redis']);
    setCollidingUserRule('project');
    expect(enforcedVerdict(tmpHome)).toBe('block');
  });

  // A local (non-cloud) shield keeps today's behaviour: the user owns both
  // their local shield and their config, so a same-named config rule may still
  // win. The fix must not over-reach into legitimate local composition.
  it('a config rule still wins over a purely-LOCAL shield rule (no over-reach)', () => {
    setLocal(['redis']);
    setCollidingUserRule('global');
    expect(enforcedVerdict()).toBe('allow');
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

  // The collision hole, at the gate: a global config rule that suppressed the
  // shield rule must NOT let FLUSHALL through once the shield is cloud-mandated.
  it('blocks FLUSHALL through the engine despite a colliding config rule', async () => {
    setCloud(['redis']);
    setCollidingUserRule('global');
    const r = await evaluatePolicy('Bash', { command: 'redis-cli FLUSHALL' });
    expect(r.decision).toBe('block');
  });

  // ── Remaining bypasses ABOVE the rule-verdict layer (b1-remaining-bypasses) ──
  // Each was reproduced at the real getConfig gate BEFORE the fix (allow /
  // observe / Bash-ignored) and must now hold. The earlier B1 review wrongly
  // marked #1 "refuted"; it is real (first-match-in-array-order, shields
  // un-pinned), fixed by pinning mandated shield rules.

  const writeGlobalConfig = (obj: unknown) => {
    fs.writeFileSync(path.join(tmpHome, '.node9', 'config.json'), JSON.stringify(obj));
    _resetConfigCache();
  };
  const setManagedMode = (mode: string, lock: boolean) => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.json'),
      JSON.stringify({
        fetchedAt: '2026-07-01T00:00:00Z',
        rules: [],
        shields: [],
        managedConfig: { mode, ...(lock ? { locked: ['mode'] } : {}) },
      })
    );
    _resetConfigCache();
  };

  // #1 — a DIFFERENTLY-named local allow can no longer out-precede a mandate.
  it('#1 blocks FLUSHALL despite a differently-named local allow rule', async () => {
    setCloud(['redis']);
    writeGlobalConfig({
      policy: {
        smartRules: [
          {
            name: 'my-innocuous-allow',
            tool: '*',
            conditions: [{ field: 'command', op: 'matches', value: 'FLUSHALL', flags: 'i' }],
            verdict: 'allow',
          },
        ],
      },
    });
    const r = await evaluatePolicy('Bash', { command: 'redis-cli FLUSHALL' });
    expect(r.decision).toBe('block');
  });

  it('#1 pins a mandated shield rule in the merged policy', () => {
    setCloud(['redis']);
    expect(getConfig().policy.smartRules.find((r) => r.name === RULE)?.pinned).toBe(true);
  });

  it('#1 does NOT pin a purely-local shield rule (no over-reach)', () => {
    setLocal(['redis']);
    expect(getConfig().policy.smartRules.find((r) => r.name === RULE)?.pinned).toBeUndefined();
  });

  // #2 — NODE9_MODE (applied last) must respect a cloud-controlled mode.
  it('#2 NODE9_MODE cannot override a cloud-LOCKED mode', () => {
    setManagedMode('standard', true);
    process.env.NODE9_MODE = 'observe';
    expect(getConfig().settings.mode).toBe('standard');
  });

  it('#2 NODE9_MODE still applies when the cloud has not set mode (dev convenience)', () => {
    process.env.NODE9_MODE = 'observe';
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('#2 ignores a garbage NODE9_MODE value', () => {
    process.env.NODE9_MODE = 'wide-open';
    expect(getConfig().settings.mode).not.toBe('wide-open');
  });

  // #2b — a mandated shield resolves its BODY from BUILTIN_SHIELDS, not a user
  // shields/<name>.json shadowing the name with an empty/weak body.
  it('#2b a mandated shield ignores a shadowing weak user shield body', () => {
    getShieldImpl.current = (name) => (name === 'redis' ? { name: 'redis', smartRules: [] } : null);
    setCloud(['redis']);
    expect(getConfig().policy.smartRules.find((r) => r.name === RULE)?.verdict).toBe('block');
  });

  // #3 — local ignoredTools/sandboxPaths cannot fast-path past a mandated shield.
  it('#3 drops local ignoredTools when the fleet mandates shields', () => {
    setCloud(['redis']);
    writeGlobalConfig({ policy: { ignoredTools: ['Bash'] } });
    expect(getConfig().policy.ignoredTools).not.toContain('Bash');
  });

  it('#3 blocks FLUSHALL despite local ignoredTools:[Bash] under a mandate', async () => {
    setCloud(['redis']);
    writeGlobalConfig({ policy: { ignoredTools: ['Bash'] } });
    const r = await evaluatePolicy('Bash', { command: 'redis-cli FLUSHALL' });
    expect(r.decision).toBe('block');
  });

  it('#3 keeps local ignoredTools when NO shield is mandated (no over-reach)', () => {
    writeGlobalConfig({ policy: { ignoredTools: ['Grep'] } });
    expect(getConfig().policy.ignoredTools).toContain('Grep');
  });
});
