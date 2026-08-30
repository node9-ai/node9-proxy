// src/__tests__/keyed-sync-bootstrap.spec.ts
// PR-2 "replace-mode" §S — sync / cache / bootstrap / transitions
// (doc/roadmap/active/one-config-pr2-test-matrix.md).
//
// In-process rows at the getConfig() seam. The login/logout transition rows
// (S5/S6) model the daemon's own behavior: daemon/server.ts calls
// _resetConfigCache at the top of every POST /check ("Always read fresh
// config"), so a credentials.json write/delete lands on the NEXT decision.
//
// NOT implemented here (needs live processes / the pending §0.10 fix):
//   S7  — mcp-gateway staleness across login/logout: the gateway never resets
//         the ambient config cache today; the row FAILS pre-fix by design and
//         belongs with the gateway fix, not in a green suite.
//   S8  — `node9 connect` first-sync-synchronous: onboarding integration with
//         a mock cloud (connect.integration territory).
//   S12 — `--local` daemon sync tick skips the policy PULL but keeps audit
//         shipping: daemon sync loop integration (sync.test territory).
//
// MUTATION PREP: S1/S2 kill `keyed = rules-cache exists` (creds with NO cache
// must still be workspace-sourced); S5/S6/S9 kill any keyedness memoization
// that survives _resetConfigCache; S3/S4 kill "keyed pass bypasses
// readRulesCacheResilient"; S11 kills "keyed falls back to LOCAL when the
// cache disappears" (it must fall to SHIPPED DEFAULTS).

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { ShieldDefinition } from '../shields';

// Shields store paths are module-load consts frozen to the real home; mock the
// local-file readers (applied-shields.spec.ts harness) so S13's unkeyed twin
// can control the local enable list.
const shieldState = vi.hoisted(() => ({
  active: [] as string[],
  overrides: {} as Record<string, Record<string, 'allow' | 'review' | 'block'>>,
  userShields: {} as Record<string, unknown>,
}));

vi.mock('../shields', async () => {
  const actual = await vi.importActual<typeof import('../shields')>('../shields');
  const engine =
    await vi.importActual<typeof import('@node9/policy-engine')>('@node9/policy-engine');
  return {
    ...actual,
    readActiveShields: () => shieldState.active,
    readShieldOverrides: () => shieldState.overrides,
    getShield: (name: string) =>
      (shieldState.userShields[name] as ShieldDefinition | undefined) ??
      engine.BUILTIN_SHIELDS[name] ??
      null,
  };
});

import { getConfig, _resetConfigCache, __resetRulesCacheStateForTest } from '../config';
import { readActiveShields, readShieldOverrides } from '../shields';
import { buildPolicySnapshot } from '../policy-snapshot/build';

describe('§S — sync / cache / bootstrap / transitions', () => {
  let home: string;
  let proj: string;
  const savedEnv: Record<string, string | undefined> = {};
  const ENV_KEYS = ['NODE9_API_KEY', 'NODE9_API_URL', 'NODE9_PROFILE', 'NODE9_MODE'];

  const credsPath = () => path.join(home, '.node9', 'credentials.json');
  const cachePath = () => path.join(home, '.node9', 'rules-cache.json');
  const backupPath = () => path.join(home, '.node9', 'rules-cache.last-good.json');

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-sboot-'));
    proj = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-sboot-proj-'));
    savedEnv.HOME = process.env.HOME;
    savedEnv.USERPROFILE = process.env.USERPROFILE;
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    for (const k of ENV_KEYS) delete process.env[k];
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    shieldState.active = [];
    shieldState.overrides = {};
    shieldState.userShields = {};
    _resetConfigCache();
    __resetRulesCacheStateForTest(); // memo + log rate-limit are process state
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v !== undefined) process.env[k] = v;
      else delete process.env[k];
    }
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(proj, { recursive: true, force: true });
    _resetConfigCache();
    __resetRulesCacheStateForTest();
  });

  const keyed = () => {
    fs.writeFileSync(credsPath(), JSON.stringify({ default: { apiKey: 'n9_test_matrix' } }));
  };
  /** A RICH local config — every family sets something non-default, so a
   *  bootstrap row can prove NONE of it leaks into the keyed policy. */
  const writeRichLocal = () => {
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({
        version: '1.0',
        settings: { mode: 'strict', approvalTimeoutMs: 45_000 },
        policy: {
          dlp: { enabled: false },
          egress: { enabled: true, mode: 'block', deny: ['evil.com'] },
          ignoredTools: ['bash'],
          smartRules: [
            {
              name: 'local-rule',
              tool: 'bash',
              conditions: [{ field: 'command', op: 'contains', value: 'xyz' }],
              conditionMode: 'all',
              verdict: 'block',
              reason: 'local',
            },
          ],
        },
        environments: { production: { requireApproval: true } },
      })
    );
  };
  const cfg = () => {
    _resetConfigCache();
    return getConfig(proj);
  };

  const expectShippedDefaults = (c: ReturnType<typeof getConfig>) => {
    expect(c.policySource).toBe('workspace');
    expect(c.settings.mode).toBe('standard');
    expect(c.policy.dlp.enabled).toBe(true);
    expect(c.policy.egress.enabled).toBe(false);
    expect(c.policy.appliedShields).toEqual([]);
    expect(c.policy.smartRules.some((r) => r.name === 'local-rule')).toBe(false);
    expect(c.policy.ignoredTools).not.toContain('bash');
    expect(c.environments).toEqual({});
    expect(c.settings.approvalTimeoutMs).toBe(120_000);
  };

  it('S1: keyed + NO rules-cache ⇒ SHIPPED DEFAULTS, never the local stack', () => {
    keyed();
    writeRichLocal();
    // Mutation kill: `keyed = cache exists` makes this row resolve the local
    // stack (strict / dlp off / egress lock) — every assertion below fails.
    expectShippedDefaults(cfg());
  });

  it('S2: keyed + EMPTY cache ({} — a zero-policy workspace) ⇒ same shipped defaults', () => {
    keyed();
    writeRichLocal();
    fs.writeFileSync(cachePath(), '{}');
    expectShippedDefaults(cfg());
  });

  it('S3: corrupt cache + valid last-good ⇒ the last-good policy is enforced (resilience kept keyed)', () => {
    keyed();
    fs.writeFileSync(
      backupPath(),
      JSON.stringify({ rules: [], managedConfig: { mode: 'observe', locked: [] } })
    );
    fs.writeFileSync(cachePath(), '{"rules": [truncated-mid-wri');
    expect(cfg().settings.mode).toBe('observe');
  });

  it('S4: corrupt cache + no backup ⇒ the in-memory memo serves the last-good policy (F4), loudly', () => {
    keyed();
    // Prime the memo with a successful read (the long-lived daemon's state).
    fs.writeFileSync(
      cachePath(),
      JSON.stringify({ rules: [], managedConfig: { mode: 'observe', locked: [] } })
    );
    expect(cfg().settings.mode).toBe('observe');
    // Disk turns unreadable: corrupt primary, no backup. _resetConfigCache
    // does NOT clear the memo (by design — it runs on the enforcement path).
    fs.writeFileSync(cachePath(), '{"rules": [truncated-mid-wri');
    expect(cfg().settings.mode).toBe('observe');
    const log = fs.readFileSync(path.join(home, '.node9', 'hook-debug.log'), 'utf-8');
    expect(log).toContain('RULES_CACHE_USED_MEMORY');
  });

  it('S5: login mid-process — credentials written between reads land on the NEXT decision', () => {
    writeRichLocal();
    // Decision 1 (unkeyed): the local stack governs.
    const before = cfg();
    expect(before.policySource).toBe('local');
    expect(before.settings.mode).toBe('strict');
    // login writes credentials.json; the daemon resets the cache per check.
    keyed();
    const after = cfg();
    expect(after.policySource).toBe('workspace');
    expect(after.settings.mode).toBe('standard');
  });

  it('S6: logout (credentials deleted) — the local stack RESUMES on the next read', () => {
    writeRichLocal();
    keyed();
    expect(cfg().policySource).toBe('workspace');
    fs.rmSync(credsPath()); // logout.ts removes the profile
    const after = cfg();
    expect(after.policySource).toBe('local');
    expect(after.settings.mode).toBe('strict');
  });

  it('S9: an ENV key is process-scoped — keyed with it, unkeyed without it (§0.14)', () => {
    writeRichLocal();
    process.env.NODE9_API_KEY = 'n9_ci_key';
    expect(cfg().policySource).toBe('workspace');
    delete process.env.NODE9_API_KEY;
    const second = cfg();
    expect(second.policySource).toBe('local');
    expect(second.settings.mode).toBe('strict');
  });

  it('S10: a named-profile key (NODE9_PROFILE) is unkeyed-for-policy (§0.11 — profiles never policy-sync)', () => {
    writeRichLocal();
    fs.writeFileSync(credsPath(), JSON.stringify({ work: { apiKey: 'n9_work_key' } }));
    process.env.NODE9_PROFILE = 'work';
    const c = cfg();
    expect(c.policySource).toBe('local');
    expect(c.settings.mode).toBe('strict');
  });

  it('S11: deleting the cache mid-run falls to SHIPPED DEFAULTS — never back to local ("key present ⇒ server only")', () => {
    keyed();
    writeRichLocal();
    fs.writeFileSync(
      cachePath(),
      JSON.stringify({ rules: [], managedConfig: { mode: 'observe', locked: [] } })
    );
    expect(cfg().settings.mode).toBe('observe');
    fs.rmSync(cachePath());
    __resetRulesCacheStateForTest(); // ENOENT is "no cloud policy" — the memo only serves corrupt-PRESENT files
    const after = cfg();
    // Mutation kill: a fallback to the LOCAL stack would read strict here.
    expect(after.settings.mode).toBe('standard');
    expect(after.policySource).toBe('workspace');
  });

  it("S-classB (K4d twin at the bootstrap seam): a hand-edited cache cannot turn a Class-B check 'off'", () => {
    keyed();
    fs.writeFileSync(
      cachePath(),
      JSON.stringify({
        rules: [],
        managedConfig: { commandChecks: { evalDynamic: 'off', pipeChainHigh: 'off' }, locked: [] },
      })
    );
    const cc = cfg().policy.commandChecks ?? {};
    expect(cc.evalDynamic).not.toBe('off');
    expect(cc.pipeChainHigh).not.toBe('off');
  });

  // ── S13 — the snapshot wire ships what the CONFIG APPLIED (§0.5) ──────────
  // sync.ts (both push sites) passes `cfg.policy.appliedShields ??
  // readActiveShields()` into buildPolicySnapshot. These rows pin the wire
  // field through that exact call shape.
  it('S13: keyed snapshot ships appliedShields (the cloud mandate), not the local shields file', () => {
    keyed();
    shieldState.active = ['filesystem']; // local file lists something else entirely
    fs.writeFileSync(cachePath(), JSON.stringify({ rules: [], shields: ['redis'] }));
    const c = cfg();
    const body = buildPolicySnapshot(c, c.policy.appliedShields ?? readActiveShields(), {});
    // The fw comparator marks a mandated shield absent from activeShields as
    // `not-applied` (drift) — shipping the local file here would flag every
    // correctly-enforcing keyed machine forever.
    expect(body.activeShields).toEqual(['redis']);
    expect(body.mode).toBe(c.settings.mode);
    expect(body.dlpEnabled).toBe(c.policy.dlp.enabled);
  });

  it('S13-unkeyed twin: the snapshot carries the applied local∪cloud union byte-for-byte', () => {
    shieldState.active = ['filesystem'];
    fs.writeFileSync(cachePath(), JSON.stringify({ rules: [], shields: ['redis'] }));
    const c = cfg();
    const body = buildPolicySnapshot(
      c,
      c.policy.appliedShields ?? readActiveShields(),
      readShieldOverrides()
    );
    expect(body.activeShields).toEqual(['filesystem', 'redis']);
  });
});
