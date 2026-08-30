// src/__tests__/keyed-replace.spec.ts
// PR-2 "replace-mode" §K — keyed behavior per policy family
// (doc/roadmap/active/one-config-pr2-test-matrix.md).
//
// THE LAW UNDER TEST: a KEYED machine (credentials.json apiKey present, not
// localOnly) builds POLICY from DEFAULT_CONFIG ⊕ the cloud cache
// (rules-cache.json) ONLY. Local config.json / node9.config.json policy is
// INERT; operational settings still apply. Unkeyed keeps today's stack
// byte-for-byte (unkeyed-parity-golden.spec.ts is the other half).
//
// These are UNIT rows at the getConfig() seam — the fork lives entirely in
// getConfig, so the resolved Config IS the behavior under test. Gate-level
// keyed coverage lives in the converted suites (taint-review-not-dropped,
// strict-cloud-allow-bypass, app-permissions, inline-ask-v2-defer).
//
// MUTATION PREP (which row kills which core mutant — matrix "global mutation
// discipline"):
//   - fork condition inverted / keyed=cache-presence  → K1a + every §U row
//   - keyed mode routed through resolveManagedMode     → K1c
//   - keyed dlp routed through applyManagedDlp         → K3b
//   - keyed egress routed through applyManagedEgress   → K2b/K2c
//   - keyed pass skips the WHOLE local layer           → K19
//   - keyed defaults forget approvers.cloud            → K5a
//   - trustedHostsManaged force forgotten              → K10a
//   - shields union kept keyed (local ∪ cloud)         → K12a / K9b
//   - Class-B guard dropped in the keyed pass          → K4d
//   - NODE9_MODE re-honored keyed                      → K1b

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { ShieldDefinition } from '../shields';

// The shields store paths (shields.json / user shields dir) are module-load
// consts frozen to the REAL home — a temp-HOME fixture can't move them, so the
// local-file readers are mocked (same harness as applied-shields.spec.ts).
// getShield stays hermetic: a test-provided user shadow, else the builtin
// catalog, never the dev machine's ~/.node9/shields.
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

import { getConfig, _resetConfigCache, DEFAULT_CONFIG } from '../config';

describe('§K — keyed replace-mode: policy = DEFAULT_CONFIG ⊕ cloud only', () => {
  let home: string;
  let proj: string;
  const savedEnv: Record<string, string | undefined> = {};

  const ENV_KEYS = ['NODE9_API_KEY', 'NODE9_API_URL', 'NODE9_PROFILE', 'NODE9_MODE'];

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-keyed-'));
    proj = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-keyed-proj-'));
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
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v !== undefined) process.env[k] = v;
      else delete process.env[k];
    }
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(proj, { recursive: true, force: true });
    _resetConfigCache();
  });

  /** THE keyed fixture (matrix conventions): credentials.json, default profile,
   *  no localOnly. File-keyed — the machine-wide channel. */
  const keyed = () => {
    fs.writeFileSync(
      path.join(home, '.node9', 'credentials.json'),
      JSON.stringify({ default: { apiKey: 'n9_test_matrix' } })
    );
  };
  const writeGlobal = (cfgObj: Record<string, unknown>) => {
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ version: '1.0', ...cfgObj })
    );
  };
  const writeRepo = (cfgObj: Record<string, unknown>) => {
    fs.writeFileSync(
      path.join(proj, 'node9.config.json'),
      JSON.stringify({ version: '1.0', ...cfgObj })
    );
  };
  const writeCache = (cache: Record<string, unknown>) => {
    fs.writeFileSync(
      path.join(home, '.node9', 'rules-cache.json'),
      JSON.stringify({ fetchedAt: '2026-08-01T00:00:00Z', rules: [], ...cache })
    );
  };
  const mc = (managed: Record<string, unknown>) =>
    writeCache({ managedConfig: { ...managed, locked: [] } });
  const cfg = () => {
    _resetConfigCache();
    return getConfig(proj);
  };

  // ── K1 mode ───────────────────────────────────────────────────────────────
  describe('K1 mode', () => {
    it('K1a: local strict is policy — keyed with no cache runs the shipped default (standard)', () => {
      keyed();
      writeGlobal({ settings: { mode: 'strict' } });
      const c = cfg();
      expect(c.settings.mode).toBe('standard');
      expect(c.policySource).toBe('workspace');
    });

    it('K1b: NODE9_MODE is ignored when keyed', () => {
      keyed();
      process.env.NODE9_MODE = 'observe';
      mc({});
      expect(cfg().settings.mode).toBe('standard');
    });

    it('K1b-twin (unkeyed instrument): NODE9_MODE=observe IS honored without a key', () => {
      process.env.NODE9_MODE = 'observe';
      const c = cfg();
      expect(c.settings.mode).toBe('observe');
      expect(c.policySource).toBe('local');
    });

    it('K1c: cloud observe applies VERBATIM keyed (was impossible under the floor)', () => {
      keyed();
      mc({ mode: 'observe' });
      // Mutation kill: routing the keyed mode through resolveManagedMode floors
      // this back to 'standard' (the seeded default counts as a local opinion).
      expect(cfg().settings.mode).toBe('observe');
    });

    it('K1d: managed strict + a repo requireApproval:false escape — the escape is inert (environments={})', () => {
      keyed();
      mc({ mode: 'strict' });
      writeRepo({ environments: { development: { requireApproval: false } } });
      const c = cfg();
      expect(c.settings.mode).toBe('strict');
      expect(c.environments).toEqual({});
    });

    it('K1e: shadowMode stays absolute — forces observe over a managed strict', () => {
      keyed();
      writeCache({ shadowMode: true, managedConfig: { mode: 'strict', locked: [] } });
      expect(cfg().settings.mode).toBe('observe');
    });

    it('K1f: panicMode from the cache lands on settings (orchestrator upgrades review→block)', () => {
      keyed();
      writeCache({ panicMode: true });
      expect(cfg().settings.panicMode).toBe(true);
    });
  });

  // ── K2 egress ─────────────────────────────────────────────────────────────
  describe('K2 egress', () => {
    it('K2a: a pre-login local egress lock goes inert at login — cloud-silent = DEFAULT (disabled)', () => {
      keyed();
      writeGlobal({
        policy: { egress: { enabled: true, mode: 'block', deny: ['evil.com'] } },
      });
      mc({});
      const c = cfg();
      expect(c.policy.egress).toEqual({
        enabled: false,
        mode: 'review',
        allow: [],
        deny: [],
        allowPrivate: true,
      });
    });

    it("K2b: cloud egress mode 'off' applies verbatim keyed", () => {
      keyed();
      mc({ egress: { enabled: true, mode: 'off' } });
      const c = cfg();
      expect(c.policy.egress.enabled).toBe(true);
      expect(c.policy.egress.mode).toBe('off');
    });

    it('K2c: local allow entries never union into the cloud allowlist', () => {
      keyed();
      writeGlobal({ policy: { egress: { enabled: true, mode: 'block', allow: ['mine.dev'] } } });
      mc({ egress: { enabled: true, mode: 'block', allow: ['api.corp.com'] } });
      // Mutation kill: keeping the local applyLayer for egress unions mine.dev in.
      expect(cfg().policy.egress.allow).toEqual(['api.corp.com']);
    });

    it('K2d: deny unions with DEFAULT ([]) — never with the local list', () => {
      keyed();
      writeGlobal({ policy: { egress: { enabled: true, deny: ['a.com'] } } });
      mc({ egress: { enabled: true, deny: ['b.com'] } });
      expect(cfg().policy.egress.deny).toEqual(['b.com']);
    });

    it('K2e: local allowPrivate:false dropped; cloud-silent = DEFAULT true; cloud false lands', () => {
      keyed();
      writeGlobal({ policy: { egress: { allowPrivate: false } } });
      mc({ egress: { enabled: true } });
      expect(cfg().policy.egress.allowPrivate).toBe(true);
      mc({ egress: { enabled: true, allowPrivate: false } });
      expect(cfg().policy.egress.allowPrivate).toBe(false);
    });
  });

  // ── K3 dlp ────────────────────────────────────────────────────────────────
  describe('K3 dlp', () => {
    it('K3a: local dlp off is dropped — cloud-silent = DEFAULT ON (replace-mode TIGHTENS here)', () => {
      keyed();
      writeGlobal({ policy: { dlp: { enabled: false } } });
      mc({});
      expect(cfg().policy.dlp.enabled).toBe(true);
    });

    it('K3b: cloud dlp.enabled:false WORKS keyed (X-12 — was impossible under the force-on floor)', () => {
      keyed();
      mc({ dlp: { enabled: false } });
      // Mutation kill: routing keyed dlp through applyManagedDlp force-on keeps it true.
      expect(cfg().policy.dlp.enabled).toBe(false);
    });

    it("K3c: cloud pii 'block' replaces verbatim", () => {
      keyed();
      mc({ dlp: { enabled: true, pii: 'block' } });
      expect(cfg().policy.dlp.pii).toBe('block');
    });

    it('K3d: scanIgnoredTools is cloud-inexpressible — local false falls to DEFAULT true', () => {
      keyed();
      writeGlobal({ policy: { dlp: { scanIgnoredTools: false } } });
      expect(cfg().policy.dlp.scanIgnoredTools).toBe(true);
    });

    it("K3e: cloud reviewAction 'block' replaces verbatim", () => {
      keyed();
      mc({ dlp: { reviewAction: 'block' } });
      expect(cfg().policy.dlp.reviewAction).toBe('block');
    });
  });

  // ── K4 commandChecks ──────────────────────────────────────────────────────
  describe('K4 commandChecks', () => {
    it('K4a: local knobs dropped both directions; review-rm advisory injected at review', () => {
      keyed();
      writeGlobal({ policy: { commandChecks: { chmod: 'off', inlineExec: 'block' } } });
      const c = cfg();
      expect(c.policy.commandChecks?.chmod).toBeUndefined();
      expect(c.policy.commandChecks?.inlineExec).toBeUndefined();
      const rm = c.policy.smartRules.find((r) => r.name === 'review-rm');
      expect(rm?.verdict).toBe('review');
    });

    it("K4b: cloud Class-A 'off' applies verbatim — the 3 -sql advisories are NOT injected", () => {
      keyed();
      mc({ commandChecks: { sqlDdl: 'off' } });
      const names = cfg().policy.smartRules.map((r) => r.name);
      expect(names).not.toContain('review-drop-table-sql');
      expect(names).not.toContain('review-truncate-sql');
      expect(names).not.toContain('review-drop-column-sql');
    });

    it("K4c: cloud rmAdvisory 'block' escalates the injected advisory, pinned", () => {
      keyed();
      mc({ commandChecks: { rmAdvisory: 'block' } });
      const rm = cfg().policy.smartRules.find((r) => r.name === 'review-rm');
      expect(rm?.verdict).toBe('block');
      expect(rm?.pinned).toBe(true);
    });

    it("K4d: a hostile hand-edited cache cannot set a Class-B key to 'off'", () => {
      keyed();
      mc({ commandChecks: { evalDynamic: 'off' } });
      // Mutation kill: dropping the Class-B guard in the keyed pass lands 'off'.
      expect(cfg().policy.commandChecks?.evalDynamic).not.toBe('off');
    });
  });

  // ── K5 approvers / reviewChannel / timeout ────────────────────────────────
  describe('K5 approvers / reviewChannel / timeout', () => {
    it('K5a: keyed default approvers.cloud=true — with AND without the local login-v2 seed', () => {
      keyed();
      writeGlobal({ settings: { approvers: { cloud: true } } }); // the login seed (local, ignored)
      expect(cfg().settings.approvers.cloud).toBe(true);
      // Mutation kill (§0.3): a keyed pass starting from plain DEFAULT_CONFIG
      // has cloud:false when NO local seed exists — audit shipping goes dark.
      writeGlobal({ settings: {} });
      expect(cfg().settings.approvers.cloud).toBe(true);
    });

    it('K5b: cloud approvers replace per-field over the keyed defaults', () => {
      keyed();
      mc({ approvers: { terminal: false } });
      expect(cfg().settings.approvers).toEqual({
        native: true,
        browser: false,
        cloud: true,
        terminal: false,
      });
    });

    it('K5c: local reviewChannel dropped; cloud-silent = unset (smart default)', () => {
      keyed();
      writeGlobal({ settings: { reviewChannel: 'approver' } });
      const c = cfg();
      expect(c.settings.reviewChannel).toBeUndefined();
      expect(c.settings.reviewChannelManaged).not.toBe(true);
    });

    it("K5d: cloud reviewChannel 'ask' applies + is marked managed", () => {
      keyed();
      mc({ reviewChannel: 'ask' });
      const c = cfg();
      expect(c.settings.reviewChannel).toBe('ask');
      expect(c.settings.reviewChannelManaged).toBe(true);
    });

    it('K5e: local timeout alias ignored; a cloud 0 is rejected — DEFAULT 120000 stands', () => {
      keyed();
      writeGlobal({ settings: { approvalTimeoutSeconds: 30 } });
      mc({ approvalTimeoutMs: 0 });
      expect(cfg().settings.approvalTimeoutMs).toBe(120_000);
    });
  });

  // ── K6-K8 injectionScan / loopDetection / skillPinning ────────────────────
  describe('K6-K8 detections', () => {
    it('K6a: local injectionScan opt-in dropped — cloud-silent = DEFAULT off (a keyed LOOSENING, deliberate)', () => {
      keyed();
      writeGlobal({ policy: { injectionScan: { enabled: true } } });
      expect(cfg().policy.injectionScan.enabled).toBe(false);
    });

    it('K6b: cloud injectionScan applies verbatim', () => {
      keyed();
      mc({ injectionScan: { enabled: true, minConfidence: 'high', allow: ['webfetch'] } });
      expect(cfg().policy.injectionScan).toEqual({
        enabled: true,
        minConfidence: 'high',
        allow: ['webfetch'],
      });
    });

    it('K7a: local loopDetection off dropped — DEFAULT on 5/120 (tightening direction)', () => {
      keyed();
      writeGlobal({ policy: { loopDetection: { enabled: false } } });
      expect(cfg().policy.loopDetection).toEqual({
        enabled: true,
        threshold: 5,
        windowSeconds: 120,
      });
    });

    it('K7b: cloud loopDetection off applies verbatim', () => {
      keyed();
      mc({ loopDetection: { enabled: false } });
      expect(cfg().policy.loopDetection.enabled).toBe(false);
    });

    it('K8a: local skillPinning roots never union keyed — cloud roots only', () => {
      keyed();
      writeGlobal({ policy: { skillPinning: { enabled: true, roots: ['/x'] } } });
      mc({ skillPinning: { enabled: true, mode: 'block', roots: ['/y'] } });
      const c = cfg();
      expect(c.policy.skillPinning.roots).toEqual(['/y']);
      expect(c.policy.skillPinning.mode).toBe('block');
    });
  });

  // ── K9 jailPaths ──────────────────────────────────────────────────────────
  describe('K9 jailPaths', () => {
    it('K9a: cloud jailPaths land as managedJailPaths + org:-prefixed rules', () => {
      keyed();
      mc({ jailPaths: [{ path: '~/.aws', verdict: 'block' }] });
      const c = cfg();
      expect(c.policy.managedJailPaths).toEqual([{ path: '~/.aws', verdict: 'block' }]);
      expect(c.policy.smartRules.some((r) => r.name?.startsWith('org:'))).toBe(true);
    });

    it('K9b: a pre-login local user-jail is dead keyed (unkeyed instrument row first)', () => {
      // The local jail shield exists and is enabled locally.
      shieldState.active = ['user-jail'];
      shieldState.userShields['user-jail'] = {
        name: 'user-jail',
        description: 'user jail',
        aliases: [],
        smartRules: [
          {
            name: 'user-jail:block-secrets',
            tool: '*',
            conditions: [{ field: 'file_path', op: 'contains', value: '/secrets/' }],
            conditionMode: 'all',
            verdict: 'block',
            reason: 'jailed path',
          },
        ],
        dangerousWords: [],
      };
      // INSTRUMENT (known-true) row: unkeyed, the jail shield applies.
      const before = cfg();
      expect(before.policy.appliedShields).toContain('user-jail');
      expect(before.policy.smartRules.some((r) => r.name === 'user-jail:block-secrets')).toBe(true);
      // Same fixture + a key: the local jail contributes NOTHING (guard-arming
      // reads appliedShields ∪ managedJailPaths — both empty here, §0.4).
      keyed();
      const after = cfg();
      expect(after.policy.appliedShields).toEqual([]);
      expect(after.policy.smartRules.some((r) => r.name === 'user-jail:block-secrets')).toBe(false);
      expect(after.policy.managedJailPaths).toEqual([]);
    });
  });

  // ── K10-K11 trustedHosts / appPermissions ─────────────────────────────────
  describe('K10-K11 trustedHosts / appPermissions', () => {
    it('K10a: keyed forces trustedHostsManaged=true with an empty list — the local trust file is never consulted', () => {
      keyed();
      // Pre-login `node9 trust add evil.exfil.com` artifact:
      fs.writeFileSync(
        path.join(home, '.node9', 'trusted-hosts.json'),
        JSON.stringify({ hosts: ['evil.exfil.com'] })
      );
      const c = cfg();
      // Mutation kill: forgetting the force leaves managed=false → the policy
      // hook falls back to the fresh local-file read → downgrade leaks through.
      expect(c.policy.trustedHostsManaged).toBe(true);
      expect(c.policy.trustedHosts).toEqual([]);
    });

    it('K10b: cloud trustedHosts are normalized (scheme/port stripped) and managed', () => {
      keyed();
      mc({ trustedHosts: ['https://api.co:443'] });
      const c = cfg();
      expect(c.policy.trustedHosts).toEqual(['api.co']);
      expect(c.policy.trustedHostsManaged).toBe(true);
    });

    it('K11a: cloud appPermissions apply keyed (gateway enforcement pinned in app-permissions.spec.ts)', () => {
      keyed();
      mc({ appPermissions: { ghKey: { delete_repo: 'block' } } });
      expect(cfg().policy.appPermissions).toEqual({ ghKey: { delete_repo: 'block' } });
    });

    it('K11b: cloud-silent appPermissions = {} — there is no local layer to miss', () => {
      keyed();
      writeGlobal({ policy: { appPermissions: { local: { x: 'allow' } } } }); // never merged
      mc({});
      expect(cfg().policy.appPermissions).toEqual({});
    });
  });

  // ── K12 shields ───────────────────────────────────────────────────────────
  describe('K12 shields', () => {
    it('K12a: keyed runs the CLOUD-mandated shields only; local enables and overrides are inert', () => {
      keyed();
      shieldState.active = ['filesystem']; // local enable — must contribute nothing
      shieldState.overrides = { redis: { 'shield:redis:block-flushall': 'allow' } }; // local weaken attempt
      writeCache({ shields: ['redis'] });
      const c = cfg();
      // Mutation kill: keeping the local∪cloud union keyed lists filesystem too.
      expect(c.policy.appliedShields).toEqual(['redis']);
      expect(c.policy.smartRules.some((r) => r.name?.startsWith('shield:filesystem:'))).toBe(false);
      const flushall = c.policy.smartRules.find((r) => r.name === 'shield:redis:block-flushall');
      expect(flushall?.verdict).toBe('block'); // the override never applied to a mandate
      expect(flushall?.pinned).toBe(true);
    });

    it('K12b: a user shadow of a mandated shield is ignored — BUILTIN body enforced (B1)', () => {
      keyed();
      shieldState.userShields['redis'] = {
        name: 'redis',
        description: 'all-allow shadow',
        aliases: [],
        smartRules: [
          {
            name: 'shield:redis:block-flushall',
            tool: '*',
            conditions: [],
            conditionMode: 'all',
            verdict: 'allow',
            reason: 'weakened',
          },
        ],
        dangerousWords: [],
      };
      writeCache({ shields: ['redis'] });
      const c = cfg();
      const flushall = c.policy.smartRules.find((r) => r.name === 'shield:redis:block-flushall');
      expect(flushall?.verdict).toBe('block');
      expect(
        c.policy.smartRules.filter((r) => r.name === 'shield:redis:block-flushall')
      ).toHaveLength(1);
    });

    it('K12c: an unknown mandated shield fails CLOSED (dropped) without throwing', () => {
      keyed();
      writeCache({ shields: ['redis', 'not-a-shield'] });
      expect(cfg().policy.appliedShields).toEqual(['redis']);
    });
  });

  // ── K13 smartRules ────────────────────────────────────────────────────────
  describe('K13 smartRules', () => {
    it('K13a: a local same-name override of a DEFAULT rule is dead — the default is restored (STRICTER keyed)', () => {
      keyed();
      writeGlobal({
        policy: {
          smartRules: [
            {
              name: 'review-sudo',
              tool: 'bash',
              conditions: [{ field: 'command', op: 'matches', value: '\\bsudo\\s' }],
              conditionMode: 'all',
              verdict: 'allow',
              reason: 'local defeat attempt',
            },
          ],
        },
      });
      const sudo = cfg().policy.smartRules.filter((r) => r.name === 'review-sudo');
      expect(sudo).toHaveLength(1);
      expect(sudo[0].verdict).toBe('review');
    });

    it('K13b: a repo-carried block rule is fully inert keyed', () => {
      keyed();
      writeRepo({
        policy: {
          smartRules: [
            {
              name: 'repo-block-x',
              tool: 'bash',
              conditions: [{ field: 'command', op: 'contains', value: 'xyz' }],
              conditionMode: 'all',
              verdict: 'block',
              reason: 'repo rule',
            },
          ],
        },
      });
      expect(cfg().policy.smartRules.some((r) => r.name === 'repo-block-x')).toBe(false);
    });

    // The cloud cache's `rules` array routes through applyLayer, and the PR-2
    // fork's keyed gate initially swallowed it — a KEYED machine dropped every
    // workspace smart rule (found as an it.fails pin while writing this
    // matrix). Fixed by the isCloud flag: the cloud layer is the one applyLayer
    // caller that passes the gate. Mutation twin: reverting `keyed && !isCloud`
    // to `keyed` kills this row.
    it('K13c: cloud cache rules are enforced keyed', () => {
      keyed();
      writeCache({
        rules: [
          {
            name: 'org-block-x',
            tool: 'bash',
            conditions: [{ field: 'command', op: 'contains', value: 'xyz' }],
            conditionMode: 'all',
            verdict: 'block',
            reason: 'org rule',
          },
        ],
      });
      expect(cfg().policy.smartRules.some((r) => r.name === 'org-block-x')).toBe(true);
    });

    it('K13c-instrument: the same cache rules DO apply unkeyed (known-true witness)', () => {
      writeCache({
        rules: [
          {
            name: 'org-block-x',
            tool: 'bash',
            conditions: [{ field: 'command', op: 'contains', value: 'xyz' }],
            conditionMode: 'all',
            verdict: 'block',
            reason: 'org rule',
          },
        ],
      });
      expect(cfg().policy.smartRules.some((r) => r.name === 'org-block-x')).toBe(true);
    });
  });

  // ── K14-K18 cloud-inexpressible families fall to DEFAULT ──────────────────
  describe('K14-K18 cloud-inexpressible families', () => {
    it('K14: local ignoredTools additions dropped — DEFAULT list only', () => {
      keyed();
      writeGlobal({ policy: { ignoredTools: ['bash'] } });
      mc({ egress: { enabled: true, mode: 'block' } });
      const c = cfg();
      expect(c.policy.ignoredTools).not.toContain('bash');
      expect(c.policy.ignoredTools).toEqual(
        expect.arrayContaining(DEFAULT_CONFIG.policy.ignoredTools)
      );
    });

    it('K15: local sandboxPaths additions dropped — DEFAULT only', () => {
      keyed();
      writeGlobal({ policy: { sandboxPaths: ['/**'] } });
      expect(cfg().policy.sandboxPaths).not.toContain('/**');
    });

    it('K16: local dangerousWords weakening replace ([]) is dead — DEFAULT words restored', () => {
      keyed();
      writeGlobal({ policy: { dangerousWords: [] } });
      expect(cfg().policy.dangerousWords).toContain('mkfs');
    });

    it('K17: local toolInspection mapping is a permanent, cloud-inexpressible loss (pinned deliberate, §0.15)', () => {
      keyed();
      writeGlobal({ policy: { toolInspection: { 'my_db:query': 'sql' } } });
      expect(cfg().policy.toolInspection['my_db:query']).toBeUndefined();
    });

    it('K18: local environments + settings.environment are gone keyed', () => {
      keyed();
      writeGlobal({
        settings: { environment: 'production' },
        environments: { production: { requireApproval: true } },
      });
      const c = cfg();
      expect(c.environments).toEqual({});
      expect(c.settings.environment).toBeUndefined();
    });
  });

  // ── K19 operational pass stays local ──────────────────────────────────────
  describe('K19 operational settings', () => {
    it('K19: operational knobs keep working keyed — the fork SPLITS applyLayer, it does not skip it', () => {
      keyed();
      writeGlobal({
        settings: {
          autoStartDaemon: false,
          enableHookLogDebug: false,
          shipper: { intervalSeconds: 99 },
          mcpReconcileIntervalMinutes: 30,
        },
      });
      const c = cfg();
      // Mutation kill: skipping the whole local layer loses all four.
      expect(c.settings.autoStartDaemon).toBe(false);
      expect(c.settings.enableHookLogDebug).toBe(false);
      expect(c.settings.shipper.intervalSeconds).toBe(99);
      expect(c.settings.mcpReconcileIntervalMinutes).toBe(30);
      // (settings.hud is stripped by the config schema before the merge — it is
      // not exercisable through a config file; not asserted here.)
    });
  });

  // ── keyedness detection (the --local promise, profiles, env keys) ─────────
  describe('keyedness detection', () => {
    it('localOnly credentials (`login --local`) keep FULL local behavior (§0.1 — the printed promise)', () => {
      fs.writeFileSync(
        path.join(home, '.node9', 'credentials.json'),
        JSON.stringify({ default: { apiKey: 'n9_local_key', localOnly: true } })
      );
      writeGlobal({ settings: { mode: 'strict' } });
      const c = cfg();
      expect(c.settings.mode).toBe('strict');
      expect(c.policySource).toBe('local');
    });

    it('a NAMED profile key is localOnly-for-policy (§0.11 — profiles never policy-sync)', () => {
      fs.writeFileSync(
        path.join(home, '.node9', 'credentials.json'),
        JSON.stringify({ work: { apiKey: 'n9_work_key' } })
      );
      process.env.NODE9_PROFILE = 'work';
      writeGlobal({ settings: { mode: 'strict' } });
      const c = cfg();
      expect(c.settings.mode).toBe('strict');
      expect(c.policySource).toBe('local');
    });

    it('an ENV key (CI) is fully keyed — no localOnly channel', () => {
      process.env.NODE9_API_KEY = 'n9_ci_key';
      writeGlobal({ settings: { mode: 'strict' } });
      const c = cfg();
      expect(c.settings.mode).toBe('standard');
      expect(c.policySource).toBe('workspace');
    });

    it('policySource: workspace when keyed, local when unkeyed', () => {
      expect(cfg().policySource).toBe('local');
      keyed();
      expect(cfg().policySource).toBe('workspace');
    });
  });
});
