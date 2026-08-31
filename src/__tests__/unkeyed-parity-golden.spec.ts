// U0 — the UNKEYED PARITY GOLDEN (PR-2 matrix §U).
//
// Captured on the PRE-replace-mode tree: for a rich local config exercising
// every policy family, the resolved getConfig() output is frozen here. PR-2
// must keep every one of these assertions green — an unkeyed machine's
// behavior may not change by a single field. (The keyed world gets its own
// rows; this file is the other half of the contract.)
//
// Deliberately NOT a .snapshot file: a snapshot invites a thoughtless
// --update; these are hand-pinned assertions a diff review can read.

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { ShieldDefinition } from '../shields';

// The shields store paths are module-load consts frozen to the REAL home — a
// temp-HOME fixture can't move them. Mock the local-file readers (harness from
// applied-shields.spec.ts) so both the U0 golden and the U-rows below are
// hermetic against the dev machine's own shields.json. Defaults (empty) match
// a clean machine — the state U0 was captured against.
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

// getConfig caches ambient calls; cwd-scoped calls bypass the cache. We use
// a temp HOME + a temp cwd so the run is hermetic either way.
import { getConfig, _resetConfigCache } from '../config';

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-u0-'));
const PROJ = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-u0-proj-'));

const LOCAL_GLOBAL = {
  version: '1.0',
  settings: {
    mode: 'strict',
    approvalTimeoutMs: 45_000,
    approvers: { native: false, browser: false, cloud: true, terminal: true },
    reviewChannel: 'approver',
  },
  policy: {
    sandboxPaths: ['/custom/sandbox/**'],
    ignoredTools: ['my_custom_readonly'],
    dangerousWords: ['frobnicate'],
    toolInspection: { 'my_db:query': 'sql' },
    smartRules: [
      {
        name: 'local-rule-block-frob',
        tool: 'bash',
        conditionMode: 'all',
        conditions: [{ field: 'command', op: 'contains', value: 'frobnicate' }],
        verdict: 'block',
        reason: 'local custom rule',
      },
    ],
    egress: {
      enabled: true,
      mode: 'block',
      allow: ['api.allowed.example'],
      deny: ['evil.example'],
      allowPrivate: false,
    },
    dlp: { enabled: false, scanIgnoredTools: false, pii: 'block' },
    loopDetection: { enabled: false, threshold: 9, windowSeconds: 60 },
    injectionScan: { enabled: true, minConfidence: 'high', allow: ['Read'] },
    skillPinning: { enabled: true, mode: 'block', roots: ['/skills'] },
    trustedHosts: ['trusted.corp.example'],
    commandChecks: { inlineExec: 'block', rmAdvisory: 'off' },
  },
  environments: {
    prod: { requireApproval: true, patterns: ['deploy*'] },
  },
};

const LOCAL_PROJECT = {
  version: '1.0',
  policy: {
    // repo-carried config may only TIGHTEN — pinned by existing suites; here
    // it contributes one extra sandbox path so the merge itself is witnessed.
    sandboxPaths: ['/proj/tmp/**'],
  },
};

beforeAll(() => {
  fs.mkdirSync(path.join(HOME, '.node9'), { recursive: true });
  fs.writeFileSync(path.join(HOME, '.node9', 'config.json'), JSON.stringify(LOCAL_GLOBAL, null, 2));
  fs.writeFileSync(path.join(PROJ, 'node9.config.json'), JSON.stringify(LOCAL_PROJECT, null, 2));
  process.env.HOME = HOME;
  process.env.USERPROFILE = HOME;
  delete process.env.NODE9_API_KEY;
  delete process.env.NODE9_API_URL;
  delete process.env.NODE9_PROFILE;
  delete process.env.NODE9_MODE;
  _resetConfigCache();
});

afterAll(() => {
  fs.rmSync(HOME, { recursive: true, force: true });
  fs.rmSync(PROJ, { recursive: true, force: true });
});

describe('U0 — unkeyed golden: the local stack resolves EXACTLY as today', () => {
  it('U0.1 settings: mode/timeout/approvers/reviewChannel come from the local file', () => {
    const c = getConfig(PROJ);
    expect(c.settings.mode).toBe('strict');
    expect(c.settings.approvalTimeoutMs).toBe(45_000);
    expect(c.settings.approvers).toEqual({
      native: false,
      browser: false,
      cloud: true,
      terminal: true,
    });
    expect(c.settings.reviewChannel).toBe('approver');
  });

  it('U0.2 egress: the full local family survives verbatim', () => {
    const c = getConfig(PROJ);
    expect(c.policy.egress).toMatchObject({
      enabled: true,
      mode: 'block',
      allowPrivate: false,
    });
    expect(c.policy.egress.allow).toContain('api.allowed.example');
    expect(c.policy.egress.deny).toContain('evil.example');
  });

  it('U0.3 dlp: local managed-OFF holds (enabled:false, pii block)', () => {
    const c = getConfig(PROJ);
    expect(c.policy.dlp.enabled).toBe(false);
    expect(c.policy.dlp.pii).toBe('block');
  });

  it('U0.4 detection: loop off, injection high, skill block — all local', () => {
    const c = getConfig(PROJ);
    expect(c.policy.loopDetection.enabled).toBe(false);
    expect(c.policy.loopDetection.threshold).toBe(9);
    expect(c.policy.injectionScan.minConfidence).toBe('high');
    expect(c.policy.skillPinning.mode).toBe('block');
    expect(c.policy.skillPinning.roots).toContain('/skills');
  });

  it('U0.5 commandChecks: local values incl. Class-A off are honored', () => {
    const c = getConfig(PROJ);
    expect(c.policy.commandChecks?.inlineExec).toBe('block');
    expect(c.policy.commandChecks?.rmAdvisory).toBe('off');
  });

  it('U0.6 the cloud-inexpressible families come from local: sandbox/ignored/dangerous/toolInspection/environments', () => {
    const c = getConfig(PROJ);
    expect(c.policy.sandboxPaths).toContain('/custom/sandbox/**');
    expect(c.policy.sandboxPaths).toContain('/proj/tmp/**'); // project layer merged
    expect(c.policy.ignoredTools).toContain('my_custom_readonly');
    expect(c.policy.dangerousWords).toContain('frobnicate');
    expect(c.policy.toolInspection['my_db:query']).toBe('sql');
    expect(c.environments?.prod?.requireApproval).toBe(true);
  });

  it('U0.7 local smartRules are present alongside the defaults', () => {
    const c = getConfig(PROJ);
    const names = c.policy.smartRules.map((r) => r.name);
    expect(names).toContain('local-rule-block-frob');
    expect(names).toContain('block-rm-rf-home'); // a shipped default survives
  });

  it('U0.9 policySource: an unkeyed machine reports the local stack', () => {
    expect(getConfig(PROJ).policySource).toBe('local');
  });

  it('U0.8 trustedHosts: config.json does NOT feed the list on unkeyed (measured)', () => {
    // Capturing this golden REVEALED the real behavior: a `trustedHosts`
    // array in local config.json is ignored — the unkeyed trust store is
    // the separate ~/.node9/trusted-hosts.json, read FRESH at eval time
    // (policy/index.ts isTrustedHost → getCachedHosts). The config field
    // is populated only by the CLOUD path. Pinned as-is: replace-mode
    // must not change either half.
    const c = getConfig(PROJ);
    expect(c.policy.trustedHosts).toEqual([]);
    expect(c.policy.trustedHostsManaged).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// §U rows U1-U15 — per-family unkeyed twins of the §K keyed rows
// (keyed-replace.spec.ts). Each row runs the SAME fixture shape as its K twin
// with the key ABSENT and asserts TODAY'S law holds.
//
// MUTATION NOTE: every row here kills the "fork condition inverted / keyed
// detection too broad" mutant class — U3/U7/U11/U13 in particular run WITH a
// rules-cache PRESENT and no credentials, so a `keyed = cache file exists`
// mutant flips them to cloud-replace behavior and they fail.
// ───────────────────────────────────────────────────────────────────────────
describe('§U — unkeyed byte-parity rows (U1-U17)', () => {
  let home: string;
  let proj: string;
  const savedEnv: Record<string, string | undefined> = {};
  const ENV_KEYS = ['NODE9_API_KEY', 'NODE9_API_URL', 'NODE9_PROFILE', 'NODE9_MODE'];

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-uparity-'));
    proj = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-uparity-proj-'));
    savedEnv.HOME = process.env.HOME;
    savedEnv.USERPROFILE = process.env.USERPROFILE;
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    for (const k of ENV_KEYS) delete process.env[k]; // UNKEYED by construction
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
    shieldState.active = [];
    shieldState.overrides = {};
    shieldState.userShields = {};
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(proj, { recursive: true, force: true });
    _resetConfigCache();
  });

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
  const cfg = () => {
    _resetConfigCache();
    return getConfig(proj);
  };

  it('U1 (K1a twin): local strict is honored', () => {
    writeGlobal({ settings: { mode: 'strict' } });
    expect(cfg().settings.mode).toBe('strict');
  });

  it('U2 (K1b twin): NODE9_MODE=observe is honored (no cache)', () => {
    process.env.NODE9_MODE = 'observe';
    expect(cfg().settings.mode).toBe('observe');
  });

  it("U3 (K1c twin): a managed observe is FLOORED away unkeyed — today's floor law kept", () => {
    writeCache({ managedConfig: { mode: 'observe', locked: [] } });
    expect(cfg().settings.mode).toBe('standard');
  });

  it('U4 (K2a twin): the local egress lock is enforced', () => {
    writeGlobal({
      policy: { egress: { enabled: true, mode: 'block', deny: ['evil.com'] } },
    });
    const c = cfg();
    expect(c.policy.egress.enabled).toBe(true);
    expect(c.policy.egress.mode).toBe('block');
    expect(c.policy.egress.deny).toContain('evil.com');
  });

  it('U5 (K2c twin): a repo may not widen the allowlist past the global one (egressAllowUserSet)', () => {
    writeGlobal({ policy: { egress: { enabled: true, mode: 'block', allow: ['mine.dev'] } } });
    writeRepo({ policy: { egress: { allow: ['evil.com'] } } });
    const c = cfg();
    expect(c.policy.egress.allow).toContain('mine.dev');
    expect(c.policy.egress.allow).not.toContain('evil.com');
  });

  it("U6 (K3a twin): local dlp OFF is honored (the user's own home)", () => {
    writeGlobal({ policy: { dlp: { enabled: false } } });
    expect(cfg().policy.dlp.enabled).toBe(false);
  });

  it('U7 (K3b twin): the managed dlp force-on floor keeps DLP ON unkeyed', () => {
    writeGlobal({ policy: { dlp: { enabled: true } } });
    writeCache({ managedConfig: { dlp: { enabled: false }, locked: [] } });
    expect(cfg().policy.dlp.enabled).toBe(true);
  });

  it('U8 (K4a twin): local commandChecks honored; a repo cannot weaken (rank clamp)', () => {
    writeGlobal({ policy: { commandChecks: { chmod: 'off', inlineExec: 'block' } } });
    writeRepo({ policy: { commandChecks: { inlineExec: 'off' } } });
    const c = cfg();
    expect(c.policy.commandChecks?.chmod).toBe('off');
    expect(c.policy.commandChecks?.inlineExec).toBe('block'); // repo 'off' clamped
  });

  it('U9 (K5a twin): approvers.cloud comes from the local seed — true when seeded, DEFAULT false when not', () => {
    writeGlobal({ settings: { approvers: { cloud: true } } });
    expect(cfg().settings.approvers.cloud).toBe(true);
    writeGlobal({ settings: {} });
    expect(cfg().settings.approvers.cloud).toBe(false);
  });

  it('U10 (K9b twin): a local user-jail shield applies — shield listed + its rules injected (task #20 law)', () => {
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
    const c = cfg();
    expect(c.policy.appliedShields).toContain('user-jail');
    expect(c.policy.smartRules.some((r) => r.name === 'user-jail:block-secrets')).toBe(true);
  });

  it('U11 (K12a twin): shields = local ∪ cloud union; overrides apply to LOCAL shields only', () => {
    shieldState.active = ['filesystem'];
    shieldState.overrides = {
      filesystem: { 'shield:filesystem:review-chmod-777': 'block' }, // local shield → applies
      redis: { 'shield:redis:block-flushall': 'allow' }, // mandated shield → ignored
    };
    writeCache({ shields: ['redis'] });
    const c = cfg();
    expect(c.policy.appliedShields).toEqual(['filesystem', 'redis']);
    const chmod = c.policy.smartRules.find((r) => r.name === 'shield:filesystem:review-chmod-777');
    expect(chmod?.verdict).toBe('block'); // local override honored on a local shield
    const flushall = c.policy.smartRules.find((r) => r.name === 'shield:redis:block-flushall');
    expect(flushall?.verdict).toBe('block'); // weaken attempt on a mandate ignored
  });

  it('U12 (K13a twin): a local same-name override of a default rule WINS unkeyed', () => {
    writeGlobal({
      policy: {
        smartRules: [
          {
            name: 'review-sudo',
            tool: 'bash',
            conditions: [{ field: 'command', op: 'matches', value: '\\bsudo\\s' }],
            conditionMode: 'all',
            verdict: 'allow',
            reason: 'my machine, my rule',
          },
        ],
      },
    });
    const sudo = cfg().policy.smartRules.filter((r) => r.name === 'review-sudo');
    expect(sudo).toHaveLength(1);
    expect(sudo[0].verdict).toBe('allow');
  });

  it('U13 (K14 twin + mandate): a mandated shield resets local ignoredTools/sandboxPaths (task #16/#24)', () => {
    writeGlobal({ policy: { ignoredTools: ['bash'], sandboxPaths: ['/**'] } });
    writeCache({ shields: ['redis'] });
    const c = cfg();
    expect(c.policy.ignoredTools).not.toContain('bash');
    expect(c.policy.sandboxPaths).not.toContain('/**');
  });

  it('U14 (K16/K17/K18 twins): dangerousWords replace, toolInspection merge, environments gate all work', () => {
    writeGlobal({
      settings: { environment: 'production' },
      policy: {
        dangerousWords: ['frobnicate'],
        toolInspection: { 'my_db:query': 'sql' },
      },
      environments: { production: { requireApproval: true } },
    });
    const c = cfg();
    expect(c.policy.dangerousWords).toContain('frobnicate');
    expect(c.policy.dangerousWords).not.toContain('mkfs'); // replace, not union
    expect(c.policy.toolInspection['my_db:query']).toBe('sql');
    expect(c.environments.production?.requireApproval).toBe(true);
    expect(c.settings.environment).toBe('production');
  });

  it('U15 (K19 twin): operational knobs work unkeyed (same pass)', () => {
    writeGlobal({
      settings: {
        autoStartDaemon: false,
        enableHookLogDebug: false,
        shipper: { intervalSeconds: 99 },
        mcpReconcileIntervalMinutes: 30,
      },
    });
    const c = cfg();
    expect(c.settings.autoStartDaemon).toBe(false);
    expect(c.settings.enableHookLogDebug).toBe(false);
    expect(c.settings.shipper.intervalSeconds).toBe(99);
    expect(c.settings.mcpReconcileIntervalMinutes).toBe(30);
  });

  it('U16: hook-debug logging is OFF when the config does not mention it', () => {
    // The DEBUG facility must not be on by default: when on, every tool call
    // appends to ~/.node9/hook-debug.log, which has no production reader and
    // no size ceiling. Absent key ⇒ off.
    writeGlobal({ settings: { mode: 'standard' } });
    expect(cfg().settings.enableHookLogDebug).toBe(false);
  });

  it('U17: an explicit enableHookLogDebug:true is still honored', () => {
    // Flipping the DEFAULT must not take the knob away from someone who asked
    // for it on purpose — that would be a second bug wearing the first's coat.
    writeGlobal({ settings: { mode: 'standard', enableHookLogDebug: true } });
    expect(cfg().settings.enableHookLogDebug).toBe(true);
  });
});
