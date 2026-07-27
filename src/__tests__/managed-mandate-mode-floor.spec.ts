// src/__tests__/managed-mandate-mode-floor.spec.ts
//
// Task #21 — a LOCAL `mode: observe|audit` must not nullify an ORG mandate.
//
// observe/audit make the orchestrator return approved:true for every call
// before any enforcement gate runs. B1 #1 saw this and floored the mode to
// standard under a mandated SHIELD — its comment states the principle
// ("a mandated shield must actually enforce") but the condition was keyed on
// shields alone. Every other org mandate (appPermissions, jailPaths, egress,
// dlp, commandChecks, injectionScan, skillPinning, loopDetection) was silently
// unenforced: verified at the gate as real ALLOWS (org jail block → the agent
// read the jailed file; org appPermissions block → the gateway called the
// blocked tool; org dlp block → an AWS key went through).
//
// Reachability was the refutation that had to fail before this counted: the
// SaaS resolver types `mode?: string` over a nullable row, so an admin who sets
// only app permissions ships managedConfig with NO mode — modeCloudControlled
// stays false and the local observe wins. Confirmed against the real
// resolveScopedManaged.
//
// A cloud-CHOSEN observe (mc.mode) or a shadowMode staged rollout is the
// fleet's own decision and is still honoured — asserted below so the fix
// can't over-tighten.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';
import { authorizeHeadless, _resetConfigCache as _resetCore } from '../core.js';

/** Composed so this file never trips DLP itself (repo convention). */
const FAKE_AWS_KEY = 'AKIA' + 'J2XZKZMV' + 'P3NQRSTU';

/** Local config asks for the no-enforcement posture; approvers off so a review
 *  can't hang — a fall-through then resolves deterministically. */
const LOCAL_OBSERVE = {
  settings: {
    mode: 'observe',
    approvalTimeoutMs: 0,
    approvers: { native: false, browser: false, cloud: false, terminal: false },
  },
  policy: {},
};

describe('a local observe/audit must not nullify an org mandate (task #21)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;
  let origNode9Mode: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-mandate-floor-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    origNode9Mode = process.env.NODE9_MODE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    delete process.env.NODE9_MODE;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    _resetConfigCache();
    _resetCore();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    if (origNode9Mode !== undefined) process.env.NODE9_MODE = origNode9Mode;
    else delete process.env.NODE9_MODE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
    _resetCore();
  });

  /** Seed a local config + a cloud rules-cache, then resolve fresh. */
  function seed(local: object, cache: object): void {
    fs.writeFileSync(path.join(tmpHome, '.node9', 'config.json'), JSON.stringify(local));
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.json'),
      JSON.stringify({ fetchedAt: '2026-07-01T00:00:00Z', rules: [], ...cache })
    );
    _resetConfigCache();
    _resetCore();
  }

  // ── Every org mandate must floor a local observe ──────────────────────────
  // One case per mandate type the SaaS can ship. `shields` is the CONTROL: it
  // passed before this fix, so if it ever fails the harness itself is broken.
  const MANDATES: Array<[string, object]> = [
    ['shields (CONTROL — floored before this fix too)', { shields: ['project-jail'] }],
    ['appPermissions', { managedConfig: { appPermissions: { srv1: { write_file: 'block' } } } }],
    ['jailPaths', { managedConfig: { jailPaths: [{ path: '~/.secrets', verdict: 'block' }] } }],
    ['egress', { managedConfig: { egress: { enabled: true, mode: 'block', allow: [] } } }],
    ['dlp', { managedConfig: { dlp: { enabled: true, reviewAction: 'block' } } }],
    ['commandChecks', { managedConfig: { commandChecks: { pipeChainHigh: 'block' } } }],
    ['injectionScan', { managedConfig: { injectionScan: { enabled: true } } }],
    ['skillPinning', { managedConfig: { skillPinning: { enabled: true } } }],
    ['loopDetection', { managedConfig: { loopDetection: { enabled: true } } }],
  ];

  for (const [label, cache] of MANDATES) {
    it(`org mandate ${label} floors a local observe to standard`, () => {
      seed(LOCAL_OBSERVE, cache);
      expect(getConfig().settings.mode).toBe('standard');
    });
  }

  it('the same floor applies to a local AUDIT mode', () => {
    seed(
      { ...LOCAL_OBSERVE, settings: { ...LOCAL_OBSERVE.settings, mode: 'audit' } },
      { managedConfig: { appPermissions: { srv1: { write_file: 'block' } } } }
    );
    expect(getConfig().settings.mode).toBe('standard');
  });

  it('the floor also beats NODE9_MODE=observe (the env-var route)', () => {
    process.env.NODE9_MODE = 'observe';
    seed(
      { settings: { mode: 'standard' }, policy: {} },
      { managedConfig: { jailPaths: [{ path: '~/.secrets', verdict: 'block' }] } }
    );
    expect(getConfig().settings.mode).toBe('standard');
  });

  // ── The mandates must actually ENFORCE at the gate, not just resolve ──────
  // A config-layer assertion alone would not prove the allow is gone; these are
  // the three probes that came back ALLOWED (checkedBy:'audit') before the fix.
  it('org appPermissions block: the gateway call is blocked, not audit-allowed', async () => {
    seed(LOCAL_OBSERVE, {
      managedConfig: { appPermissions: { srv1: { write_file: 'block' } } },
    });
    const r = await authorizeHeadless(
      'write_file',
      { path: '/x' },
      { agent: 'MCP-Gateway', serverKey: 'srv1' } // the exact shape mcp-gateway sends
    );
    expect(r.approved).toBe(false);
    expect(r.checkedBy).not.toBe('audit');
  });

  it('org jailPaths block: the jailed read is blocked, not audit-allowed', async () => {
    seed(LOCAL_OBSERVE, {
      managedConfig: { jailPaths: [{ path: '~/.secrets', verdict: 'block' }] },
    });
    const r = await authorizeHeadless(
      'Bash',
      { command: 'cat ~/.secrets/key.txt' },
      { agent: 'MCP' }
    );
    expect(r.approved).toBe(false);
    expect(r.checkedBy).not.toBe('audit');
  });

  it('org dlp block: a secret in args is blocked, not audit-allowed', async () => {
    seed(LOCAL_OBSERVE, { managedConfig: { dlp: { enabled: true, reviewAction: 'block' } } });
    const r = await authorizeHeadless(
      'Bash',
      { command: `echo ${FAKE_AWS_KEY}` },
      { agent: 'MCP' }
    );
    expect(r.approved).toBe(false);
    expect(r.checkedBy).not.toBe('audit');
  });

  // ── Over-tightening guards: these must STAY observe ───────────────────────
  it('no org mandate at all — a self-chosen observe is untouched', () => {
    seed(LOCAL_OBSERVE, {});
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('an all-`allow` appPermissions map mandates no enforcement — stays observe', () => {
    seed(LOCAL_OBSERVE, {
      managedConfig: { appPermissions: { srv1: { read_file: 'allow' } } },
    });
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('an org mandate that is switched OFF does not floor — stays observe', () => {
    seed(LOCAL_OBSERVE, {
      managedConfig: {
        dlp: { enabled: false },
        egress: { enabled: false },
        commandChecks: { pipeChainHigh: 'off' },
        injectionScan: { enabled: false },
      },
    });
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('org routing/loosening settings are not enforcement mandates — stays observe', () => {
    // trustedHosts LOOSENS (widens pipe-chain trust); approvers/reviewChannel/
    // approvalTimeoutMs only route a review. None of them mandate enforcement,
    // so none may drag a self-chosen observe up to standard.
    seed(LOCAL_OBSERVE, {
      managedConfig: {
        trustedHosts: ['api.example.com'],
        approvers: { native: true },
        reviewChannel: 'slack',
        approvalTimeoutMs: 30000,
      },
    });
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('a purely LOCAL egress/dlp opt-in is the dev own choice — stays observe', () => {
    // The floor must key on the ORG's mandate, never on the merged result: a
    // dev who turns egress on locally and also picks observe keeps both.
    seed(
      {
        ...LOCAL_OBSERVE,
        policy: { egress: { enabled: true, mode: 'block' }, dlp: { enabled: true } },
      },
      {}
    );
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('a LOCAL appPermissions block does not floor the dev own observe', () => {
    // Currently near-vacuous — a local policy.appPermissions does not survive
    // the merge (verified: it resolves to {}). Kept to pin the INVARIANT: the
    // floor reads the cloud-derived map, so if local app permissions ever
    // become mergeable this stays correct instead of silently over-tightening.
    seed({ ...LOCAL_OBSERVE, policy: { appPermissions: { srv1: { write_file: 'block' } } } }, {});
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('a CLOUD-set observe is the fleet own decision — honoured over a mandate', () => {
    seed(LOCAL_OBSERVE, {
      managedConfig: {
        mode: 'observe',
        appPermissions: { srv1: { write_file: 'block' } },
      },
    });
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('a shadowMode staged rollout is honoured over a mandate', () => {
    seed(LOCAL_OBSERVE, {
      shadowMode: true,
      managedConfig: { appPermissions: { srv1: { write_file: 'block' } } },
    });
    expect(getConfig().settings.mode).toBe('observe');
  });

  it('a mandate never over-tightens a local STANDARD to strict', () => {
    seed(
      { settings: { mode: 'standard' }, policy: {} },
      { managedConfig: { appPermissions: { srv1: { write_file: 'block' } } } }
    );
    expect(getConfig().settings.mode).toBe('standard');
  });
});

// ── The other half of the app-permissions gauntlet ─────────────────────────
// The persistent "Always Allow" guard (`!appPermReview` in orchestrator.ts) is
// correct — but it had ZERO tests. An untested guard is how the shadowMode taint
// gap survived a whole commit, so pin it.
describe('a persistent "Always Allow" never resolves an org app permission', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-appperm-persistent-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 0,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
        },
        policy: {},
      })
    );
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.json'),
      JSON.stringify({
        fetchedAt: '2026-07-01T00:00:00Z',
        rules: [],
        managedConfig: {
          appPermissions: { srv1: { write_file: 'block', edit_file: 'review' } },
        },
      })
    );
    // The user clicked "Always Allow" on both tools at some earlier point —
    // before the org set its policy. getPersistentDecision reads this file.
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'decisions.json'),
      JSON.stringify({ write_file: 'allow', edit_file: 'allow' })
    );
    _resetConfigCache();
    _resetCore();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
    _resetCore();
  });

  it('does not bypass an org BLOCK', async () => {
    const r = await authorizeHeadless(
      'write_file',
      { path: '/x' },
      { agent: 'MCP-Gateway', serverKey: 'srv1' }
    );
    expect(r.approved).toBe(false);
    expect(r.checkedBy).not.toBe('persistent');
  });

  it('does not bypass an org REVIEW', async () => {
    const r = await authorizeHeadless(
      'edit_file',
      { path: '/x' },
      { agent: 'MCP-Gateway', serverKey: 'srv1' }
    );
    expect(r.approved).toBe(false);
    expect(r.checkedBy).not.toBe('persistent');
  });
});
