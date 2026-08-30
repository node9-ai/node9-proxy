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

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

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
