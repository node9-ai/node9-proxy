// src/__tests__/addon-enforcement.spec.ts
// node9Firewall#376 item 6, phase 3: the workspace's approved list of add-ons
// reaches the effective config from the managed cache only, and a verdict the
// caller resolved (gateway: its server; hook: the server or skill a call uses)
// is enforced in the authorize path the way an app permission is.
// Mirrors app-permissions.spec.ts.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';
import { authorizeHeadless, _resetConfigCache as _resetCore } from '../core.js';
import type { AddonVerdict } from '../addons/policy';

const { mockTrustSession, auditSpy } = vi.hoisted(() => ({
  mockTrustSession: vi.fn((..._a: unknown[]): unknown => null),
  auditSpy: vi.fn(),
}));
vi.mock('../audit', async (importOriginal) => {
  const real = await importOriginal<typeof import('../audit')>();
  return {
    ...real,
    appendLocalAudit: (...a: Parameters<typeof real.appendLocalAudit>) => {
      auditSpy(...a);
    },
  };
});
vi.mock('../auth/state', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../auth/state')>()),
  getActiveTrustSession: (...a: unknown[]) => mockTrustSession(...a),
}));
vi.mock('../auth/cloud', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../auth/cloud')>()),
  initNode9SaaS: vi.fn(async () => ({ pending: false })),
  pollNode9SaaS: vi.fn(async () => ({ approved: false })),
  resolveNode9SaaS: vi.fn(async () => undefined),
}));

const ADDONS = {
  unapproved: 'block',
  mcp: { 'npm:@acme/db-mcp': 'blocked' },
  skills: {},
  plugins: {},
};

const BLOCK: AddonVerdict = {
  action: 'block',
  reason: 'the MCP server "npm:@acme/db-mcp" is on your workspace\'s block list.',
  ruleName: 'addon:mcp:npm:@acme/db-mcp',
};
const REVIEW: AddonVerdict = {
  action: 'review',
  reason:
    'the skill "deploy" is not on your workspace\'s approved list, so a person must approve this use.',
  ruleName: 'addon:skill:deploy',
};

describe('the approved list of add-ons on the machine (phase 3)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;
  let origMode: string | undefined;

  function seed(local: object, managed: object | null): void {
    fs.writeFileSync(path.join(tmpHome, '.node9', 'config.json'), JSON.stringify(local));
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.json'),
      JSON.stringify({
        fetchedAt: '2026-11-24T00:00:00Z',
        rules: [],
        ...(managed ? { managedConfig: { ...managed, locked: [] } } : {}),
      })
    );
    _resetConfigCache();
    _resetCore();
  }

  const standard = {
    settings: {
      mode: 'standard',
      approvalTimeoutMs: 0,
      approvers: { native: false, browser: false, cloud: false, terminal: false },
    },
    policy: {},
  };

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-addon-gate-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    origMode = process.env.NODE9_MODE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    delete process.env.NODE9_MODE;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    mockTrustSession.mockReturnValue(null);
    auditSpy.mockReset();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    if (origMode !== undefined) process.env.NODE9_MODE = origMode;
    else delete process.env.NODE9_MODE;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
    _resetCore();
  });

  it('applies the managed list to config.policy.addons', () => {
    seed(standard, { addons: ADDONS });
    expect(getConfig().policy.addons).toEqual(ADDONS);
  });

  it('a local config cannot write the list (cloud-only)', () => {
    seed({ ...standard, policy: { addons: { unapproved: 'off', mcp: {} } } }, null);
    expect(getConfig().policy.addons).toBeUndefined();
  });

  it('blocks a call whose add-on is blocked, and names the rule in the audit row', async () => {
    seed(standard, { addons: ADDONS });
    const r = await authorizeHeadless(
      'query',
      {},
      { agent: 'MCP-Gateway', serverKey: 'k1', addon: BLOCK }
    );
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toContain('Add-on');
    expect(r.reason).toBe(BLOCK.reason);
    expect(auditSpy).toHaveBeenCalledWith(
      'query',
      {},
      'deny',
      'addon-block',
      expect.objectContaining({ ruleName: 'addon:mcp:npm:@acme/db-mcp' }),
      expect.anything()
    );
  });

  it('a review reaches the approver race (denied here only because none exists)', async () => {
    seed(standard, { addons: { ...ADDONS, unapproved: 'review' } });
    const r = await authorizeHeadless(
      'Skill',
      { skill: 'deploy' },
      {
        agent: 'Claude Code',
        addon: REVIEW,
      }
    );
    expect(r.approved).toBe(false);
    expect(r.noApprovalMechanism).toBe(true);
    expect(r.blockedByLabel).toContain('Add-on (Review)');
  });

  it('a standing trust session does not answer an add-on review', async () => {
    seed(standard, { addons: { ...ADDONS, unapproved: 'review' } });
    mockTrustSession.mockReturnValue({ pattern: 'Skill', expiresAt: Date.now() + 60_000 });
    const r = await authorizeHeadless(
      'Skill',
      { skill: 'deploy' },
      {
        agent: 'Claude Code',
        addon: REVIEW,
      }
    );
    expect(r.approved).toBe(false);
  });

  it('a list that blocks floors a local observe to standard (a mandate)', async () => {
    seed({ ...standard, settings: { ...standard.settings, mode: 'observe' } }, { addons: ADDONS });
    expect(getConfig().settings.mode).toBe('standard');
    const r = await authorizeHeadless('query', {}, { agent: 'MCP-Gateway', addon: BLOCK });
    expect(r.approved).toBe(false);
  });

  it('a list that only logs mandates nothing: a self-chosen observe stays', () => {
    seed(
      { ...standard, settings: { ...standard.settings, mode: 'observe' } },
      { addons: { unapproved: 'log', mcp: { 'npm:a': 'approved' }, skills: {}, plugins: {} } }
    );
    expect(getConfig().settings.mode).toBe('observe');
  });
});
