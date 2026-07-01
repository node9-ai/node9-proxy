// src/__tests__/app-permissions.spec.ts
// P3 Phase 2 (GOVERN) — managed MCP per-tool permissions applied to config +
// enforced in the authorize path. Keyed by (serverKey, bareTool). A tightening
// gate: block hard-denies; review routes to the approver race (Phase 2.5);
// allow/unset fall through to normal policy.
// Mirrors trust-managed.spec.ts (managedConfig via rules-cache.json).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig, _resetConfigCache } from '../config';
import { authorizeHeadless, _resetConfigCache as _resetCore } from '../core.js';

// Controllable mocks for the review→approver race tests. Defaults are inert:
// no trust session (same as an empty trust file) and a cloud that's never
// consulted (cloud is only enforced when approvers.cloud && an API key exist,
// which the base config doesn't provide).
const { mockTrustSession, mockInitSaaS, mockPollSaaS } = vi.hoisted(() => ({
  mockTrustSession: vi.fn((..._a: unknown[]): unknown => null),
  mockInitSaaS: vi.fn(async (..._a: unknown[]): Promise<unknown> => ({ pending: false })),
  mockPollSaaS: vi.fn(async (..._a: unknown[]): Promise<unknown> => ({ approved: false })),
}));
vi.mock('../auth/state', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../auth/state')>()),
  getActiveTrustSession: (...a: unknown[]) => mockTrustSession(...a),
}));
vi.mock('../auth/cloud', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../auth/cloud')>()),
  initNode9SaaS: (...a: unknown[]) => mockInitSaaS(...a),
  pollNode9SaaS: (...a: unknown[]) => mockPollSaaS(...a),
  resolveNode9SaaS: vi.fn(async () => undefined),
}));

describe('managed appPermissions apply + enforce (P3 Phase 2)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-appperm-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    // standard mode, every approver surface off so a fall-through can't prompt.
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
          appPermissions: {
            srv1: {
              read_file: 'allow',
              write_file: 'block',
              edit_file: 'review',
              // review on an IGNORED-pattern tool (read_*) — must still race.
              read_email: 'review',
            },
          },
          locked: [],
        },
      })
    );
    _resetConfigCache();
    _resetCore();
    // Inert defaults — individual tests override.
    mockTrustSession.mockReturnValue(null);
    mockInitSaaS.mockResolvedValue({ pending: false });
    mockPollSaaS.mockResolvedValue({ approved: false });
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

  // The REAL gateway path: a stdio MCP gateway forwards the BARE upstream tool
  // name (`write_file`, not namespaced) and serverKey — mcpServer is undefined
  // (extractMcpServer only matches `mcp__server__`). The gate must fire on
  // serverKey alone. (An earlier version gated on serverKey && mcpServer, which
  // is never both-truthy here → the gate was dead in production.)
  const call = (tool: string) =>
    authorizeHeadless(tool, { path: '/x' }, { agent: 'MCP-Gateway', serverKey: 'srv1' });

  it('applies the managed map to config.policy.appPermissions (coerced)', () => {
    expect(getConfig().policy.appPermissions).toEqual({
      srv1: {
        read_file: 'allow',
        write_file: 'block',
        edit_file: 'review',
        read_email: 'review',
      },
    });
  });

  it('BLOCKS a tool set to block', async () => {
    const r = await call('write_file');
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toContain('App Permission');
  });

  it('review REACHES THE RACE (deny here only because no approver exists)', async () => {
    const r = await call('edit_file');
    expect(r.approved).toBe(false);
    // noApprovalMechanism proves it entered the race engine and found no
    // channel — NOT the old hard-deny return in the gate.
    expect(r.noApprovalMechanism).toBe(true);
    expect(r.blockedByLabel).toContain('App Permission (Review)');
  });

  it('does NOT app-permission-block a tool set to allow (falls through)', async () => {
    const r = await call('read_file');
    // 'allow' is not a bypass, but it is NOT the app-permission denial.
    expect(r.blockedByLabel ?? '').not.toContain('App Permission');
  });

  it('does NOT app-permission-block an unset tool (falls through)', async () => {
    const r = await call('list_directory');
    expect(r.blockedByLabel ?? '').not.toContain('App Permission');
  });

  it('ignores app permissions for a different serverKey', async () => {
    const r = await authorizeHeadless(
      'write_file',
      { path: '/x' },
      { agent: 'MCP-Gateway', serverKey: 'OTHER' }
    );
    expect(r.blockedByLabel ?? '').not.toContain('App Permission');
  });

  it('also strips an mcp__<name>__ prefix if a namespaced caller appears (defensive)', async () => {
    const r = await authorizeHeadless(
      'mcp__fs__write_file',
      { path: '/x' },
      { agent: 'MCP-Gateway', mcpServer: 'fs', serverKey: 'srv1' }
    );
    expect(r.approved).toBe(false);
    expect(r.blockedByLabel).toContain('App Permission');
  });

  it('does not enforce without a serverKey (non-gateway hook path)', async () => {
    const r = await authorizeHeadless(
      'write_file',
      { path: '/x' },
      { agent: 'Claude Code' } // no serverKey → gate skipped
    );
    expect(r.blockedByLabel ?? '').not.toContain('App Permission');
  });

  // ── Phase 2.5: review → the live approver race ────────────────────────────
  const writeSettings = (settings: Record<string, unknown>) => {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 0,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
          ...settings,
        },
        policy: {},
      })
    );
    _resetConfigCache();
    _resetCore();
  };

  it('review on an IGNORED-pattern tool (read_*) still races — not auto-allowed', async () => {
    // read_email matches the read_* ignoredTools fast path, which would
    // auto-allow before the race — the same failure class as the dead gate.
    const r = await call('read_email');
    expect(r.approved).toBe(false);
    expect(r.noApprovalMechanism).toBe(true);
    expect(r.blockedByLabel).toContain('App Permission (Review)');
  });

  it('an active trust session does NOT bypass an org-set review', async () => {
    mockTrustSession.mockReturnValue({ pattern: 'edit_file', expiresAt: Date.now() + 60_000 });
    const r = await call('edit_file');
    expect(r.approved).toBe(false); // would be approved-via-trust without the guard
    expect(r.checkedBy).not.toBe('trust');
  });

  it('human APPROVAL via the cloud approver allows the call through', async () => {
    writeSettings({ approvers: { native: false, browser: false, cloud: true, terminal: false } });
    process.env.NODE9_API_KEY = 'test-key';
    mockInitSaaS.mockResolvedValue({ pending: true, requestId: 'req-1' });
    mockPollSaaS.mockResolvedValue({ approved: true });
    const r = await call('edit_file');
    expect(r.approved).toBe(true);
    expect(r.checkedBy).toBe('cloud');
    // the SaaS was forced to create a genuine PENDING entry (forceReview)
    expect(mockInitSaaS.mock.calls[0][6]).toBe(true);
  });

  it('human DENIAL via the cloud approver blocks the call', async () => {
    writeSettings({ approvers: { native: false, browser: false, cloud: true, terminal: false } });
    process.env.NODE9_API_KEY = 'test-key';
    mockInitSaaS.mockResolvedValue({ pending: true, requestId: 'req-2' });
    mockPollSaaS.mockResolvedValue({ approved: false, reason: 'denied by admin' });
    const r = await call('edit_file');
    expect(r.approved).toBe(false);
    expect(r.blockedBy).toBe('team-policy');
  });

  it('a stale BE answering immediate-allow cannot bypass the review', async () => {
    writeSettings({ approvers: { native: false, browser: false, cloud: true, terminal: false } });
    process.env.NODE9_API_KEY = 'test-key';
    // An older BE that ignores forceReview: pending:false + approved:true.
    mockInitSaaS.mockResolvedValue({ pending: false, approved: true });
    const r = await call('edit_file');
    expect(r.approved).toBe(false); // falls to the race; no channel → denied
    expect(r.noApprovalMechanism).toBe(true);
  });

  it('panic mode upgrades review to a hard block (no race)', async () => {
    // panicMode is cloud-pushed via the rules-cache (never local settings).
    const cache = JSON.parse(
      fs.readFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), 'utf-8')
    );
    cache.panicMode = true;
    fs.writeFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), JSON.stringify(cache));
    _resetConfigCache();
    _resetCore();
    const r = await call('edit_file');
    expect(r.approved).toBe(false);
    expect(r.noApprovalMechanism).toBeUndefined(); // gate return, not the race
    expect(r.blockedByLabel).toContain('Panic mode');
  });

  it('deferReview (inline ask) is EXCLUDED for app-perm reviews', async () => {
    const r = await authorizeHeadless(
      'edit_file',
      { path: '/x' },
      { agent: 'MCP-Gateway', serverKey: 'srv1' },
      { deferReview: true }
    );
    expect(r.review).not.toBe(true); // must not hand the prompt to the agent
    expect(r.approved).toBe(false);
  });

  it('the blocked audit row carries MCP attribution + rule name (not anonymous)', async () => {
    // LOCAL_AUDIT_LOG resolves os.homedir() at import time (before this suite's
    // HOME swap), so observe the write via a spy instead of reading a file path.
    const spy = vi.spyOn(fs, 'appendFileSync');
    try {
      // The fixed gateway resolves a friendly label even for bare tool names and
      // passes it as mcpServer — this is the exact meta shape it sends.
      const r = await authorizeHeadless(
        'write_file',
        { path: '/x' },
        { agent: 'MCP-Gateway', mcpServer: 'gmail-autoauth', serverKey: 'srv1' }
      );
      expect(r.approved).toBe(false);
      const line = spy.mock.calls
        .map((c) => String(c[1]))
        .find((s) => s.includes('"tool":"write_file"') && s.includes('"decision":"deny"'));
      expect(line).toBeDefined();
      const row = JSON.parse(line!);
      expect(row.checkedBy).toBe('app-permission-block');
      expect(row.mcpServer).toBe('gmail-autoauth'); // the app chip on the dashboard
      expect(row.ruleName).toBe('app-permission:write_file'); // the "why"
    } finally {
      spy.mockRestore();
    }
  });

  // ── Corrected design (2026-07-02) — the 7 adversarial-review fixes ────────

  it('fix #3: a smart-rule BLOCK wins over review — review cannot loosen a block', async () => {
    // review composes with policy: evaluatePolicy still runs, and a hard block
    // hard-blocks (with its attribution) rather than becoming an approvable card.
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 0,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
        },
        policy: {
          smartRules: [
            {
              name: 'block-edit',
              tool: 'edit_file',
              conditions: [{ field: 'path', op: 'contains', value: '/x' }],
              verdict: 'block',
              reason: 'blocked by shield',
            },
          ],
        },
      })
    );
    _resetConfigCache();
    _resetCore();
    const r = await call('edit_file'); // edit_file is set to review AND smart-blocked
    expect(r.approved).toBe(false);
    expect(r.noApprovalMechanism).toBeUndefined(); // hard block, NOT the race
    expect(r.blockedByLabel ?? '').not.toContain('App Permission (Review)');
  });

  it('fix #2: a SaaS shadowMode response does NOT bypass a review (review > shadow)', async () => {
    writeSettings({ approvers: { native: false, browser: false, cloud: true, terminal: false } });
    process.env.NODE9_API_KEY = 'test-key';
    mockInitSaaS.mockResolvedValue({ pending: false, shadowMode: true });
    const r = await call('edit_file');
    expect(r.approved).toBe(false); // falls to the race; no channel → denied
    expect(r.noApprovalMechanism).toBe(true);
  });

  it('fix #4: an approver-less review deny still WRITES an audit row (not invisible)', async () => {
    const spy = vi.spyOn(fs, 'appendFileSync');
    try {
      const r = await call('edit_file'); // all approvers off → noApprovalMechanism
      expect(r.noApprovalMechanism).toBe(true);
      const line = spy.mock.calls
        .map((c) => String(c[1]))
        .find((s) => s.includes('"tool":"edit_file"') && s.includes('"decision":"deny"'));
      expect(line).toBeDefined();
      const row = JSON.parse(line!);
      expect(row.checkedBy).toBe('app-permission-review');
      expect(row.ruleName).toBe('app-permission:edit_file');
    } finally {
      spy.mockRestore();
    }
  });

  it('fix #6: a race-resolved deny row carries app-permission attribution', async () => {
    writeSettings({ approvers: { native: false, browser: false, cloud: true, terminal: false } });
    process.env.NODE9_API_KEY = 'test-key';
    mockInitSaaS.mockResolvedValue({ pending: true, requestId: 'req-9' });
    mockPollSaaS.mockResolvedValue({ approved: false, reason: 'denied by admin' });
    const spy = vi.spyOn(fs, 'appendFileSync');
    try {
      const r = await call('edit_file');
      expect(r.approved).toBe(false);
      const line = spy.mock.calls
        .map((c) => String(c[1]))
        .find((s) => s.includes('"tool":"edit_file"') && s.includes('"decision":"deny"'));
      expect(line).toBeDefined();
      expect(JSON.parse(line!).ruleName).toBe('app-permission:edit_file');
    } finally {
      spy.mockRestore();
    }
  });

  // fix #1 (daemon skipBackgroundAuth) is NOT unit-testable here: the vitest
  // test-env silencer forces approvers.terminal=false, so the terminal racer
  // that calls registerDaemonEntry never runs. Verified by design reasoning +
  // the live e2e (daemon running). See mcp-review-approver-design.md fix #1.
});
