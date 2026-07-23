// src/__tests__/strict-cloud-allow-bypass.spec.ts
// B1 (#6) — a cloud-managed strict mode must not be bypassed by the SaaS
// gate's immediate-allow.
//
// The bug (live repro 2026-07-23): tier-7 strict fallback produces a review
// verdict with NO ruleName — it is a mode, not a rule. The orchestrator's
// cloud-bypass guard (`localSmartRuleMatched`) was keyed on ruleName, so the
// SaaS checkRule answer for an unmatched tool — AUTO_ALLOWED, meaning "no org
// rule matched", not "the org approved" — resolved the call as approved.
// The strictest posture an admin can set did nothing on the exact path it
// exists for.
//
// Harness mirrors app-permissions.spec.ts: tmp HOME, managedConfig via
// rules-cache.json (the REAL input the daemon sync writes), cloud mocked at
// the initNode9SaaS boundary answering exactly what today's BE answers for an
// unmatched tool: { pending: false, approved: true }.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { _resetConfigCache } from '../config';
import { authorizeHeadless, _resetConfigCache as _resetCore } from '../core.js';

const { mockTrustSession, mockInitSaaS, mockPollSaaS } = vi.hoisted(() => ({
  mockTrustSession: vi.fn((..._a: unknown[]): unknown => null),
  mockInitSaaS: vi.fn(
    async (..._a: unknown[]): Promise<unknown> => ({ pending: false, approved: true })
  ),
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

/** Base local config: standard mode, cloud is the ONLY approver surface.
 *  Native/browser/terminal stay off so a guarded fall-through resolves
 *  deterministically as no-approval-mechanism instead of opening UI. */
function writeLocalConfig(tmpHome: string): void {
  fs.writeFileSync(
    path.join(tmpHome, '.node9', 'config.json'),
    JSON.stringify({
      settings: {
        mode: 'standard',
        approvalTimeoutMs: 0,
        approvers: { native: false, browser: false, cloud: true, terminal: false },
      },
      policy: {},
    })
  );
}

function writeRulesCache(
  tmpHome: string,
  opts: { managedMode?: string; rules?: unknown[] } = {}
): void {
  fs.writeFileSync(
    path.join(tmpHome, '.node9', 'rules-cache.json'),
    JSON.stringify({
      fetchedAt: '2026-07-01T00:00:00Z',
      rules: opts.rules ?? [],
      ...(opts.managedMode ? { managedConfig: { mode: opts.managedMode, locked: [] } } : {}),
    })
  );
}

describe('cloud immediate-allow vs managed strict (B1 #6)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-strictbypass-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    delete process.env.NODE9_MODE;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    writeLocalConfig(tmpHome);
    // cloudEnforced requires a real credential on disk (approvers.cloud && apiKey).
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'credentials.json'),
      JSON.stringify({
        default: { apiKey: 'nk_test_0000', apiUrl: 'https://example.invalid/api/v1/intercept' },
      })
    );
    _resetConfigCache();
    _resetCore();
    mockTrustSession.mockReturnValue(null);
    // Today's BE answer for an unmatched tool: resolved, allowed, no pending entry.
    mockInitSaaS.mockClear();
    mockInitSaaS.mockResolvedValue({ pending: false, approved: true });
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

  it('managed strict: cloud "no rule matched" allow must NOT resolve the call', async () => {
    writeRulesCache(tmpHome, { managedMode: 'strict' });

    const result = await authorizeHeadless('TotallyUnknownTool', { note: 'probe' });

    // The bug resolved this as { approved: true, checkedBy: 'cloud' }. A tier-7
    // strict review must fall through to the race; with every local surface off
    // and no cloud PENDING entry, that is a deterministic deny.
    expect(result.approved).toBe(false);
    expect(result.checkedBy).not.toBe('cloud');
    expect(result.blockedBy).toBe('no-approval-mechanism');
    // Label convention: once cloud is enforced, the orchestrator stamps
    // 'Organization Policy (SaaS)' over the local label (orchestrator.ts —
    // same for smart-rule reviews today). The managed strict floor IS org
    // policy, so either attribution is honest; assert only that a label exists.
    expect(result.blockedByLabel).toMatch(/strict|organization policy/i);
  });

  it('managed strict: the SaaS is told forceReview so it creates a genuine PENDING', async () => {
    writeRulesCache(tmpHome, { managedMode: 'strict' });

    await authorizeHeadless('TotallyUnknownTool', { note: 'probe' });

    expect(mockInitSaaS).toHaveBeenCalled();
    // initNode9SaaS(toolName, args, creds, meta, riskMetadata, agentPolicy, forceReview)
    const forceReview = mockInitSaaS.mock.calls[0][6];
    expect(forceReview).toBe(true);
  });

  it('standard mode: unmatched tools stay on the local fast path — no cloud round-trip (pinned)', async () => {
    writeRulesCache(tmpHome, {});

    const result = await authorizeHeadless('TotallyUnknownTool', { note: 'probe' });

    // Standard-mode unmatched → local allow at the fast path. The fix must not
    // drag every allowed call through initNode9SaaS (the hot-path cost the
    // outbox shipper exists to avoid).
    expect(result.approved).toBe(true);
    expect(result.checkedBy).toBe('local-policy');
    expect(mockInitSaaS).not.toHaveBeenCalled();
  });

  it('smart-rule review: still falls to the race, never resolved by cloud allow (pinned)', async () => {
    writeRulesCache(tmpHome, {
      rules: [
        {
          name: 'review-unknown',
          tool: 'TotallyUnknownTool',
          verdict: 'review',
          conditions: [],
        },
      ],
    });

    const result = await authorizeHeadless('TotallyUnknownTool', { note: 'probe' });

    expect(result.approved).toBe(false);
    expect(result.checkedBy).not.toBe('cloud');
  });
});
