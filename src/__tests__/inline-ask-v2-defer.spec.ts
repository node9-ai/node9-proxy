// src/__tests__/inline-ask-v2-defer.spec.ts
// Inline-ask v2 — "block = stop, review = the dev decides, inline is the dev's
// seat" (review-ask-inline-v2-spec.md). The defer guard keeps EXACTLY ONE
// exclusion: a DOWNGRADED HARD BLOCK (F1d — an intrinsic block softened only
// because a human is reachable is not an admin-chosen review; "block = stop"
// keeps it on the routed approver). The v1 exclusions — cloud-enforced, taint,
// app-permission review — are deliberately removed: those ARE admin/detector
// review verdicts, and review means the dev reviews, inline.
//
// Real gate: authorizeHeadless (feedback_verify_at_real_gate). Downgraded-block
// regression coverage lives in shield-block-downgrade-realgate.spec.ts Test F.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { _resetConfigCache } from '../config';
import { authorizeHeadless, _resetConfigCache as _resetCore } from '../core.js';
import { buildReviewMessage } from '../policy/negotiation';

const { mockInitSaaS, mockPollSaaS, mockSessionTaint } = vi.hoisted(() => ({
  mockInitSaaS: vi.fn(async (..._a: unknown[]): Promise<unknown> => ({ pending: false })),
  mockPollSaaS: vi.fn(async (..._a: unknown[]): Promise<unknown> => ({ approved: false })),
  mockSessionTaint: vi.fn(async (..._a: unknown[]): Promise<unknown> => ({ tainted: false })),
}));
vi.mock('../auth/cloud', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../auth/cloud')>()),
  initNode9SaaS: (...a: unknown[]) => mockInitSaaS(...a),
  pollNode9SaaS: (...a: unknown[]) => mockPollSaaS(...a),
  resolveNode9SaaS: vi.fn(async () => undefined),
}));
vi.mock('../auth/daemon', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../auth/daemon')>()),
  // Session-taint is daemon-served; mock the client so the taint test doesn't
  // need a live daemon. isDaemonRunning stays real (no daemon in tests → the
  // race, if ever reached, has no channels and denies fast).
  checkSessionTaint: (...a: unknown[]) => mockSessionTaint(...a),
}));

describe('inline-ask v2: the defer guard has ONE exclusion (downgraded hard block)', () => {
  let tmpHome: string;
  let origHome: string | undefined;
  let origUserprofile: string | undefined;

  const reviewGitPushRule = {
    name: 'review-git-push',
    tool: 'bash',
    conditions: [{ field: 'command', op: 'matches', value: '\\bgit\\b.*\\bpush\\b' }],
    conditionMode: 'all',
    verdict: 'review',
    reason: 'git push sends changes to a shared remote',
  };

  // PR-2 replace-mode (§F disposition): when a test sets NODE9_API_KEY the
  // process is KEYED and the local config.json policy below is inert — a keyed
  // test passes `keyed: true` so the review rule and the approval knobs ride
  // in the CLOUD cache instead (rules + managedConfig), exactly what a real
  // keyed machine gets from sync. Unkeyed tests keep the local delivery.
  function writeHome(opts: {
    cloud?: boolean;
    appPermissions?: Record<string, unknown>;
    keyed?: boolean;
  }): void {
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 0,
          autoStartDaemon: false,
          approvers: {
            native: false,
            browser: false,
            cloud: opts.cloud === true,
            terminal: false,
          },
        },
        policy: { smartRules: [reviewGitPushRule] },
      })
    );
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'rules-cache.json'),
      JSON.stringify({
        fetchedAt: '2026-07-01T00:00:00Z',
        rules: opts.keyed ? [reviewGitPushRule] : [],
        managedConfig: {
          ...(opts.appPermissions ? { appPermissions: opts.appPermissions } : {}),
          ...(opts.keyed
            ? {
                // A managed 0 is rejected by design (index.ts) — 50ms keeps a
                // race, if ever reached, deterministic instead of hanging.
                approvalTimeoutMs: 50,
                approvers: {
                  native: false,
                  browser: false,
                  cloud: opts.cloud === true,
                  terminal: false,
                },
              }
            : {}),
          locked: [],
        },
      })
    );
    _resetConfigCache();
    _resetCore();
  }

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-askv2-'));
    origHome = process.env.HOME;
    origUserprofile = process.env.USERPROFILE;
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.NODE9_API_KEY;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    mockInitSaaS.mockClear();
    mockInitSaaS.mockResolvedValue({ pending: false });
    mockPollSaaS.mockResolvedValue({ approved: false });
    mockSessionTaint.mockResolvedValue({ tainted: false });
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    if (origUserprofile !== undefined) process.env.USERPROFILE = origUserprofile;
    else delete process.env.USERPROFILE;
    delete process.env.NODE9_API_KEY;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    _resetConfigCache();
    _resetCore();
  });

  it('CLOUD-ENFORCED + ordinary review → defers inline; no SaaS pending entry is created', async () => {
    writeHome({ cloud: true, keyed: true });
    process.env.NODE9_API_KEY = 'nk_test_v2'; // env key => KEYED process
    // PR-2: keyed drops the local review-git-push rule, and cloud cache
    // `rules` are currently dropped keyed too (prod bug pinned as K13c in
    // keyed-replace.spec.ts) — so the probe rides the SHIPPED DEFAULT
    // `review-sudo` rule, which survives keyed by construction. The property
    // under test is unchanged: cloud-enforced + ordinary review defers inline.
    const r = await authorizeHeadless('Bash', { command: 'sudo make install' }, undefined, {
      deferReview: true,
    });
    expect(r.review).toBe(true);
    expect(r.approved).toBe(false);
    // The defer short-circuits BEFORE the handshake — an /intercept pending
    // entry would orphan in the dashboard/Slack.
    expect(mockInitSaaS).not.toHaveBeenCalled();
  });

  it('APP-PERMISSION review: the REAL caller (mcp-gateway) never defers — it races', async () => {
    // Test-honesty fix (/code-review round 2): the ONLY producer of serverKey
    // is src/mcp-gateway/index.ts, and it does NOT pass deferReview — the
    // gateway answers JSON-RPC and has no inline-ask channel to render. So
    // "app-perm reviews defer inline" is principle-level only; in production
    // they always take the approver race. This pins the real caller shape
    // (per CLAUDE.md: tests must use the inputs the real caller produces).
    writeHome({ appPermissions: { srv1: { edit_file: 'review' } } });
    const r = await authorizeHeadless(
      'edit_file',
      { path: '/x' },
      { agent: 'MCP-Gateway', serverKey: 'srv1' }
      // no options — the gateway passes none
    );
    expect(r.review).not.toBe(true);
    expect(r.approved).toBe(false);
    expect(r.noApprovalMechanism).toBe(true); // reached the race, no channel in tests
  });

  it('SESSION-TAINT review → defers inline, and the prompt reason carries the taint sentence', async () => {
    writeHome({});
    mockSessionTaint.mockResolvedValue({
      tainted: true,
      record: { source: 'a GitHub token (DLP:github-token)' },
    });
    const r = await authorizeHeadless(
      'write_file',
      { path: '/tmp/out.txt', content: 'x' },
      { sessionId: 'sess-taint-1' },
      { deferReview: true }
    );
    expect(r.review).toBe(true);
    expect(r.approved).toBe(false);
    expect(r.reason).toContain('flagged this session');
  });

  it('the rendered ask message carries the reason sentence (taint/app-perm context)', () => {
    // sendAsk (check.ts) renders via buildReviewMessage — the defer return's
    // reason must survive into the prompt text, not just the orchestrator result.
    const msg = buildReviewMessage(
      '🔒 Node9 App Permission (Review)',
      undefined,
      'App permission: "edit_file" requires human approval (workspace policy).'
    );
    expect(msg).toContain('edit_file');
    expect(msg).toContain('human approval');
    // A rule's own description still wins when present (unchanged v1 behavior).
    const ruleMsg = buildReviewMessage('label', 'git push sends changes to a shared remote', 'x');
    expect(ruleMsg).toContain('shared remote');
  });

  it('PANIC MODE still upgrades review → hard block; defer never sees it (regression)', async () => {
    writeHome({ cloud: false });
    const cache = JSON.parse(
      fs.readFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), 'utf-8')
    ) as Record<string, unknown>;
    cache.panicMode = true;
    fs.writeFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), JSON.stringify(cache));
    _resetConfigCache();
    _resetCore();
    const r = await authorizeHeadless('Bash', { command: 'git push origin dev' }, undefined, {
      deferReview: true,
    });
    expect(r.approved).toBe(false);
    expect(r.review).not.toBe(true); // gate return, not a deferred ask
    expect(r.blockedByLabel).toContain('Panic mode');
  });
});
