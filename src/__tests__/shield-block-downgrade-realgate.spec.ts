// src/__tests__/shield-block-downgrade-realgate.spec.ts
//
// Round-2 fail-open fixes (daemon-failopen-round2-design F1 + F3).
//
// F3 (the false-witness fix): every prior test ran with isTestEnv=true, which
// makes `mayDowngrade` constant-false — the downgrade branch and everything
// after it was UNREACHABLE in the whole suite (deleting the round-1 gate kept
// the suite green). These tests clear the test-env markers around the call so
// the REAL wired gate (orchestrator `mayDowngrade` + the post-downgrade
// non-human-channel guards) is exercised end-to-end through authorizeHeadless.
//
// F1 (the surviving fail-open): a downgraded hard block with NO ruleName
// (node9's intrinsic AST blocks — pipe-chain exfiltration, eval-remote-exec —
// return decision:'block', tier:3, no ruleName) must NOT be resolvable by a
// non-human channel: a prior persistent "Always Allow <tool>" or the cloud
// no-match immediate-allow. Test B is the regression: before F1 it resolves
// {approved:true, checkedBy:'persistent'} — a silent allow of a hard block.
//
// The policy verdict is mocked at the `evaluatePolicy` seam with exactly the
// ruleName-less shape the engine emits (verified against the dist) — no
// exfil-shaped literals needed anywhere in this file.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const H = vi.hoisted(() => ({
  daemonRunning: vi.fn<() => boolean>(),
  interactiveApprover: vi.fn<() => Promise<boolean>>(),
  persistentDecision: vi.fn<() => 'allow' | 'deny' | null>(),
  trustSession: vi.fn<() => boolean>(),
  cloudEnabled: vi.fn<() => boolean>(),
  initSaaS: vi.fn(),
  evaluatePolicy: vi.fn(),
  registerDaemonEntry: vi.fn(),
}));

vi.mock('../policy', () => ({
  isIgnoredTool: () => false,
  evaluatePolicy: (...a: unknown[]) => H.evaluatePolicy(...a),
}));

vi.mock('../config', () => ({
  getConfig: () => ({
    settings: {
      // RACER 0 ends the race deterministically — a fixed downgrade path must
      // terminate via timeout-deny, never hang the spec.
      approvalTimeoutMs: 80,
      auditHashArgs: false,
      approvers: { native: true, terminal: true, cloud: H.cloudEnabled() },
      mode: 'standard',
      panicMode: false,
      enableHookLogDebug: false,
    },
    policy: {
      dlp: { enabled: false, pii: false, scanIgnoredTools: false },
      egress: undefined,
      loopDetection: { enabled: false },
      appPermissions: {},
    },
  }),
  getCredentials: () => (H.cloudEnabled() ? { apiKey: 'n9_live_test' } : null),
}));

vi.mock('../auth/state', () => ({
  checkPause: () => ({ paused: false }),
  getActiveTrustSession: () => (H.trustSession() ? { toolName: 'Bash' } : null),
  writeTrustSession: vi.fn(),
  getPersistentDecision: () => H.persistentDecision(),
}));

vi.mock('../auth/daemon', () => ({
  DAEMON_PORT: 7391,
  DAEMON_HOST: '127.0.0.1',
  isDaemonRunning: () => H.daemonRunning(),
  daemonHasInteractiveApprover: () => H.interactiveApprover(),
  getInternalToken: () => null,
  registerDaemonEntry: (...a: unknown[]) => H.registerDaemonEntry(...a),
  // Never resolves — the timeout racer must win, proving no non-human channel
  // short-circuited the race.
  waitForDaemonDecision: () => new Promise(() => {}),
  notifyDaemonViewer: vi.fn().mockResolvedValue(null),
  resolveViaDaemon: vi.fn(),
  notifyTaint: vi.fn(),
  checkTaint: vi.fn().mockResolvedValue(null),
  checkSessionTaint: vi.fn().mockResolvedValue(null),
  notifyActivitySocket: vi.fn().mockResolvedValue(false),
  checkStatePredicates: vi.fn(),
}));

vi.mock('../ui/native', () => ({
  // Popup "shown" but the human never answers — resolves only on abort.
  askNativePopup: () => new Promise(() => {}),
}));

vi.mock('../audit', () => ({
  appendHookDebug: vi.fn(),
  appendLocalAudit: vi.fn(),
  appendToLog: vi.fn(),
  HOOK_DEBUG_LOG: '/dev/null',
}));

vi.mock('../auth/cloud', () => ({
  initNode9SaaS: (...a: unknown[]) => H.initSaaS(...a),
  // Never resolves — the cloud poller must not win; the timeout racer decides.
  pollNode9SaaS: () => new Promise(() => {}),
  resolveNode9SaaS: vi.fn(),
}));

vi.mock('../dlp', () => ({
  scanArgs: () => [],
  scanFilePath: () => null,
  detectArgsPii: () => [],
}));

vi.mock('../loop-detector', () => ({
  recordAndCheck: () => ({ isLoop: false }),
}));

vi.mock('../shields', () => ({
  readActiveShields: () => [],
}));

import { authorizeHeadless } from '../auth/orchestrator';

// The exact shape @node9/policy-engine emits for its intrinsic AST hard blocks
// (pipe-chain exfiltration / eval-remote-exec): block, tier 3, NO ruleName.
const RULENAME_LESS_BLOCK = {
  decision: 'block',
  tier: 3,
  blockedByLabel: 'Node9: Pipe-Chain Exfiltration (critical)',
  reason: 'Chained read of a sensitive file into a network destination.',
};

const ENV_KEYS = ['VITEST', 'NODE_ENV', 'CI', 'NODE9_TESTING'] as const;

describe('real-gate: downgraded ruleName-less hard block (round-2 F1/F3)', () => {
  const savedEnv: Record<string, string | undefined> = {};
  let savedDisplay: string | undefined;
  let savedWayland: string | undefined;

  beforeEach(() => {
    for (const k of ENV_KEYS) {
      savedEnv[k] = process.env[k];
      delete process.env[k];
    }
    // isTestEnv must be FALSE for these tests — that is the whole point (F3).
    process.env.NODE_ENV = 'production';
    savedDisplay = process.env.DISPLAY;
    savedWayland = process.env.WAYLAND_DISPLAY;
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;

    H.daemonRunning.mockReturnValue(true);
    H.interactiveApprover.mockResolvedValue(false);
    H.persistentDecision.mockReturnValue(null);
    H.trustSession.mockReturnValue(false);
    H.cloudEnabled.mockReturnValue(false);
    H.initSaaS.mockResolvedValue({ pending: true, requestId: 'req-1' });
    H.evaluatePolicy.mockResolvedValue(RULENAME_LESS_BLOCK);
    H.registerDaemonEntry.mockResolvedValue({ id: 'entry-1', allowCount: 1 });
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (savedEnv[k] !== undefined) process.env[k] = savedEnv[k];
      else delete process.env[k];
    }
    if (savedDisplay !== undefined) process.env.DISPLAY = savedDisplay;
    else delete process.env.DISPLAY;
    if (savedWayland !== undefined) process.env.WAYLAND_DISPLAY = savedWayland;
    else delete process.env.WAYLAND_DISPLAY;
    vi.clearAllMocks();
  });

  it('A: headless (no display, no tail) — the block STAYS hard through the real path', async () => {
    const res = await authorizeHeadless('Bash', { command: 'echo hello' });
    expect(res.approved).toBe(false);
    expect(res.blockedBy).toBe('local-config');
  });

  it('B: interactive downgrade + prior "Always Allow" — persistent must NOT resolve a hard block', async () => {
    process.env.DISPLAY = ':0'; // native approver looks reachable → downgrade
    H.persistentDecision.mockReturnValue('allow'); // the poisoned precondition

    const res = await authorizeHeadless('Bash', { command: 'echo hello' });

    // Before F1: {approved:true, checkedBy:'persistent'} — a hard block
    // silently allowed with no human. After F1 the persistent consult is
    // skipped for a downgraded block; nobody answers the review, so the
    // timeout racer denies.
    expect(res.checkedBy).not.toBe('persistent');
    expect(res.approved).toBe(false);
  });

  it('C: the downgrade carries localSmartRuleMatched to the daemon card (cloud guard armed)', async () => {
    process.env.DISPLAY = ':0';

    await authorizeHeadless('Bash', { command: 'echo hello' });

    // registerDaemonEntry's localSmartRuleMatched param (10th arg) must be true
    // for a downgraded ruleName-less block — the same flag that forces cloud
    // review (forceReview) instead of the no-match immediate-allow.
    expect(H.registerDaemonEntry).toHaveBeenCalled();
    const args = H.registerDaemonEntry.mock.calls[0];
    expect(args[9]).toBe(true);
  });

  it('D: interactive downgrade + active trust session — trust must NOT resolve a hard block (round-3 F1b)', async () => {
    process.env.DISPLAY = ':0'; // downgrade path
    H.trustSession.mockReturnValue(true); // a prior "always allow" grant matches

    const res = await authorizeHeadless('Bash', { command: 'echo hello' });

    // Before F1b: {approved:true, checkedBy:'trust'} — the trust bypass at
    // orchestrator.ts:1006 resolved a downgraded intrinsic block with no human.
    // After F1b the trust check is skipped for a downgraded block; the review
    // reaches no one and the timeout racer denies.
    expect(res.checkedBy).not.toBe('trust');
    expect(res.approved).toBe(false);
  });

  it('E: interactive downgrade + cloud shadowMode — shadowMode must NOT resolve a hard block (round-3 F1c)', async () => {
    process.env.DISPLAY = ':0'; // downgrade path
    H.cloudEnabled.mockReturnValue(true);
    // A shadow/observe org (or a stale BE ignoring forceReview) answers the
    // handshake with a non-pending shadowMode allow.
    H.initSaaS.mockResolvedValue({ pending: false, shadowMode: true });

    const res = await authorizeHeadless('Bash', { command: 'echo hello' });

    // Before F1c: {approved:true, checkedBy:'cloud'} — shadowMode short-circuit
    // resolved a downgraded intrinsic block. After F1c a local review match
    // (localSmartRuleMatched, set via hardBlockDowngraded) blocks the shadowMode
    // allow; the poller never resolves, so the timeout racer denies.
    expect(res.approved).toBe(false);
  });
});
