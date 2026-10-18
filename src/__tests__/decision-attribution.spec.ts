// src/__tests__/decision-attribution.spec.ts
//
// Who decided, as the agent and the approval card are told.
//
// ENG-2 (node9Firewall#304): the terminal racer turned every `deny` from
// `waitForDaemonDecision` into "The human user rejected this action via the
// Node9 Terminal", label "User Decision (Terminal)". /wait also answers `deny`
// when no person did anything: the daemon's auto-deny timer, its own
// background pass, a failed /wait. The agent then stopped and asked the user
// instead of reading the block's reason.
//
// MSG-5 (node9Firewall#305): a project-jail block softened to a review showed
// "Organization Policy (SaaS)" as the card's header whenever the machine was
// cloud-connected, and the rule's sentence "Reading .env files is blocked by
// project-jail shield" directly above "Enter = Allow".
//
// The approver race runs for real (isTestEnv cleared, as in
// shield-block-downgrade-realgate.spec.ts); the engine verdict, the daemon and
// the native popup are stubbed at their seams.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const H = vi.hoisted(() => ({
  approvalTimeoutMs: 5000,
  cloudEnabled: vi.fn<() => boolean>(),
  initSaaS: vi.fn(),
  evaluatePolicy: vi.fn(),
  registerDaemonEntry: vi.fn(),
  waitForDaemonDecision: vi.fn(),
  askNativePopup: vi.fn(),
}));

vi.mock('../policy', () => ({
  isIgnoredTool: () => false,
  evaluatePolicy: (...a: unknown[]) => H.evaluatePolicy(...a),
}));

vi.mock('../config', () => ({
  getConfig: () => ({
    settings: {
      approvalTimeoutMs: H.approvalTimeoutMs,
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
  getActiveTrustSession: () => null,
  writeTrustSession: vi.fn(),
  getPersistentDecision: () => null,
}));

vi.mock('../auth/daemon', () => ({
  DAEMON_PORT: 7391,
  DAEMON_HOST: '127.0.0.1',
  isDaemonRunning: () => true,
  daemonHasInteractiveApprover: () => Promise.resolve(false),
  getInternalToken: () => null,
  registerDaemonEntry: (...a: unknown[]) => H.registerDaemonEntry(...a),
  waitForDaemonDecision: (...a: unknown[]) => H.waitForDaemonDecision(...a),
  notifyDaemonViewer: vi.fn().mockResolvedValue(null),
  resolveViaDaemon: vi.fn(),
  notifyTaint: vi.fn(),
  checkTaint: vi.fn().mockResolvedValue(null),
  checkSessionTaint: vi.fn().mockResolvedValue(null),
  notifyActivitySocket: vi.fn().mockResolvedValue(false),
  checkStatePredicates: vi.fn(),
}));

vi.mock('../ui/native', () => ({
  askNativePopup: (...a: unknown[]) => H.askNativePopup(...a),
}));

vi.mock('../audit', () => ({
  appendHookDebug: vi.fn(),
  appendLocalAudit: vi.fn(),
  appendToLog: vi.fn(),
  HOOK_DEBUG_LOG: '/dev/null',
}));

vi.mock('../auth/cloud', () => ({
  initNode9SaaS: (...a: unknown[]) => H.initSaaS(...a),
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

import { authorizeHeadless, type AuthResult } from '../auth/orchestrator';
import { buildNegotiationMessage, isHumanDecision } from '../policy/negotiation';

// The verdict the engine returns for the builtin project-jail .env rule.
const JAIL_BLOCK = {
  decision: 'block',
  tier: 2,
  ruleName: 'shield:project-jail:block-read-env',
  blockedByLabel: 'Smart Rule: shield:project-jail:block-read-env',
  reason: 'Reading .env files is blocked by project-jail shield',
};
const JAIL_LABEL = JAIL_BLOCK.blockedByLabel;

const PUSH_REVIEW = {
  decision: 'review',
  tier: 2,
  ruleName: 'review-git-push',
  blockedByLabel: 'Smart Rule: review-git-push',
  reason: 'git push needs a review',
};

/** What the agent reads: the message check.ts, the MCP gateway and the proxy
 *  build, each deciding "human" with isHumanDecision. */
function agentMessage(res: AuthResult): string {
  const label = res.blockedByLabel ?? res.blockedBy ?? 'Local Security Policy';
  const isHuman = isHumanDecision(label, res.blockedBy);
  return buildNegotiationMessage(label, isHuman, res.reason, res.recoveryCommand, {
    kind: res.blockKind,
    path: res.blockedPath,
  });
}

const ENV_KEYS = ['VITEST', 'NODE_ENV', 'CI', 'NODE9_TESTING'] as const;

describe('decision attribution (ENG-2, MSG-5)', () => {
  const savedEnv: Record<string, string | undefined> = {};
  let savedDisplay: string | undefined;

  beforeEach(() => {
    for (const k of ENV_KEYS) {
      savedEnv[k] = process.env[k];
      delete process.env[k];
    }
    // The real gate: mayDowngrade is constant-false under isTestEnv.
    process.env.NODE_ENV = 'production';
    savedDisplay = process.env.DISPLAY;
    process.env.DISPLAY = ':0'; // a person is reachable, so a block softens

    H.approvalTimeoutMs = 5000;
    H.cloudEnabled.mockReturnValue(false);
    H.initSaaS.mockResolvedValue({ pending: true, requestId: 'req-1' });
    H.registerDaemonEntry.mockResolvedValue({ id: 'entry-1', allowCount: 1 });
    H.waitForDaemonDecision.mockImplementation(() => new Promise(() => {}));
    // The popup is shown and nobody answers it.
    H.askNativePopup.mockImplementation(() => new Promise(() => {}));
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (savedEnv[k] !== undefined) process.env[k] = savedEnv[k];
      else delete process.env[k];
    }
    if (savedDisplay !== undefined) process.env.DISPLAY = savedDisplay;
    else delete process.env.DISPLAY;
    vi.clearAllMocks();
  });

  describe('ENG-2: a deny no person made is not a human rejection', () => {
    it('a softened jail block denied by the daemon with no source gets the block, not a human veto', async () => {
      H.evaluatePolicy.mockResolvedValue(JAIL_BLOCK);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny' });

      const res = await authorizeHeadless('Bash', { command: 'echo hello' });

      expect(res.approved).toBe(false);
      expect(res.blockedBy).toBe('local-config');
      expect(res.blockedByLabel).toBe(JAIL_LABEL);
      expect(res.reason).toBe(JAIL_BLOCK.reason);
      expect(res.ruleHit).toBe(JAIL_BLOCK.ruleName);
      expect(res.blockKind).toBe('protected-path');
      expect(agentMessage(res)).not.toMatch(/human/i);
      expect(agentMessage(res)).toMatch(/protected/);
    });

    it("the daemon's timer (source 'timeout') is recorded as a timeout", async () => {
      H.evaluatePolicy.mockResolvedValue(JAIL_BLOCK);
      H.waitForDaemonDecision.mockResolvedValue({
        decision: 'deny',
        source: 'timeout',
        reason: 'No response — auto-denied after timeout',
      });

      const res = await authorizeHeadless('Bash', { command: 'echo hello' });

      expect(res.approved).toBe(false);
      expect(res.blockedBy).toBe('timeout');
      expect(res.blockedByLabel).toBe(JAIL_LABEL);
      expect(agentMessage(res)).not.toMatch(/human/i);
    });

    it('a review denied by the daemon with no source carries the review label and the daemon reason', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({
        decision: 'deny',
        reason: 'denied by the background check',
      });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.approved).toBe(false);
      expect(res.blockedBy).toBe('local-config');
      expect(res.blockedByLabel).toBe(PUSH_REVIEW.blockedByLabel);
      expect(res.reason).toBe('denied by the background check');
      expect(res.decisionSource).toBeUndefined();
      expect(agentMessage(res)).not.toMatch(/human/i);
    });

    it("a review the daemon's timer denied is an Approval Timeout", async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'timeout' });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.blockedBy).toBe('timeout');
      expect(res.blockedByLabel).toBe('Approval Timeout');
      expect(agentMessage(res)).not.toMatch(/human/i);
    });

    it('a review whose rule name says "user" is still not a human rejection', async () => {
      H.evaluatePolicy.mockResolvedValue({
        ...PUSH_REVIEW,
        ruleName: 'review-user-data',
        blockedByLabel: 'Smart Rule: review-user-data',
      });
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny' });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.blockedByLabel).toBe('Smart Rule: review-user-data');
      expect(agentMessage(res)).not.toMatch(/human/i);
    });

    it('control: a person who denies in node9 tail is still a human rejection', async () => {
      H.evaluatePolicy.mockResolvedValue(JAIL_BLOCK);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'terminal' });

      const res = await authorizeHeadless('Bash', { command: 'echo hello' });

      expect(res.blockedBy).toBe('local-decision');
      expect(res.blockedByLabel).toBe('User Decision (Terminal (node9 tail))');
      expect(res.decisionSource).toBe('terminal');
      expect(agentMessage(res)).toMatch(/The human user rejected this action/);
    });

    it('control: a deny posted with source browser is still a human rejection', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'browser' });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.blockedBy).toBe('local-decision');
      expect(agentMessage(res)).toMatch(/The human user rejected this action/);
    });

    it('control: a redirect keeps its own reason and label', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({
        decision: 'deny',
        source: 'terminal-redirect',
        reason: 'push to a branch instead',
      });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.blockedByLabel).toBe('Steered Redirect (Terminal)');
      expect(res.reason).toBe('push to a branch instead');
    });

    it('control: an allow from the daemon is unchanged', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'allow', source: 'terminal' });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.approved).toBe(true);
      expect(res.checkedBy).toBe('daemon');
    });
  });

  describe('MSG-5: a softened local block asks on its own card', () => {
    it('cloud-connected: the card names the jail rule, not Organization Policy (SaaS), and asks', async () => {
      H.approvalTimeoutMs = 80; // nobody answers; the timeout racer ends the race
      H.cloudEnabled.mockReturnValue(true);
      H.evaluatePolicy.mockResolvedValue(JAIL_BLOCK);

      await authorizeHeadless('Bash', { command: 'echo hello' });

      expect(H.askNativePopup).toHaveBeenCalled();
      const card = H.askNativePopup.mock.calls[0];
      expect(card[3]).toBe(`⚠️ Override block rule: ${JAIL_LABEL}`);
      expect(card[9]).toBe('Reading .env files needs your approval (project-jail shield)');
    });

    it('cloud-connected: a smart-rule review keeps its rule label', async () => {
      H.approvalTimeoutMs = 80;
      H.cloudEnabled.mockReturnValue(true);
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);

      await authorizeHeadless('Bash', { command: 'git push' });

      const card = H.askNativePopup.mock.calls[0];
      expect(card[3]).toBe(PUSH_REVIEW.blockedByLabel);
      // Not a block: the rule's own sentence is shown as written.
      expect(card[9]).toBe(PUSH_REVIEW.reason);
    });

    it("control: cloud-connected, a review no local rule asked for is the organisation's", async () => {
      H.approvalTimeoutMs = 80;
      H.cloudEnabled.mockReturnValue(true);
      H.evaluatePolicy.mockResolvedValue({
        decision: 'review',
        tier: 1,
        blockedByLabel: 'Ordinary review',
        reason: 'ordinary review verdict',
      });

      await authorizeHeadless('Bash', { command: 'echo hello' });

      const card = H.askNativePopup.mock.calls[0];
      expect(card[3]).toBe('Organization Policy (SaaS)');
    });

    it('the node9 tail card for a softened block asks too', async () => {
      H.evaluatePolicy.mockResolvedValue(JAIL_BLOCK);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'terminal' });

      await authorizeHeadless('Bash', { command: 'echo hello' });

      const riskMetadata = H.registerDaemonEntry.mock.calls[0][3] as { ruleDescription?: string };
      expect(riskMetadata.ruleDescription).toBe(
        'Reading .env files needs your approval (project-jail shield)'
      );
    });

    it('the agent still reads the block wording after a person denies the softened block', async () => {
      H.evaluatePolicy.mockResolvedValue(JAIL_BLOCK);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'terminal' });

      const res = await authorizeHeadless('Bash', { command: 'echo hello' });

      expect(res.ruleDescription).toBe(JAIL_BLOCK.reason);
    });
  });
});
