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
  resolveViaDaemon: vi.fn(),
  notifyDaemonViewer: vi.fn(),
  resolveNode9SaaS: vi.fn(),
  pollNode9SaaS: vi.fn(),
  token: null as string | null,
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
  getInternalToken: () => H.token,
  registerDaemonEntry: (...a: unknown[]) => H.registerDaemonEntry(...a),
  waitForDaemonDecision: (...a: unknown[]) => H.waitForDaemonDecision(...a),
  notifyDaemonViewer: (...a: unknown[]) => H.notifyDaemonViewer(...a),
  resolveViaDaemon: (...a: unknown[]) => H.resolveViaDaemon(...a),
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
  pollNode9SaaS: (...a: unknown[]) => H.pollNode9SaaS(...a),
  resolveNode9SaaS: (...a: unknown[]) => H.resolveNode9SaaS(...a),
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

import { authorizeHeadless, daemonWaitCapMs, type AuthResult } from '../auth/orchestrator';
import { buildNegotiationMessage, isHumanDecision } from '../policy/negotiation';
import { personRecord } from '../auth/decision-record';

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
  const isHuman = isHumanDecision(label, res.blockedBy, res.decidedBy);
  return buildNegotiationMessage(label, isHuman, res.reason, res.recoveryCommand, {
    kind: res.blockKind,
    path: res.blockedPath,
    redirect: !!res.redirect,
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
    H.token = null;
    H.resolveViaDaemon.mockResolvedValue(null);
    H.notifyDaemonViewer.mockResolvedValue(null);
    H.resolveNode9SaaS.mockResolvedValue(undefined);
    H.pollNode9SaaS.mockImplementation(() => new Promise(() => {}));
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

    it("a review the daemon's background pass blocked (source 'policy') carries the review label and the pass's reason", async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({
        decision: 'deny',
        source: 'policy',
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

    // fw#304 review, finding 1: the background pass runs the cloud racer, so
    // an administrator's deny in Slack or Mission Control reaches the hook
    // through the daemon. It is the organisation's decision, reported as the
    // hook's own cloud racer reports one, not as a local rule.
    it("an administrator's deny relayed by the background pass (source 'cloud') is the organisation's", async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({
        decision: 'deny',
        source: 'cloud',
        reason: 'Action rejected by organization administrator via Slack.',
      });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.approved).toBe(false);
      expect(res.blockedBy).toBe('team-policy');
      expect(res.blockedByLabel).toBe('Organization Policy (SaaS)');
      expect(res.decisionSource).toBe('cloud');
      expect(res.reason).toBe('Action rejected by organization administrator via Slack.');
    });

    it("an administrator's deny of a softened block is still the organisation's, not the block", async () => {
      H.evaluatePolicy.mockResolvedValue(JAIL_BLOCK);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'cloud' });

      const res = await authorizeHeadless('Bash', { command: 'echo hello' });

      expect(res.blockedBy).toBe('team-policy');
      expect(res.blockedByLabel).toBe('Organization Policy (SaaS)');
    });

    // Finding 3: with no source the wait itself failed (the daemon died, the
    // card was gone). No rule decided, so none is named.
    it('a failed wait (no source) is Approval Unavailable, not the active rule', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny' });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.approved).toBe(false);
      expect(res.blockedBy).toBe('no-approval-mechanism');
      expect(res.blockedByLabel).toBe('Approval Unavailable');
      expect(res.noApprovalMechanism).toBeUndefined();
      expect(agentMessage(res)).not.toMatch(/human/i);
    });

    it('a failed wait on a cloud-connected machine does not name Organization Policy (SaaS)', async () => {
      // A review no local rule asked for: the card is labelled as the
      // organisation's, and the hook shares the daemon viewer card.
      H.cloudEnabled.mockReturnValue(true);
      H.initSaaS.mockResolvedValue({ pending: true, requestId: 'req-2' });
      H.notifyDaemonViewer.mockResolvedValueOnce({ id: 'viewer-1', allowCount: 1 });
      H.evaluatePolicy.mockResolvedValue({
        decision: 'review',
        tier: 1,
        blockedByLabel: 'Ordinary review',
        reason: 'ordinary review verdict',
      });
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny' });

      const res = await authorizeHeadless('Bash', { command: 'echo hello' });

      expect(H.waitForDaemonDecision).toHaveBeenCalled();
      expect(res.blockedByLabel).toBe('Approval Unavailable');
    });

    it('the terminal racer waits as long as the configured timeout, and without a cap for 0', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'terminal' });

      await authorizeHeadless('Bash', { command: 'git push' });

      expect(H.waitForDaemonDecision.mock.calls[0][2]).toBe(daemonWaitCapMs(5000));
      expect(daemonWaitCapMs(5000)).toBe(125_000);
      expect(daemonWaitCapMs(300_000)).toBe(305_000);
      expect(daemonWaitCapMs(0)).toBe(0);
      // Unset is the default timeout, not "no timer".
      expect(daemonWaitCapMs(undefined)).toBe(125_000);
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
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'policy' });

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

    it("an allow the background pass's cloud racer made is the organisation's, not a click in tail", async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'allow', source: 'cloud' });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.approved).toBe(true);
      expect(res.checkedBy).toBe('cloud');
      expect(res.decisionSource).toBe('cloud');
    });

    it('an allow the background pass made by rule is a rule allow', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'allow', source: 'policy' });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.approved).toBe(true);
      expect(res.checkedBy).toBe('local-policy');
      expect(res.decisionSource).toBeUndefined();
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

  // Approval-card design, step 3: the hook reads who decided from the card's
  // record, reports its own winners to the card, and adopts the card's
  // decision when a person answered first.
  describe('the card decides once (approval-card design)', () => {
    it('registers the card with who may answer it and the hook timeout', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'terminal' });

      await authorizeHeadless('Bash', { command: 'git push' });

      const args = H.registerDaemonEntry.mock.calls[0];
      expect(args[args.length - 1]).toEqual({
        channels: ['terminal', 'monitor', 'native'],
        timeoutMs: 5000,
      });
    });

    it('a protocol-2 record names who decided (node9 monitor is a person)', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({
        decision: 'deny',
        source: 'terminal',
        record: personRecord('monitor', 'deny'),
      });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.approved).toBe(false);
      expect(res.decidedBy).toBe('person');
      expect(res.channel).toBe('monitor');
      expect(res.blockedByLabel).toBe('User Decision (node9 monitor)');
    });

    it("a native popup allow loses to a person's deny already on the card", async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.token = 'tok';
      H.askNativePopup.mockResolvedValue('allow');
      H.resolveViaDaemon.mockResolvedValue({
        won: false,
        record: personRecord('terminal', 'deny'),
      });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      // Before: the hook kept its own allow and fired /resolve without reading
      // the reply, so the call ran while the card and the audit said denied.
      expect(res.approved).toBe(false);
      expect(res.decidedBy).toBe('person');
      expect(res.channel).toBe('terminal');
      const sent = H.resolveViaDaemon.mock.calls[0][4];
      expect(sent).toMatchObject({ decision: 'allow', decidedBy: 'person', channel: 'native' });
    });

    it('a cloud deny is not reported back to the cloud as a local decision', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.cloudEnabled.mockReturnValue(true);
      H.pollNode9SaaS.mockResolvedValue({ approved: false, reason: 'no' });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.approved).toBe(false);
      expect(res.decidedBy).toBe('cloud');
      // Before: the deny had no checkedBy, so it was PATCHed back as "local".
      expect(H.resolveNode9SaaS).not.toHaveBeenCalled();
    });

    it('the cloud-path card carries the cwd, the session and the recovery command', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.cloudEnabled.mockReturnValue(true);

      void authorizeHeadless(
        'Bash',
        { command: 'git push' },
        { sessionId: 'sess-1' },
        { cwd: '/tmp/proj' }
      );
      await vi.waitFor(() => expect(H.notifyDaemonViewer).toHaveBeenCalled());

      const extra = H.notifyDaemonViewer.mock.calls[0][6];
      expect(extra).toMatchObject({
        cwd: '/tmp/proj',
        sessionId: 'sess-1',
        card: { channels: ['terminal', 'monitor', 'native', 'cloud'] },
      });
    });

    it('one timer: with a protocol-2 card the hook arms none; the card times out', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.approvalTimeoutMs = 60;
      H.registerDaemonEntry.mockResolvedValue({
        id: 'entry-1',
        allowCount: 1,
        protocol: 2,
        deadline: Date.now() + 60,
      });
      let daemonAnswered = false;
      H.waitForDaemonDecision.mockImplementation(
        () =>
          new Promise((resolve) =>
            setTimeout(() => {
              daemonAnswered = true;
              resolve({
                decision: 'deny',
                source: 'timeout',
                record: {
                  decision: 'deny',
                  decidedBy: 'timer',
                  label: 'Approval Timeout',
                  decidedAt: Date.now(),
                },
              });
            }, 300)
          )
      );

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      // Before: the hook's own 60 ms timer ended the race first.
      expect(daemonAnswered).toBe(true);
      expect(res.decidedBy).toBe('timer');
      expect(res.blockedBy).toBe('timeout');
    });

    it('an older daemon (no protocol): the hook keeps its own timer', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.approvalTimeoutMs = 60;

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      expect(res.decidedBy).toBe('timer');
      expect(res.blockedBy).toBe('timeout');
    });

    it("a person's redirect in node9 tail reaches the agent as their instruction", async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({
        decision: 'deny',
        source: 'terminal-redirect',
        reason: 'Run `npm test` first, then retry.',
        record: personRecord('terminal', 'deny', { redirect: 'Run `npm test` first, then retry.' }),
      });

      const res = await authorizeHeadless('Bash', { command: 'git push' });

      // Before: "Steered Redirect (Terminal)" failed the label test and the
      // agent got a generic "blocked by security policy" with no instruction.
      expect(res.decidedBy).toBe('person');
      const msg = agentMessage(res);
      expect(msg).toMatch(/gave you an instruction/);
      expect(msg).toContain('Run `npm test` first, then retry.');
    });

    it('lists the native channel only where the popup can show', async () => {
      if (process.platform !== 'linux') return;
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'terminal' });
      delete process.env.DISPLAY;
      const savedWayland = process.env.WAYLAND_DISPLAY;
      delete process.env.WAYLAND_DISPLAY;
      try {
        await authorizeHeadless('Bash', { command: 'git push' });
      } finally {
        if (savedWayland !== undefined) process.env.WAYLAND_DISPLAY = savedWayland;
      }

      // Before: native was listed on a headless machine, so the card was never
      // abandoned when node9 tail closed and waited with nobody to answer.
      const args = H.registerDaemonEntry.mock.calls[0];
      expect(args[args.length - 1].channels).toEqual(['terminal', 'monitor']);
    });

    it('a softened block whose wait failed is not reported back to the card', async () => {
      H.evaluatePolicy.mockResolvedValue(JAIL_BLOCK);
      H.token = 'tok';
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny' });

      const res = await authorizeHeadless('Bash', { command: 'echo hello' });

      expect(res.blockedBy).toBe('local-config');
      expect(H.resolveViaDaemon).not.toHaveBeenCalled();
    });

    it('a protocol-2 card with no timer is waited on with no cap', async () => {
      H.evaluatePolicy.mockResolvedValue(PUSH_REVIEW);
      H.registerDaemonEntry.mockResolvedValue({
        id: 'entry-1',
        allowCount: 1,
        protocol: 2,
        deadline: null,
      });
      H.waitForDaemonDecision.mockResolvedValue({ decision: 'deny', source: 'terminal' });

      await authorizeHeadless('Bash', { command: 'git push' });

      expect(H.waitForDaemonDecision.mock.calls[0][2]).toBe(0);
    });
  });
});
