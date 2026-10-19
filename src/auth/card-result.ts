// src/auth/card-result.ts
// The hook's side of the decision record: ONE function turns a card's
// DecisionRecord into the AuthResult the agent, the audit row and the cloud
// read, and one turns a racer's AuthResult back into a record for the card.
// Before, the terminal racer rebuilt who decided from a one-word `source` in
// a chain of special cases (fw#304 and its reviews).
import {
  ABANDONED_LABEL,
  CLOUD_LABEL,
  TIMER_LABEL,
  type Channel,
  type DecidedBy,
  type DecisionRecord,
} from './decision-record';
import type { AuthResult } from './orchestrator';

const CHANNEL_NAMES: Record<Channel, string> = {
  terminal: 'Terminal (node9 tail)',
  monitor: 'node9 monitor',
  native: 'system dialog window',
  cloud: 'organization',
};

export interface RecordContext {
  /** The rule's own block, when a block was softened to this review: a timer
   *  (nobody answered) reports the rule's verdict, not "no response". */
  downgradedBlock?: AuthResult | null;
  /** The hook's own wording for a timeout (it names the setting and the fix). */
  timeoutReason?: string;
}

/** The AuthResult for a card's decision. */
export function authResultFromRecord(r: DecisionRecord, ctx: RecordContext = {}): AuthResult {
  const who = { decidedBy: r.decidedBy, ...(r.channel && { channel: r.channel }) };
  switch (r.decidedBy) {
    case 'person': {
      const channel = r.channel ?? 'terminal';
      const decisionSource = channel === 'native' ? 'native' : 'terminal';
      if (r.decision === 'allow') {
        return { approved: true, checkedBy: 'daemon', decisionSource, ...who };
      }
      return {
        approved: false,
        reason:
          r.redirect ||
          `The human user rejected this action via the Node9 ${CHANNEL_NAMES[channel]}.`,
        blockedBy: 'local-decision',
        blockedByLabel: r.label,
        decisionSource,
        ...who,
        ...(r.redirect && { redirect: r.redirect }),
      };
    }
    case 'timer':
      if (r.decision === 'deny' && ctx.downgradedBlock)
        return { ...ctx.downgradedBlock, blockedBy: 'timeout', ...who };
      return r.decision === 'allow'
        ? { approved: true, ...who }
        : {
            approved: false,
            reason:
              ctx.timeoutReason ||
              r.reason ||
              'No response: auto-denied after the approval timeout.',
            blockedBy: 'timeout',
            blockedByLabel: TIMER_LABEL,
            ...who,
          };
    case 'cloud':
      return r.decision === 'allow'
        ? { approved: true, checkedBy: 'cloud', decisionSource: 'cloud', ...who }
        : {
            approved: false,
            reason: r.reason || 'Action rejected by organization administrator via Slack.',
            blockedBy: 'team-policy',
            blockedByLabel: CLOUD_LABEL,
            decisionSource: 'cloud',
            ...who,
          };
    case 'policy':
      return r.decision === 'allow'
        ? { approved: true, checkedBy: 'local-policy', ...who }
        : {
            approved: false,
            reason: r.reason || 'Action blocked by policy.',
            blockedBy: 'local-config',
            blockedByLabel: r.label,
            ...(r.ruleName && { ruleHit: r.ruleName }),
            ...who,
          };
    case 'abandoned':
      return {
        approved: false,
        reason: r.reason || 'No approver was left to answer.',
        blockedBy: 'no-approval-mechanism',
        blockedByLabel: ABANDONED_LABEL,
        ...who,
      };
  }
}

/** The result when the card gave no decision (the daemon died, the card was
 *  withdrawn, an older daemon named no decider): no channel decided, so no
 *  rule is named either. */
export function approvalUnavailable(reason?: string): AuthResult {
  return {
    approved: false,
    reason: reason || 'node9 could not get an approval decision for this call.',
    blockedBy: 'no-approval-mechanism',
    blockedByLabel: 'Approval Unavailable',
  };
}

/** Who decided a racer's result, for a result that does not say. */
function decidedByOf(res: AuthResult): DecidedBy {
  if (res.decidedBy) return res.decidedBy;
  if (res.blockedBy === 'timeout') return 'timer';
  if (res.checkedBy === 'cloud' || res.blockedBy === 'team-policy') return 'cloud';
  return 'policy';
}

/** The record the hook reports to the card for its own winning racer. */
export function recordFromAuthResult(res: AuthResult, now = Date.now()): DecisionRecord {
  const decidedBy = decidedByOf(res);
  const channel: Channel | undefined =
    res.channel ??
    (decidedBy === 'cloud' ? 'cloud' : decidedBy === 'person' ? 'native' : undefined);
  return {
    decision: res.approved ? 'allow' : 'deny',
    decidedBy,
    ...(channel && { channel }),
    label:
      res.blockedByLabel ||
      (decidedBy === 'cloud'
        ? CLOUD_LABEL
        : decidedBy === 'timer'
          ? TIMER_LABEL
          : res.approved
            ? 'Allowed'
            : 'Blocked'),
    ...(res.reason && { reason: res.reason.slice(0, 2000) }),
    ...(res.ruleHit && { ruleName: res.ruleHit }),
    ...(res.redirect && { redirect: res.redirect }),
    decidedAt: now,
  };
}
