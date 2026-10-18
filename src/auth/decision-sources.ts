// src/auth/decision-sources.ts
// Who resolved a daemon card, as GET /wait reports it in `source`.
//
// ONE list of the channels a person answers on, shared by the daemon's
// /decision and /resolve routes and the hook's terminal racer: when they were
// two lists, a new human channel could be accepted by /decision and then
// reported to the agent as a rule (fw#304 review).

/** A person answered the card: node9 tail, the browser dashboard, the desktop popup. */
export const HUMAN_DECISION_SOURCES: ReadonlySet<string> = new Set([
  'terminal',
  'browser',
  'native',
]);

/** node9 tail choice [2]: a person denies and steers the agent with their own reason. */
export const REDIRECT_SOURCE = 'terminal-redirect';

/** What /decision accepts from a client: a person's channel or a redirect. */
export const DECISION_ROUTE_SOURCES: ReadonlySet<string> = new Set([
  ...HUMAN_DECISION_SOURCES,
  REDIRECT_SOURCE,
]);

/**
 * Sources the daemon sets itself, never accepted from a request:
 * - `timeout`: the daemon's auto-deny timer, or the timeout racer of its own
 *   background pass;
 * - `cloud`: the background pass's cloud racer (an administrator in Slack or
 *   Mission Control, or the organisation's policy), the same decider as the
 *   hook's own cloud racer;
 * - `policy`: any other verdict of the background pass (a rule).
 */
export type DaemonDecisionSource = 'timeout' | 'cloud' | 'policy';

/** The source of a card the daemon's background pass resolved, from its verdict. */
export function backgroundPassSource(result: {
  checkedBy?: string;
  blockedBy?: string;
}): DaemonDecisionSource {
  if (result.checkedBy === 'cloud' || result.blockedBy === 'team-policy') return 'cloud';
  if (result.blockedBy === 'timeout') return 'timeout';
  return 'policy';
}
