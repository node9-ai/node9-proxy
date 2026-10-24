// Tune from the event (node9Firewall#390, phase 4). When a person keeps
// approving the same thing, offer the smallest change that stops the
// question. Pure: rows in, suggestions out; the host shows them and a person
// applies one. Nothing here changes a setting.
//
// Guardrails (settings-simplification-design.md 3.4): several approvals, in
// at least two sessions, and no recorded denial of the same rule.

import { CHECK_BY_ID, checkIdForRule, ruleNameInLabel } from './catalog';

export interface ApprovalRow {
  /** The rule or label the review carried (`shield:stripe:review-refund`, or
   *  `Smart Rule: shield:stripe:review-refund`). */
  ruleName: string;
  decision: 'approved' | 'denied';
  sessionId?: string;
  /** The MCP server label, when the call came through one. */
  server?: string;
}

export type Suggestion =
  | {
      kind: 'quiet-rule';
      ruleName: string;
      shield: string;
      /** The rule's part after the shield (`review-refund`). */
      rule: string;
      /** Its pack row in the checks catalog (`packs.stripe.refund`). */
      checkId: string;
      approvals: number;
      sessions: number;
    }
  | {
      kind: 'link-server';
      server: string;
      /** The general check that asked (`actions.money`). */
      checkId: string;
      approvals: number;
      sessions: number;
    };

export interface SuggestOptions {
  minApprovals?: number;
  minSessions?: number;
}

/** `Smart Rule: shield:x:y` and the other wrapping labels -> `shield:x:y`;
 *  anything else is returned as it is. The catalog's own reading, so a rule
 *  name that only contains a shield-like part is not taken for one. */
export function unwrapRuleLabel(label: string): string {
  return ruleNameInLabel(label.trim()) ?? label.trim();
}

const SHIELD_RULE = /^shield:([a-z0-9-]+):((?:review|block)-[a-z0-9-]+)$/;
const ACTION_RULE = /^review-action-(money|access|publish)-/;

/** The pack row a shield rule is, or undefined when the catalog shows it as
 *  a product check instead (a credential-file read, chmod) or not at all:
 *  "stop asking" is offered only for an app's own pack rows. */
function packRowOf(ruleName: string, shield: string): string | undefined {
  const id = checkIdForRule(ruleName);
  const def = id ? CHECK_BY_ID.get(id) : undefined;
  return def?.pack === shield && def.legacy?.includes(ruleName) ? id : undefined;
}

export function suggestFromApprovals(
  rows: readonly ApprovalRow[],
  opts: SuggestOptions = {}
): Suggestion[] {
  const minApprovals = opts.minApprovals ?? 3;
  const minSessions = opts.minSessions ?? 2;
  type Acc = { approvals: number; sessions: Set<string>; denied: boolean };
  const byKey = new Map<string, Acc & { ruleName: string; server?: string }>();
  for (const r of rows) {
    const ruleName = unwrapRuleLabel(r.ruleName);
    const action = ACTION_RULE.exec(ruleName);
    if (action && checkIdForRule(ruleName) !== `actions.${action[1]}`) continue;
    // A general check is about the server (every money action on it counts
    // together); a shield rule is about the rule.
    if (action && !r.server) continue;
    const key = action ? `server:${r.server!.toLowerCase()}:${action[1]}` : `rule:${ruleName}`;
    const isAction = action !== null;
    const acc = byKey.get(key) ?? {
      ruleName,
      server: isAction ? r.server : undefined,
      approvals: 0,
      sessions: new Set<string>(),
      denied: false,
    };
    if (r.decision === 'denied') acc.denied = true;
    else {
      acc.approvals += 1;
      if (r.sessionId) acc.sessions.add(r.sessionId);
    }
    byKey.set(key, acc);
  }
  const out: Suggestion[] = [];
  for (const acc of byKey.values()) {
    if (acc.denied || acc.approvals < minApprovals || acc.sessions.size < minSessions) continue;
    const shieldRule = SHIELD_RULE.exec(acc.ruleName);
    if (shieldRule) {
      const checkId = packRowOf(acc.ruleName, shieldRule[1]);
      if (!checkId) continue;
      out.push({
        kind: 'quiet-rule',
        ruleName: acc.ruleName,
        shield: shieldRule[1],
        rule: shieldRule[2],
        checkId,
        approvals: acc.approvals,
        sessions: acc.sessions.size,
      });
      continue;
    }
    const action = ACTION_RULE.exec(acc.ruleName);
    if (action && acc.server) {
      out.push({
        kind: 'link-server',
        server: acc.server,
        checkId: `actions.${action[1]}`,
        approvals: acc.approvals,
        sessions: acc.sessions.size,
      });
    }
  }
  return out.sort((a, b) => b.approvals - a.approvals);
}
