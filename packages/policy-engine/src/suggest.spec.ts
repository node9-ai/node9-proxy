// Tune from the event (node9Firewall#390, phase 4): a suggestion only after
// several approvals in at least two sessions, never after a denial.
import { describe, it, expect } from 'vitest';
import { suggestFromApprovals, unwrapRuleLabel, type ApprovalRow } from './suggest';

const ok = (ruleName: string, sessionId: string, server?: string): ApprovalRow => ({
  ruleName,
  decision: 'approved',
  sessionId,
  server,
});

describe('suggestFromApprovals', () => {
  it('quiets a shield rule approved three times in two sessions', () => {
    const out = suggestFromApprovals([
      ok('Smart Rule: shield:stripe:review-refund', 's1'),
      ok('shield:stripe:review-refund', 's1'),
      ok('shield:stripe:review-refund', 's2'),
    ]);
    expect(out).toEqual([
      {
        kind: 'quiet-rule',
        ruleName: 'shield:stripe:review-refund',
        shield: 'stripe',
        rule: 'review-refund',
        checkId: 'packs.stripe.refund',
        approvals: 3,
        sessions: 2,
      },
    ]);
  });

  it('asks for more: two approvals, or one session', () => {
    expect(
      suggestFromApprovals([
        ok('shield:stripe:review-refund', 's1'),
        ok('shield:stripe:review-refund', 's2'),
      ])
    ).toEqual([]);
    expect(
      suggestFromApprovals([
        ok('shield:stripe:review-refund', 's1'),
        ok('shield:stripe:review-refund', 's1'),
        ok('shield:stripe:review-refund', 's1'),
      ])
    ).toEqual([]);
  });

  it('a recorded denial cancels the suggestion', () => {
    expect(
      suggestFromApprovals([
        ok('shield:stripe:review-refund', 's1'),
        ok('shield:stripe:review-refund', 's2'),
        ok('shield:stripe:review-refund', 's3'),
        { ruleName: 'shield:stripe:review-refund', decision: 'denied', sessionId: 's4' },
      ])
    ).toEqual([]);
  });

  it('a general check on a named server suggests linking it, counting its actions together', () => {
    const out = suggestFromApprovals([
      ok('review-action-money-refund', 's1', 'acme_billing'),
      ok('review-action-money-payout', 's1', 'acme_billing'),
      ok('review-action-money-refund', 's2', 'acme_billing'),
    ]);
    expect(out).toEqual([
      {
        kind: 'link-server',
        server: 'acme_billing',
        checkId: 'actions.money',
        approvals: 3,
        sessions: 2,
      },
    ]);
  });

  it('a general check without a server suggests nothing (nothing to link)', () => {
    expect(
      suggestFromApprovals([
        ok('review-action-money-refund', 's1'),
        ok('review-action-money-refund', 's2'),
        ok('review-action-money-refund', 's3'),
      ])
    ).toEqual([]);
  });

  it('ignores rules that are neither a shield rule nor a general action', () => {
    expect(
      suggestFromApprovals([
        ok('review-sudo', 's1'),
        ok('review-sudo', 's2'),
        ok('review-sudo', 's3'),
      ])
    ).toEqual([]);
  });

  it('unwraps a label', () => {
    expect(unwrapRuleLabel('⚠️ Override block rule: Smart Rule: shield:redis:block-flushall')).toBe(
      'shield:redis:block-flushall'
    );
    expect(unwrapRuleLabel('inline-review')).toBe('inline-review');
  });
});
