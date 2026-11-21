// Privilege row: a sudo rule that sends the command to review IS a gate.
// On 2026-11-21 posture told the founder "No sudo rule is active" while the
// built-in review-sudo rule was on, because only `block` counted as gated.
import { describe, it, expect, vi, beforeEach } from 'vitest';

const decision = { current: 'allow' as 'allow' | 'review' | 'block' };

vi.mock('../../policy', () => ({
  evaluatePolicy: async () => ({ decision: decision.current }),
}));

import { checkPrivilege } from '../privilege';

const CTX = { home: '/home/u', cwd: '/home/u' };
const notGated = (fs: { title: string }[]) =>
  fs.some((f) => f.title === 'Privilege escalation is not gated');

describe('posture privilege check', () => {
  beforeEach(() => {
    decision.current = 'allow';
  });

  it('reports sudo as not gated when the policy allows it', async () => {
    expect(notGated(await checkPrivilege(CTX))).toBe(true);
  });

  it('treats a review rule for sudo as gated', async () => {
    decision.current = 'review';
    expect(notGated(await checkPrivilege(CTX))).toBe(false);
  });

  it('treats a block rule for sudo as gated', async () => {
    decision.current = 'block';
    expect(notGated(await checkPrivilege(CTX))).toBe(false);
  });
});
