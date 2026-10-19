// The daemon's two UIs on the approval-card protocol: node9 tail shows how
// long a card waits, and node9 monitor's keys mean what they say.
import { describe, it, expect } from 'vitest';
import { deadlineLine } from '../tui/tail';
import { monitorDecisionBody } from '../tui/dashboard/data';

describe('node9 tail: the card says how long it waits', () => {
  it('a deadline shows the time left', () => {
    const now = Date.UTC(2026, 9, 19, 12, 0, 0);
    expect(deadlineLine(now + 125_000, now)).toMatch(
      /^Auto-denies in 2m 5s \(at .+\) if nobody answers$/
    );
  });
  it('no timer says so', () => {
    expect(deadlineLine(null)).toBe('No timeout: waits for your answer');
  });
  it('an older daemon sends no deadline: no line', () => {
    expect(deadlineLine(undefined)).toBeNull();
  });
});

describe('node9 monitor: the decision it sends', () => {
  it('trust is a 30 minute trust, never a permanent decision', () => {
    // Before: { decision: 'trust', persist: true } with no duration, which the
    // daemon turned into a permanent deny of the whole tool.
    expect(monitorDecisionBody('trust')).toEqual({
      decision: 'trust',
      source: 'monitor',
      trustDuration: '30m',
    });
  });
  it('allow and deny name monitor as the channel', () => {
    expect(monitorDecisionBody('deny')).toEqual({ decision: 'deny', source: 'monitor' });
    expect(monitorDecisionBody('allow')).toEqual({ decision: 'allow', source: 'monitor' });
  });
});
