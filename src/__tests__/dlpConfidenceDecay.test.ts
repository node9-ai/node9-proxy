import { describe, it, expect } from 'vitest';
import {
  buildRecurringPatternSet,
  isStaleFinding,
  sortDlpFindingsByPriority,
} from '../cli/commands/scan';

// Fixed clock for stable age tests
const NOW = Date.parse('2026-04-30T12:00:00Z');

function f(opts: { patternName: string; sessionId: string; daysAgo?: number }) {
  const ts =
    opts.daysAgo !== undefined ? new Date(NOW - opts.daysAgo * 86_400_000).toISOString() : '';
  return {
    patternName: opts.patternName,
    sessionId: opts.sessionId,
    timestamp: ts,
  };
}

describe('buildRecurringPatternSet', () => {
  it('returns empty set when there are no findings', () => {
    expect(buildRecurringPatternSet([]).size).toBe(0);
  });

  it('marks a pattern recurring at exactly 3 distinct sessions', () => {
    const findings = [
      f({ patternName: 'GCP API Key', sessionId: 'a' }),
      f({ patternName: 'GCP API Key', sessionId: 'b' }),
      f({ patternName: 'GCP API Key', sessionId: 'c' }),
    ];
    const recurring = buildRecurringPatternSet(findings);
    expect(recurring.has('GCP API Key')).toBe(true);
  });

  it('does NOT mark a pattern recurring at 2 distinct sessions', () => {
    const findings = [
      f({ patternName: 'AWS Access Key', sessionId: 'a' }),
      f({ patternName: 'AWS Access Key', sessionId: 'b' }),
    ];
    const recurring = buildRecurringPatternSet(findings);
    expect(recurring.has('AWS Access Key')).toBe(false);
  });

  it('counts distinct sessions, not finding occurrences', () => {
    // Same pattern, same session, 5 times → 1 session, NOT recurring
    const findings = Array.from({ length: 5 }, () =>
      f({ patternName: 'JWT', sessionId: 'one-session' })
    );
    const recurring = buildRecurringPatternSet(findings);
    expect(recurring.has('JWT')).toBe(false);
  });

  it('ignores findings with empty sessionId (shell-config etc)', () => {
    const findings = [
      f({ patternName: 'X', sessionId: '' }),
      f({ patternName: 'X', sessionId: '' }),
      f({ patternName: 'X', sessionId: '' }),
      f({ patternName: 'X', sessionId: '' }),
    ];
    const recurring = buildRecurringPatternSet(findings);
    expect(recurring.has('X')).toBe(false);
  });
});

describe('isStaleFinding', () => {
  it('returns false for an empty timestamp (defensive)', () => {
    expect(isStaleFinding('', NOW)).toBe(false);
  });

  it('returns false for an unparseable timestamp (defensive)', () => {
    expect(isStaleFinding('not-a-date', NOW)).toBe(false);
  });

  it('returns false for findings under 30 days old', () => {
    const t = new Date(NOW - 25 * 86_400_000).toISOString();
    expect(isStaleFinding(t, NOW)).toBe(false);
  });

  it('returns true for findings older than 30 days', () => {
    const t = new Date(NOW - 45 * 86_400_000).toISOString();
    expect(isStaleFinding(t, NOW)).toBe(true);
  });

  it('handles boundary (exactly 30 days = not stale; >30 days = stale)', () => {
    const exactly30 = new Date(NOW - 30 * 86_400_000).toISOString();
    expect(isStaleFinding(exactly30, NOW)).toBe(false);
    const thirtyOne = new Date(NOW - 31 * 86_400_000).toISOString();
    expect(isStaleFinding(thirtyOne, NOW)).toBe(true);
  });
});

describe('sortDlpFindingsByPriority', () => {
  it('puts recurring patterns before one-offs', () => {
    const findings = [
      f({ patternName: 'OneOff', sessionId: 'z', daysAgo: 1 }),
      f({ patternName: 'Recurring', sessionId: 'a', daysAgo: 50 }),
      f({ patternName: 'Recurring', sessionId: 'b', daysAgo: 50 }),
      f({ patternName: 'Recurring', sessionId: 'c', daysAgo: 50 }),
    ];
    const sorted = sortDlpFindingsByPriority(findings, NOW);
    // Even though Recurring is 50 days old (stale) and OneOff is 1 day,
    // Recurring wins on the recurring axis
    expect(sorted[0].patternName).toBe('Recurring');
  });

  it('puts non-stale before stale within same recurring tier', () => {
    const findings = [
      f({ patternName: 'X', sessionId: 'a', daysAgo: 60 }), // stale
      f({ patternName: 'Y', sessionId: 'b', daysAgo: 5 }), // fresh
    ];
    const sorted = sortDlpFindingsByPriority(findings, NOW);
    expect(sorted.map((s) => s.patternName)).toEqual(['Y', 'X']);
  });

  it('sorts by recency within same recurring + staleness tier', () => {
    const findings = [
      f({ patternName: 'A', sessionId: '1', daysAgo: 10 }),
      f({ patternName: 'B', sessionId: '2', daysAgo: 2 }),
      f({ patternName: 'C', sessionId: '3', daysAgo: 5 }),
    ];
    const sorted = sortDlpFindingsByPriority(findings, NOW);
    expect(sorted.map((s) => s.patternName)).toEqual(['B', 'C', 'A']);
  });

  it('is stable for ties (same recurring, same staleness, same timestamp)', () => {
    const findings = [
      f({ patternName: 'A', sessionId: '1', daysAgo: 5 }),
      f({ patternName: 'B', sessionId: '2', daysAgo: 5 }),
      f({ patternName: 'C', sessionId: '3', daysAgo: 5 }),
    ];
    const sorted = sortDlpFindingsByPriority(findings, NOW);
    expect(sorted.map((s) => s.patternName)).toEqual(['A', 'B', 'C']);
  });

  it('does not mutate the input array', () => {
    const findings = [
      f({ patternName: 'X', sessionId: 'a', daysAgo: 60 }),
      f({ patternName: 'Y', sessionId: 'b', daysAgo: 5 }),
    ];
    const before = findings.map((x) => x.patternName);
    sortDlpFindingsByPriority(findings, NOW);
    expect(findings.map((x) => x.patternName)).toEqual(before);
  });
});
