/**
 * Unit tests for the pure derivation helpers shared across the scan
 * renderers (default inline / --compact / --narrative).
 *
 * These mirror the inlined logic that the helpers replace, line-for-line,
 * so a regression in either direction is caught here.
 */
import { describe, it, expect } from 'vitest';
import chalk from 'chalk';
import {
  classifyScore,
  topDlpPatterns,
  topRulesByVerdict,
  computeLoopWaste,
} from '../cli/render/scan-derive';
import type { Section } from '../scan-summary';

describe('classifyScore', () => {
  it('100 → good', () => {
    const c = classifyScore(100);
    expect(c.band).toBe('good');
    expect(c.label).toBe('Good');
    expect(c.color).toBe(chalk.green);
  });

  it('80 → good (lower bound)', () => {
    expect(classifyScore(80).band).toBe('good');
  });

  it('79 → at-risk', () => {
    const c = classifyScore(79);
    expect(c.band).toBe('at-risk');
    expect(c.label).toBe('At Risk');
    expect(c.color).toBe(chalk.yellow);
  });

  it('50 → at-risk (lower bound)', () => {
    expect(classifyScore(50).band).toBe('at-risk');
  });

  it('49 → critical', () => {
    const c = classifyScore(49);
    expect(c.band).toBe('critical');
    expect(c.label).toBe('Critical');
    expect(c.color).toBe(chalk.red);
  });

  it('0 → critical', () => {
    expect(classifyScore(0).band).toBe('critical');
  });
});

describe('topDlpPatterns', () => {
  it('returns empty for empty input', () => {
    expect(topDlpPatterns([], 3)).toEqual([]);
  });

  it('groups by pattern name, sorts by frequency desc', () => {
    const findings = [
      { patternName: 'GitHub Token' },
      { patternName: 'AWS Access Key' },
      { patternName: 'GitHub Token' },
      { patternName: 'JWT' },
      { patternName: 'GitHub Token' },
    ];
    expect(topDlpPatterns(findings, 3)).toEqual([
      { name: 'GitHub Token', count: 3 },
      { name: 'AWS Access Key', count: 1 },
      { name: 'JWT', count: 1 },
    ]);
  });

  it('truncates to n', () => {
    const findings = [
      { patternName: 'a' },
      { patternName: 'b' },
      { patternName: 'c' },
      { patternName: 'd' },
    ];
    expect(topDlpPatterns(findings, 2)).toHaveLength(2);
  });
});

describe('topRulesByVerdict', () => {
  function section(rules: Section['rules']): Section {
    return {
      id: 's',
      label: 's',
      subtitle: '',
      sourceType: 'user',
      blockedCount: 0,
      reviewCount: 0,
      rules,
    };
  }

  function rule(name: string, verdict: 'block' | 'review', count: number): Section['rules'][0] {
    return {
      name,
      verdict,
      reason: '',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      findings: Array.from({ length: count }, (_, i) => ({ project: `p${i}` }) as any),
    };
  }

  it('returns empty for no sections', () => {
    expect(topRulesByVerdict([], 'block', 3)).toEqual([]);
  });

  it('returns top-N blocked rules across all sections, by finding count desc', () => {
    const sections: Section[] = [
      section([rule('block-force-push', 'block', 5), rule('review-rm', 'review', 30)]),
      section([rule('block-eval-remote', 'block', 1), rule('block-read-creds', 'block', 3)]),
    ];
    expect(topRulesByVerdict(sections, 'block', 3)).toEqual([
      { name: 'block-force-push', count: 5 },
      { name: 'block-read-creds', count: 3 },
      { name: 'block-eval-remote', count: 1 },
    ]);
  });

  it('returns top-N review rules (verdict !== block, matching original logic)', () => {
    const sections: Section[] = [
      section([rule('review-rm', 'review', 33), rule('block-x', 'block', 100)]),
      section([rule('review-sudo', 'review', 5)]),
    ];
    expect(topRulesByVerdict(sections, 'review', 3)).toEqual([
      { name: 'review-rm', count: 33 },
      { name: 'review-sudo', count: 5 },
    ]);
  });

  it('truncates to n', () => {
    const sections: Section[] = [
      section([
        rule('a', 'block', 5),
        rule('b', 'block', 4),
        rule('c', 'block', 3),
        rule('d', 'block', 2),
      ]),
    ];
    expect(topRulesByVerdict(sections, 'block', 2)).toHaveLength(2);
  });
});

describe('computeLoopWaste', () => {
  it('zero loops → zero waste', () => {
    expect(computeLoopWaste([], 100)).toEqual({ wastedCalls: 0, wastePct: 0 });
  });

  it('zero total calls → zero pct (no divide-by-zero)', () => {
    expect(computeLoopWaste([{ count: 50 }], 0)).toEqual({ wastedCalls: 49, wastePct: 0 });
  });

  it('waste per loop = count - 1', () => {
    // 126 + 101 = 227 → wasted = 125 + 100 = 225
    expect(computeLoopWaste([{ count: 126 }, { count: 101 }], 1000).wastedCalls).toBe(225);
  });

  it('count of 1 contributes zero waste', () => {
    expect(computeLoopWaste([{ count: 1 }, { count: 1 }], 100).wastedCalls).toBe(0);
  });

  it('rounds wastePct to whole percent (matches inline rounding)', () => {
    // 19 / 100 = 19% exact
    expect(computeLoopWaste([{ count: 20 }], 100).wastePct).toBe(19);
    // 1 / 3 ≈ 0.333... → rounds to 33%
    expect(computeLoopWaste([{ count: 2 }], 3).wastePct).toBe(33);
  });
});
