/**
 * Unit tests for the dashboard's pure display-formatting helpers in
 * src/tui/dashboard/format.ts. Extracted from panels.tsx so tests
 * don't drag in the React/Ink runtime.
 */
import { describe, expect, it } from 'vitest';
import {
  cacheHitRate,
  formatCost,
  formatPct,
  formatTokens,
  shortenModel,
  truncate,
} from '../tui/dashboard/format';
import type { CostSnapshot } from '../tui/dashboard/types';

describe('formatCost', () => {
  it('returns "$0" for exact zero', () => {
    expect(formatCost(0)).toBe('$0');
  });
  it('keeps two decimals for sub-dollar amounts', () => {
    expect(formatCost(0.42)).toBe('$0.42');
    expect(formatCost(0.005)).toBe('$0.01'); // toFixed rounds
  });
  it('keeps two decimals up to $100', () => {
    expect(formatCost(12.34)).toBe('$12.34');
    expect(formatCost(99.99)).toBe('$99.99');
  });
  it('rounds and adds thousands separator for $100..$10K', () => {
    expect(formatCost(1234.56)).toBe('$1,235');
    expect(formatCost(9999)).toBe('$9,999');
  });
  it('uses K suffix for values >= $10K', () => {
    expect(formatCost(10_000)).toBe('$10.0K');
    expect(formatCost(123_456)).toBe('$123.5K');
  });
});

describe('formatTokens', () => {
  it('keeps raw integer below 1K', () => {
    expect(formatTokens(0)).toBe('0');
    expect(formatTokens(999)).toBe('999');
  });
  it('uses K with 1 decimal below 10K', () => {
    expect(formatTokens(1234)).toBe('1.2K');
    expect(formatTokens(9999)).toBe('10.0K'); // edge: rounds up
  });
  it('uses K with no decimal between 10K and 1M', () => {
    expect(formatTokens(12_345)).toBe('12K');
    expect(formatTokens(999_000)).toBe('999K');
  });
  it('uses M with 1 decimal at 1M+', () => {
    expect(formatTokens(1_234_000)).toBe('1.2M');
    expect(formatTokens(234_000_000)).toBe('234.0M');
  });
});

describe('formatPct', () => {
  it('rounds to whole percent', () => {
    expect(formatPct(94.4)).toBe('94%');
    expect(formatPct(94.6)).toBe('95%');
  });
  it('returns "—" for non-finite', () => {
    expect(formatPct(NaN)).toBe('—');
    expect(formatPct(Infinity)).toBe('—');
    expect(formatPct(-Infinity)).toBe('—');
  });
});

describe('cacheHitRate', () => {
  function snap(over: Partial<CostSnapshot>): CostSnapshot {
    return {
      totalUSD: 0,
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      byModel: [],
      loaded: true,
      ...over,
    };
  }

  it('reads / (reads + input)', () => {
    expect(cacheHitRate(snap({ cacheReadTokens: 90, inputTokens: 10 }))).toBeCloseTo(90);
    expect(cacheHitRate(snap({ cacheReadTokens: 50, inputTokens: 50 }))).toBeCloseTo(50);
  });
  it('returns 0 when no tokens at all (no divide-by-zero)', () => {
    expect(cacheHitRate(snap({}))).toBe(0);
  });
  it('returns 100 when only cache reads (cold-start absurd, but defined)', () => {
    expect(cacheHitRate(snap({ cacheReadTokens: 1000, inputTokens: 0 }))).toBe(100);
  });
  it('does not include output or cacheWrite (mirrors `node9 report`)', () => {
    // 100 reads, 0 inputs, but 9999 outputs + 9999 cacheWrites — denom uses
    // only reads + inputs, so rate is 100% regardless of output / write.
    const result = cacheHitRate(
      snap({
        cacheReadTokens: 100,
        inputTokens: 0,
        outputTokens: 9999,
        cacheWriteTokens: 9999,
      })
    );
    expect(result).toBe(100);
  });
});

describe('shortenModel', () => {
  it('strips claude- prefix', () => {
    expect(shortenModel('claude-opus-4-7')).toBe('opus-4-7');
    expect(shortenModel('claude-haiku-4-5')).toBe('haiku-4-5');
  });
  it('strips trailing -YYYYMMDD timestamp suffix', () => {
    expect(shortenModel('claude-haiku-4-5-20251001')).toBe('haiku-4-5');
  });
  it('passes through models without the claude- prefix', () => {
    expect(shortenModel('gpt-5')).toBe('gpt-5');
    expect(shortenModel('gemini-2-pro')).toBe('gemini-2-pro');
  });
});

describe('truncate', () => {
  it('passes through strings shorter than width', () => {
    expect(truncate('short', 10)).toBe('short');
    expect(truncate('exactlyten', 10)).toBe('exactlyten'); // == width
  });
  it('replaces last char with ellipsis when over width', () => {
    expect(truncate('this is too long', 10)).toBe('this is t…');
    expect(truncate('abcdefgh', 5)).toBe('abcd…');
  });
  it('handles empty string', () => {
    expect(truncate('', 10)).toBe('');
  });
});
