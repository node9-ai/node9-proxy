import { describe, it, expect } from 'vitest';
import { parseSinceCutoff, buildSessionTotals } from '../scan-upload-history.js';
import type { ScanFinding } from '@node9/policy-engine';

const finding = (sessionId: string, type: ScanFinding['type'], lineIndex = 0): ScanFinding => ({
  sessionId,
  type,
  lineIndex,
});

describe('parseSinceCutoff', () => {
  const now = new Date('2026-05-05T12:00:00Z');

  it('handles "all" → 0 epoch (no cutoff)', () => {
    expect(parseSinceCutoff('all', now)).toBe(0);
  });

  it('handles N-day windows', () => {
    const expected = now.getTime() - 7 * 86_400_000;
    expect(parseSinceCutoff('7d', now)).toBe(expected);
  });

  it('handles N-month windows (approx 30 days)', () => {
    const expected = now.getTime() - 3 * 30 * 86_400_000;
    expect(parseSinceCutoff('3m', now)).toBe(expected);
  });

  it('handles N-year windows (approx 365 days)', () => {
    const expected = now.getTime() - 1 * 365 * 86_400_000;
    expect(parseSinceCutoff('1y', now)).toBe(expected);
  });

  it('handles absolute YYYY-MM-DD dates', () => {
    expect(parseSinceCutoff('2026-01-01', now)).toBe(Date.parse('2026-01-01T00:00:00Z'));
  });

  it('falls back to 3 months on malformed input (defence-in-depth)', () => {
    const fallback = now.getTime() - 90 * 86_400_000;
    expect(parseSinceCutoff('not-a-date', now)).toBe(fallback);
    expect(parseSinceCutoff('', now)).toBe(fallback);
    expect(parseSinceCutoff('foo123', now)).toBe(fallback);
  });
});

describe('buildSessionTotals', () => {
  it('groups findings into per-session signal totals', () => {
    const totals = buildSessionTotals(
      [
        finding('sid-A', 'dlp'),
        finding('sid-A', 'dlp'),
        finding('sid-A', 'destructive-op'),
        finding('sid-B', 'pii'),
      ],
      { 'sid-A': 47, 'sid-B': 12 }
    );
    const a = totals.find((t) => t.runId === 'sid-A')!;
    expect(a.signals.dlpFindings).toBe(2);
    expect(a.signals.destructiveOps).toBe(1);
    expect(a.totalToolCalls).toBe(47);
    const b = totals.find((t) => t.runId === 'sid-B')!;
    expect(b.signals.piiFindings).toBe(1);
    expect(b.totalToolCalls).toBe(12);
  });

  it('includes sessions with zero findings but non-zero tool calls', () => {
    const totals = buildSessionTotals([], { 'sid-quiet': 30 });
    expect(totals).toHaveLength(1);
    expect(totals[0].runId).toBe('sid-quiet');
    expect(totals[0].totalToolCalls).toBe(30);
    expect(totals[0].signals.dlpFindings).toBe(0);
  });

  it('returns empty when nothing is parsed (no findings + no tool calls)', () => {
    expect(buildSessionTotals([], {})).toEqual([]);
  });
});
