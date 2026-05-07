/**
 * Unit tests for buildScanJson — the envelope used by `node9 scan --json`.
 *
 * The builder is pure: given (scan, summary, blast, isWired, generatedAt)
 * it returns a stable shape. These tests pin the schemaVersion contract,
 * verify totals derive correctly from summary.byVerdict, and check band
 * classification at each boundary.
 */
import { describe, it, expect } from 'vitest';
import { buildScanJson } from '../cli/render/scan-json';
import type { ScanResult } from '../cli/commands/scan';
import type { ScanSummary } from '../scan-summary';
import type { BlastResult } from '../cli/commands/blast';

const FIXED_TIME = '2026-05-07T12:00:00.000Z';

function emptyScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    filesScanned: 0,
    sessions: 0,
    totalToolCalls: 0,
    bashCalls: 0,
    findings: [],
    dlpFindings: [],
    loopFindings: [],
    totalCostUSD: 0,
    firstDate: null,
    lastDate: null,
    sessionsWithEarlySecrets: 0,
    ...overrides,
  };
}

function emptySummary(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    stats: {
      sessions: 0,
      totalToolCalls: 0,
      bashCalls: 0,
      totalCostUSD: 0,
      firstDate: null,
      lastDate: null,
    },
    byVerdict: { blocked: 0, supervised: 0, leaks: 0, loops: 0 },
    byAgent: [],
    sections: [],
    leaks: [],
    loops: [],
    loopWastedUSD: 0,
    ...overrides,
  };
}

function blastWith(score: number, overrides: Partial<BlastResult> = {}): BlastResult {
  return {
    score,
    reachable: [],
    envFindings: [],
    ...overrides,
  };
}

describe('buildScanJson', () => {
  it('emits schemaVersion 1 and the supplied generatedAt', () => {
    const out = buildScanJson({
      scan: emptyScan(),
      summary: emptySummary(),
      blast: blastWith(95),
      isWired: true,
      generatedAt: FIXED_TIME,
    });
    expect(out.schemaVersion).toBe(1);
    expect(out.generatedAt).toBe(FIXED_TIME);
  });

  it('passes isWired through unchanged', () => {
    const wired = buildScanJson({
      scan: emptyScan(),
      summary: emptySummary(),
      blast: blastWith(50),
      isWired: true,
      generatedAt: FIXED_TIME,
    });
    const unwired = buildScanJson({
      scan: emptyScan(),
      summary: emptySummary(),
      blast: blastWith(50),
      isWired: false,
      generatedAt: FIXED_TIME,
    });
    expect(wired.isWired).toBe(true);
    expect(unwired.isWired).toBe(false);
  });

  it('classifies band at each boundary (mirrors classifyScore)', () => {
    const at = (score: number) =>
      buildScanJson({
        scan: emptyScan(),
        summary: emptySummary(),
        blast: blastWith(score),
        isWired: false,
        generatedAt: FIXED_TIME,
      }).band;
    expect(at(100)).toBe('good');
    expect(at(80)).toBe('good');
    expect(at(79)).toBe('at-risk');
    expect(at(50)).toBe('at-risk');
    expect(at(49)).toBe('critical');
    expect(at(0)).toBe('critical');
  });

  it('hoists totals from summary.byVerdict and blast', () => {
    const out = buildScanJson({
      scan: emptyScan(),
      summary: emptySummary({
        byVerdict: { blocked: 8, supervised: 56, leaks: 4, loops: 290 },
      }),
      blast: blastWith(25, {
        reachable: [
          { full: '/u/.ssh/id_rsa', label: 'ssh', description: '', score: 30 },
          { full: '/u/.ssh/id_ed25519', label: 'ssh', description: '', score: 30 },
        ],
        envFindings: [{ key: 'AWS_SECRET_ACCESS_KEY', patternName: 'aws' }],
      }),
      isWired: false,
      generatedAt: FIXED_TIME,
    });
    expect(out.totals).toEqual({
      blocked: 8,
      review: 56,
      leaks: 4,
      loops: 290,
      blastExposures: 3, // 2 reachable + 1 envFinding
    });
    expect(out.score).toBe(25);
  });

  it('embeds the supplied summary verbatim (no field rewrite)', () => {
    const summary = emptySummary({
      byVerdict: { blocked: 1, supervised: 2, leaks: 3, loops: 4 },
      loopWastedUSD: 0.5,
    });
    const out = buildScanJson({
      scan: emptyScan(),
      summary,
      blast: blastWith(70),
      isWired: false,
      generatedAt: FIXED_TIME,
    });
    expect(out.summary).toBe(summary); // same reference — no copy/transform
  });

  it('serializes to valid JSON (round-trip)', () => {
    const out = buildScanJson({
      scan: emptyScan({ sessions: 5 }),
      summary: emptySummary({ stats: { ...emptySummary().stats, sessions: 5 } }),
      blast: blastWith(60),
      isWired: true,
      generatedAt: FIXED_TIME,
    });
    const json = JSON.stringify(out);
    const parsed = JSON.parse(json);
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.band).toBe('at-risk');
    expect(parsed.summary.stats.sessions).toBe(5);
  });
});
