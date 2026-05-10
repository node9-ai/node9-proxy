/**
 * Unit tests for filterScanByPeriod / EMPTY_FILTERED_SCAN.
 *
 * These cover the pure derivation step that sits between the cached
 * scan walker output (3 ScanResults) and the bottom-row panels. The
 * walker itself is tested elsewhere; here we only verify the
 * period-filter + rollup math.
 */
import { describe, it, expect } from 'vitest';
import { EMPTY_FILTERED_SCAN, filterScanByPeriod } from '../tui/dashboard/views/report/derive';
import type { ScanResult } from '../cli/commands/scan';
import type { ScanCache } from '../tui/dashboard/types';

const NOW = new Date('2026-05-10T15:00:00Z');

function emptyResult(): ScanResult {
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
  };
}

function readyCache(
  overrides: Partial<{ claude: ScanResult; gemini: ScanResult; codex: ScanResult }> = {}
): Extract<ScanCache, { status: 'ready' }> {
  return {
    status: 'ready',
    readyAt: NOW.getTime(),
    results: {
      claude: overrides.claude ?? emptyResult(),
      gemini: overrides.gemini ?? emptyResult(),
      codex: overrides.codex ?? emptyResult(),
    },
  };
}

describe('EMPTY_FILTERED_SCAN', () => {
  it('exposes zero counters and empty arrays', () => {
    expect(EMPTY_FILTERED_SCAN.totalToolCalls).toBe(0);
    expect(EMPTY_FILTERED_SCAN.sessionsWithEarlySecrets).toBe(0);
    expect(EMPTY_FILTERED_SCAN.leaks).toEqual([]);
    expect(EMPTY_FILTERED_SCAN.loops).toEqual([]);
    expect(EMPTY_FILTERED_SCAN.findings).toEqual([]);
    expect(EMPTY_FILTERED_SCAN.leaksByType).toEqual([]);
    expect(EMPTY_FILTERED_SCAN.loopsByTool).toEqual([]);
    expect(EMPTY_FILTERED_SCAN.topRules).toEqual([]);
    expect(EMPTY_FILTERED_SCAN.topLoopFile).toBeUndefined();
  });
});

describe('filterScanByPeriod', () => {
  it('returns zeroed shape when all results are empty', () => {
    const out = filterScanByPeriod(readyCache(), '7d', NOW);
    expect(out.leaks).toEqual([]);
    expect(out.loops).toEqual([]);
    expect(out.findings).toEqual([]);
    expect(out.totalToolCalls).toBe(0);
  });

  it('drops findings outside the period window', () => {
    const claude: ScanResult = {
      ...emptyResult(),
      dlpFindings: [
        // In-window (last 7 days for NOW = May 10)
        {
          patternName: 'GitHub Token',
          redactedSample: 'ghp_***',
          toolName: 'Bash',
          timestamp: '2026-05-09T10:00:00Z',
          project: 'p',
          sessionId: 's1',
          agent: 'claude',
        },
        // Out-of-window (way before)
        {
          patternName: 'JWT',
          redactedSample: 'eyJ_***',
          toolName: 'Bash',
          timestamp: '2025-01-01T10:00:00Z',
          project: 'p',
          sessionId: 's2',
          agent: 'claude',
        },
      ],
    };
    const out = filterScanByPeriod(readyCache({ claude }), '7d', NOW);
    expect(out.leaks).toHaveLength(1);
    expect(out.leaks[0].patternName).toBe('GitHub Token');
  });

  it('drops findings with unparseable timestamps (best-effort filter)', () => {
    const claude: ScanResult = {
      ...emptyResult(),
      dlpFindings: [
        {
          patternName: 'GitHub Token',
          redactedSample: 'ghp_***',
          toolName: 'Bash',
          timestamp: 'not-a-date',
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
      ],
    };
    const out = filterScanByPeriod(readyCache({ claude }), '7d', NOW);
    expect(out.leaks).toHaveLength(0);
  });

  it('rolls up leaks by patternName, sorted desc', () => {
    const ts = '2026-05-09T10:00:00Z';
    const claude: ScanResult = {
      ...emptyResult(),
      dlpFindings: [
        {
          patternName: 'GitHub Token',
          redactedSample: 'a',
          toolName: 'B',
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
        {
          patternName: 'GitHub Token',
          redactedSample: 'b',
          toolName: 'B',
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
        {
          patternName: 'JWT',
          redactedSample: 'c',
          toolName: 'B',
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
        {
          patternName: 'GCP Key',
          redactedSample: 'd',
          toolName: 'B',
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
        {
          patternName: 'GitHub Token',
          redactedSample: 'e',
          toolName: 'B',
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
      ],
    };
    const out = filterScanByPeriod(readyCache({ claude }), '7d', NOW);
    expect(out.leaksByType).toEqual([
      { type: 'GitHub Token', count: 3 },
      { type: 'JWT', count: 1 },
      { type: 'GCP Key', count: 1 },
    ]);
  });

  it('rolls up loops by tool with correct pct (count/totalLoopOccurrences)', () => {
    const ts = '2026-05-09T10:00:00Z';
    const claude: ScanResult = {
      ...emptyResult(),
      loopFindings: [
        {
          toolName: 'Edit',
          commandPreview: '/a.ts',
          count: 70,
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
        {
          toolName: 'Edit',
          commandPreview: '/b.ts',
          count: 10,
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
        {
          toolName: 'Bash',
          commandPreview: 'ls',
          count: 20,
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
      ],
    };
    const out = filterScanByPeriod(readyCache({ claude }), '7d', NOW);
    // Total occurrences: 70 + 10 + 20 = 100
    // Edit: 80 → 80%, Bash: 20 → 20%
    expect(out.loopsByTool).toEqual([
      { tool: 'Edit', count: 80, pct: 80 },
      { tool: 'Bash', count: 20, pct: 20 },
    ]);
  });

  it('picks the single most-stuck file as topLoopFile', () => {
    const ts = '2026-05-09T10:00:00Z';
    const claude: ScanResult = {
      ...emptyResult(),
      loopFindings: [
        {
          toolName: 'Edit',
          commandPreview: '/scan.ts',
          count: 126,
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
        {
          toolName: 'Edit',
          commandPreview: '/server.ts',
          count: 37,
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
        // Multiple findings on the same file should sum
        {
          toolName: 'Edit',
          commandPreview: '/scan.ts',
          count: 14,
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
      ],
    };
    const out = filterScanByPeriod(readyCache({ claude }), '7d', NOW);
    expect(out.topLoopFile).toEqual({ path: '/scan.ts', count: 140 });
  });

  it('rolls up topRules from findings.source.rule.name', () => {
    const ts = '2026-05-09T10:00:00Z';
    // Cast through unknown — Finding/SmartRule have many fields the
    // rollup never reads. The fixture only needs source.rule.name.
    const mkFinding = (ruleName: string) =>
      ({
        source: {
          shieldName: '',
          shieldLabel: '',
          sourceType: 'default' as const,
          rule: {
            name: ruleName,
            tool: 'Bash',
            conditions: [],
            verdict: 'review' as const,
          },
        },
        toolName: 'Bash',
        input: {},
        timestamp: ts,
        project: 'p',
        sessionId: 's',
        agent: 'claude' as const,
      }) as unknown as ScanResult['findings'][number];
    const claude: ScanResult = {
      ...emptyResult(),
      findings: [
        mkFinding('review-rm'),
        mkFinding('review-rm'),
        mkFinding('review-rm'),
        mkFinding('review-git-destructive'),
        mkFinding('block-force-push'),
      ],
    };
    const out = filterScanByPeriod(readyCache({ claude }), '7d', NOW);
    expect(out.topRules).toEqual([
      { rule: 'review-rm', count: 3 },
      { rule: 'review-git-destructive', count: 1 },
      { rule: 'block-force-push', count: 1 },
    ]);
  });

  it('combines findings from all 3 agents', () => {
    const ts = '2026-05-09T10:00:00Z';
    const claude: ScanResult = {
      ...emptyResult(),
      totalToolCalls: 100,
      sessionsWithEarlySecrets: 1,
      dlpFindings: [
        {
          patternName: 'GitHub Token',
          redactedSample: 'a',
          toolName: 'B',
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'claude',
        },
      ],
    };
    const gemini: ScanResult = {
      ...emptyResult(),
      totalToolCalls: 50,
      sessionsWithEarlySecrets: 0,
      dlpFindings: [
        {
          patternName: 'JWT',
          redactedSample: 'b',
          toolName: 'B',
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'gemini',
        },
      ],
    };
    const codex: ScanResult = {
      ...emptyResult(),
      totalToolCalls: 25,
      sessionsWithEarlySecrets: 2,
      dlpFindings: [
        {
          patternName: 'GitHub Token',
          redactedSample: 'c',
          toolName: 'B',
          timestamp: ts,
          project: 'p',
          sessionId: 's',
          agent: 'codex',
        },
      ],
    };
    const out = filterScanByPeriod(readyCache({ claude, gemini, codex }), '7d', NOW);
    expect(out.totalToolCalls).toBe(175);
    expect(out.sessionsWithEarlySecrets).toBe(3);
    expect(out.leaks).toHaveLength(3);
    expect(out.leaksByType).toEqual([
      { type: 'GitHub Token', count: 2 },
      { type: 'JWT', count: 1 },
    ]);
  });
});
