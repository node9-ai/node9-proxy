import { describe, it, expect } from 'vitest';
import { summarizeScan, computeScanScore, type ScanFinding } from './index';

const f = (
  type: ScanFinding['type'],
  patternName?: string,
  sessionId = 's1',
  lineIndex = 0
): ScanFinding => ({ type, patternName, sessionId, lineIndex });

describe('summarizeScan', () => {
  it('returns a clean summary for an empty findings list', () => {
    const s = summarizeScan([]);
    expect(s.totalSessions).toBe(0);
    expect(s.totalToolCalls).toBe(0);
    expect(s.score).toBe(100);
    expect(s.topPatterns).toEqual([]);
    // Every signal is zero
    for (const v of Object.values(s.signals)) expect(v).toBe(0);
  });

  it('counts findings by type into the correct signals key', () => {
    const s = summarizeScan([
      f('dlp', 'GitHub Token'),
      f('dlp', 'AWS Access Key'),
      f('pii', 'Email'),
      f('loop'),
      f('loop'),
      f('loop'),
    ]);
    expect(s.signals.dlpFindings).toBe(2);
    expect(s.signals.piiFindings).toBe(1);
    expect(s.signals.loops).toBe(3);
    // Untouched signals stay zero
    expect(s.signals.sensitiveFileReads).toBe(0);
  });

  it('counts distinct sessionIds for totalSessions', () => {
    const s = summarizeScan([
      f('dlp', 'GitHub Token', 'sessA'),
      f('dlp', 'GitHub Token', 'sessA'),
      f('dlp', 'AWS Access Key', 'sessB'),
    ]);
    expect(s.totalSessions).toBe(2);
  });

  it('passes totalToolCalls through verbatim', () => {
    const s = summarizeScan([], { totalToolCalls: 47 });
    expect(s.totalToolCalls).toBe(47);
  });

  it('sorts topPatterns by count desc, alphabetical tie-break', () => {
    const s = summarizeScan([
      f('dlp', 'AWS Access Key'),
      f('dlp', 'AWS Access Key'),
      f('dlp', 'GitHub Token'),
      f('dlp', 'GitHub Token'),
      f('dlp', 'GitHub Token'),
      f('pii', 'Email'),
    ]);
    expect(s.topPatterns).toEqual([
      { patternName: 'GitHub Token', count: 3 },
      { patternName: 'AWS Access Key', count: 2 },
      { patternName: 'Email', count: 1 },
    ]);
  });

  it('caps topPatterns at topN (default 10)', () => {
    const findings: ScanFinding[] = Array.from({ length: 25 }, (_, i) => f('dlp', `pattern-${i}`));
    expect(summarizeScan(findings).topPatterns.length).toBe(10);
  });

  it('respects a custom topN', () => {
    const findings: ScanFinding[] = Array.from({ length: 20 }, (_, i) => f('dlp', `pattern-${i}`));
    expect(summarizeScan(findings, { topN: 3 }).topPatterns.length).toBe(3);
  });

  it('drops findings with no patternName from topPatterns but still counts the signal', () => {
    // Loops have no patternName but should still increment signals.loops
    const s = summarizeScan([f('loop'), f('loop'), f('dlp', 'AWS Access Key')]);
    expect(s.signals.loops).toBe(2);
    expect(s.topPatterns).toEqual([{ patternName: 'AWS Access Key', count: 1 }]);
  });

  it('produces deterministic output for identical input (cache safety)', () => {
    const findings = [f('dlp', 'GitHub Token'), f('pii', 'Email'), f('loop')];
    expect(summarizeScan(findings)).toEqual(summarizeScan(findings));
  });

  // ── PRIVACY CONTRACT ─────────────────────────────────────────────
  // The summary is sent over the wire and persisted on the SaaS side.
  // It must NEVER carry raw prompt content, tool args, or file paths.
  // The only strings allowed are: pattern names ("GitHub Token") and
  // signal-key names ("dlpFindings"). These tests pin that contract
  // so any future change that smuggles in raw text breaks loud.

  it('PRIVACY: summary contains no fields named like prompt/args/path/text/value', () => {
    const findings = [f('dlp', 'GitHub Token'), f('pii', 'Email'), f('sensitive-file-read')];
    const s = summarizeScan(findings);
    const json = JSON.stringify(s);
    // Even though our types don't allow these, defensively assert the
    // serialised form doesn't smuggle them back in via accidental
    // additions later.
    expect(json).not.toMatch(/"prompt"\s*:/i);
    expect(json).not.toMatch(/"args"\s*:/i);
    expect(json).not.toMatch(/"filePath"\s*:/i);
    expect(json).not.toMatch(/"command"\s*:/i);
    expect(json).not.toMatch(/"value"\s*:/i);
    expect(json).not.toMatch(/"text"\s*:/i);
  });

  it('PRIVACY: sessionId is NOT in the summary (sessions group findings, but ids stay local)', () => {
    // Even sessionId could leak workspace structure if we sent it up.
    // The summary aggregates to counts only.
    const findings = [f('dlp', 'GitHub Token', 'project-payments-prod-conv-12345')];
    const s = summarizeScan(findings);
    expect(JSON.stringify(s)).not.toContain('project-payments-prod-conv-12345');
  });
});

describe('computeScanScore', () => {
  it('returns 100 for a clean session (no findings)', () => {
    expect(
      computeScanScore({
        dlpFindings: 0,
        piiFindings: 0,
        sensitiveFileReads: 0,
        privilegeEscalation: 0,
        networkExfil: 0,
        pipeToShell: 0,
        evalOfRemote: 0,
        destructiveOps: 0,
        loops: 0,
        longOutputRedactions: 0,
      })
    ).toBe(100);
  });

  it('one credential leak drops the score below 80 (at-risk territory)', () => {
    const score = computeScanScore({
      dlpFindings: 1,
      piiFindings: 0,
      sensitiveFileReads: 0,
      privilegeEscalation: 0,
      networkExfil: 0,
      pipeToShell: 0,
      evalOfRemote: 0,
      destructiveOps: 0,
      loops: 0,
      longOutputRedactions: 0,
    });
    // Pinning the deduction value to 30 protects against accidental
    // weight changes that would reframe the dashboard's tier boundaries.
    expect(score).toBe(70);
  });

  it('clamps the score to 0 even with lots of high-severity findings', () => {
    const score = computeScanScore({
      dlpFindings: 100,
      piiFindings: 100,
      sensitiveFileReads: 100,
      privilegeEscalation: 100,
      networkExfil: 100,
      pipeToShell: 100,
      evalOfRemote: 100,
      destructiveOps: 100,
      loops: 100,
      longOutputRedactions: 100,
    });
    expect(score).toBe(0);
  });

  it('many loops add up (3 each, no cap per signal — caller must rate-limit)', () => {
    const score = computeScanScore({
      dlpFindings: 0,
      piiFindings: 0,
      sensitiveFileReads: 0,
      privilegeEscalation: 0,
      networkExfil: 0,
      pipeToShell: 0,
      evalOfRemote: 0,
      destructiveOps: 0,
      loops: 10,
      longOutputRedactions: 0,
    });
    expect(score).toBe(70); // 100 - 10 * 3
  });
});
