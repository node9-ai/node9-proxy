/**
 * Unit tests for aggregateReportFromAudit — the period-aware audit
 * aggregator extracted from `node9 report` so the dashboard's Report [2]
 * view can call it directly.
 *
 * Coverage focuses on the contracts the dashboard depends on:
 *   - missing audit log → hasAuditFile: false, zeroed envelope
 *   - period boundaries (entries outside window dropped)
 *   - PostToolUse / response-dlp entries excluded from main bucketing
 *   - response-dlp entries surfaced separately (period-filtered) plus the
 *     lifetime count on data.unackedDlp
 *   - excludeTests filters npm/vitest commands
 *   - agentMap, toolMap, blockMap, dailyMap, hourMap populated correctly
 *   - prior-period block rate computed when there's a prior window
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { aggregateReportFromAudit } from '../cli/aggregate/report-audit';

const NOW = new Date('2026-05-10T15:00:00Z');

interface AuditLine {
  ts: string;
  tool: string;
  decision: string;
  source?: string;
  checkedBy?: string;
  agent?: string;
  mcpServer?: string;
  args?: Record<string, unknown>;
  testRun?: boolean;
  testResult?: 'pass' | 'fail';
  dlpPattern?: string;
  dlpSample?: string;
}

let tmpDir: string;
let auditLogPath: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-report-audit-'));
  auditLogPath = path.join(tmpDir, 'audit.log');
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeLog(lines: AuditLine[]): void {
  fs.writeFileSync(auditLogPath, lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
}

function makeOpts(extra: Record<string, unknown> = {}) {
  return {
    now: NOW,
    auditLogPath,
    claudeProjectsDir: '/nonexistent',
    codexSessionsDir: '/nonexistent',
    ...extra,
  };
}

describe('aggregateReportFromAudit', () => {
  it('returns hasAuditFile=false and zeroed envelope when log is missing', () => {
    const result = aggregateReportFromAudit('7d', makeOpts());
    expect(result.hasAuditFile).toBe(false);
    expect(result.data.total).toBe(0);
    expect(result.data.unackedDlp).toBe(0);
    expect(result.data.toolMap.size).toBe(0);
    expect(result.responseDlpEntries).toEqual([]);
  });

  it('returns hasAuditFile=true with empty buckets when log exists but is empty', () => {
    fs.writeFileSync(auditLogPath, '');
    const result = aggregateReportFromAudit('7d', makeOpts());
    expect(result.hasAuditFile).toBe(true);
    expect(result.data.total).toBe(0);
  });

  it('counts only PreToolUse entries inside the period', () => {
    writeLog([
      // In-window PreToolUse — counted
      {
        ts: '2026-05-10T10:00:00Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'local-policy',
        agent: 'claude',
      },
      // In-window PostToolUse — skipped (post-hook duplicate)
      {
        ts: '2026-05-10T10:00:01Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'post-hook',
        agent: 'claude',
      },
      // Out-of-window — skipped
      {
        ts: '2026-04-01T10:00:00Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'local-policy',
        agent: 'claude',
      },
    ]);
    const result = aggregateReportFromAudit('7d', makeOpts());
    expect(result.data.total).toBe(1);
    expect(result.data.toolMap.get('Bash')?.calls).toBe(1);
  });

  it('separates user-interactive (daemon) from auto blocks', () => {
    writeLog([
      // User interactive: source='daemon'
      { ts: '2026-05-10T10:00:00Z', tool: 'Bash', decision: 'allow', source: 'daemon' },
      { ts: '2026-05-10T10:00:01Z', tool: 'Bash', decision: 'block', source: 'daemon' },
      // Auto-blocked
      {
        ts: '2026-05-10T10:00:02Z',
        tool: 'Bash',
        decision: 'block',
        source: 'local-policy',
        checkedBy: 'smart-rule-block',
      },
      // Timeout
      {
        ts: '2026-05-10T10:00:03Z',
        tool: 'Bash',
        decision: 'block',
        source: 'local-policy',
        checkedBy: 'timeout',
      },
      // DLP
      {
        ts: '2026-05-10T10:00:04Z',
        tool: 'Bash',
        decision: 'block',
        source: 'local-policy',
        checkedBy: 'dlp-block',
      },
      // DLP observe
      {
        ts: '2026-05-10T10:00:05Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'local-policy',
        checkedBy: 'observe-mode-dlp-would-block',
      },
      // Loop
      {
        ts: '2026-05-10T10:00:06Z',
        tool: 'Bash',
        decision: 'block',
        source: 'local-policy',
        checkedBy: 'loop-detected',
      },
    ]);
    const result = aggregateReportFromAudit('7d', makeOpts());
    expect(result.data.userApproved).toBe(1);
    expect(result.data.userDenied).toBe(1);
    expect(result.data.timedOut).toBe(1);
    expect(result.data.hardBlocked).toBe(1);
    expect(result.data.dlpBlocked).toBe(1);
    expect(result.data.observeDlp).toBe(0); // observeDlp is for blocked observe-mode entries; allow path ≠ block path
    expect(result.data.loopHits).toBe(1);
  });

  it('lists response-dlp entries separately and exposes lifetime count on unackedDlp', () => {
    writeLog([
      // In-window response-dlp
      {
        ts: '2026-05-10T09:00:00Z',
        tool: 'Bash',
        decision: 'observe',
        source: 'response-dlp',
        dlpPattern: 'GitHub Token',
        dlpSample: 'ghp_...',
      },
      // Out-of-window response-dlp (still counts toward lifetime unackedDlp)
      {
        ts: '2025-01-01T09:00:00Z',
        tool: 'Bash',
        decision: 'observe',
        source: 'response-dlp',
        dlpPattern: 'JWT',
        dlpSample: 'eyJ...',
      },
      // Normal in-window entry
      { ts: '2026-05-10T10:00:00Z', tool: 'Bash', decision: 'allow', source: 'local-policy' },
    ]);
    const result = aggregateReportFromAudit('7d', makeOpts());
    expect(result.data.unackedDlp).toBe(2); // lifetime (both response-dlp entries)
    expect(result.responseDlpEntries).toHaveLength(1); // period-filtered
    expect(result.responseDlpEntries[0].dlpPattern).toBe('GitHub Token');
    expect(result.responseDlpEntries[0].dlpSample).toBe('ghp_...');
    // response-dlp must NOT be counted in main aggregates
    expect(result.data.total).toBe(1);
  });

  it('excludes test-runner entries when excludeTests=true', () => {
    writeLog([
      {
        ts: '2026-05-10T10:00:00Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'local-policy',
        args: { command: 'npm test' },
      },
      {
        ts: '2026-05-10T10:01:00Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'local-policy',
        args: { command: 'ls' },
      },
      // Tagged at write time — applies to any tool
      {
        ts: '2026-05-10T10:02:00Z',
        tool: 'Edit',
        decision: 'allow',
        source: 'local-policy',
        testRun: true,
        args: { file_path: '/x' },
      },
    ]);
    const allIn = aggregateReportFromAudit('7d', makeOpts({ excludeTests: false }));
    expect(allIn.data.total).toBe(3);
    expect(allIn.data.excludedTests).toBe(0);

    const filtered = aggregateReportFromAudit('7d', makeOpts({ excludeTests: true }));
    expect(filtered.data.total).toBe(1); // only 'ls'
    expect(filtered.data.excludedTests).toBe(2);
  });

  it('aggregates by tool, agent, mcp, day, hour', () => {
    writeLog([
      {
        ts: '2026-05-10T10:00:00Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'local-policy',
        agent: 'claude',
      },
      {
        ts: '2026-05-10T11:00:00Z',
        tool: 'Bash',
        decision: 'block',
        source: 'daemon',
        agent: 'claude',
      },
      {
        ts: '2026-05-09T14:00:00Z',
        tool: 'Edit',
        decision: 'allow',
        source: 'local-policy',
        agent: 'gemini',
      },
      {
        ts: '2026-05-09T14:30:00Z',
        tool: 'Read',
        decision: 'allow',
        source: 'local-policy',
        agent: 'gemini',
        mcpServer: 'fs-mcp',
      },
    ]);
    const result = aggregateReportFromAudit('7d', makeOpts());
    expect(result.data.toolMap.get('Bash')).toEqual({ calls: 2, blocked: 1 });
    expect(result.data.toolMap.get('Edit')?.calls).toBe(1);
    expect(result.data.agentMap.get('claude')).toBe(2);
    expect(result.data.agentMap.get('gemini')).toBe(2);
    expect(result.data.mcpMap.get('fs-mcp')).toBe(1);
    expect(result.data.dailyMap.get('2026-05-10')).toEqual({ calls: 2, blocked: 1 });
    expect(result.data.dailyMap.get('2026-05-09')).toEqual({ calls: 2, blocked: 0 });
    // Hours are local — just verify the keys are 0..23 ints
    for (const h of result.data.hourMap.keys()) {
      expect(h).toBeGreaterThanOrEqual(0);
      expect(h).toBeLessThanOrEqual(23);
    }
  });

  it('computes prior-period block rate from the immediately-preceding window', () => {
    // 7d window for NOW=May 10 → May 4..May 10. Prior = Apr 27..May 3.
    writeLog([
      // Prior window: 2 entries, 1 blocked → rate 0.5
      { ts: '2026-04-30T10:00:00Z', tool: 'Bash', decision: 'allow', source: 'local-policy' },
      {
        ts: '2026-05-01T10:00:00Z',
        tool: 'Bash',
        decision: 'block',
        source: 'local-policy',
        checkedBy: 'smart-rule-block',
      },
      // Current window
      { ts: '2026-05-10T10:00:00Z', tool: 'Bash', decision: 'allow', source: 'local-policy' },
    ]);
    const result = aggregateReportFromAudit('7d', makeOpts());
    expect(result.data.priorBlockRate).toBeCloseTo(0.5, 2);
  });

  it('returns priorBlockRate=null when no prior data exists', () => {
    writeLog([
      { ts: '2026-05-10T10:00:00Z', tool: 'Bash', decision: 'allow', source: 'local-policy' },
    ]);
    const result = aggregateReportFromAudit('7d', makeOpts());
    expect(result.data.priorBlockRate).toBeNull();
  });

  it('honors today/30d/month period boundaries', () => {
    writeLog([
      { ts: '2026-05-10T10:00:00Z', tool: 'Bash', decision: 'allow', source: 'local-policy' },
      { ts: '2026-05-09T10:00:00Z', tool: 'Bash', decision: 'allow', source: 'local-policy' },
      { ts: '2026-04-15T10:00:00Z', tool: 'Bash', decision: 'allow', source: 'local-policy' },
      { ts: '2026-04-01T10:00:00Z', tool: 'Bash', decision: 'allow', source: 'local-policy' },
    ]);
    expect(aggregateReportFromAudit('today', makeOpts()).data.total).toBe(1);
    expect(aggregateReportFromAudit('7d', makeOpts()).data.total).toBe(2);
    expect(aggregateReportFromAudit('30d', makeOpts()).data.total).toBe(3);
    // 'month' = May 1 onwards (NOW is in May)
    expect(aggregateReportFromAudit('month', makeOpts()).data.total).toBe(2);
  });

  it('counts test results in testPasses / testFails', () => {
    writeLog([
      {
        ts: '2026-05-10T10:00:00Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'test-result',
        testResult: 'pass',
      },
      {
        ts: '2026-05-10T10:01:00Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'test-result',
        testResult: 'pass',
      },
      {
        ts: '2026-05-10T10:02:00Z',
        tool: 'Bash',
        decision: 'allow',
        source: 'test-result',
        testResult: 'fail',
      },
    ]);
    const result = aggregateReportFromAudit('7d', makeOpts());
    expect(result.data.testPasses).toBe(2);
    expect(result.data.testFails).toBe(1);
  });
});
