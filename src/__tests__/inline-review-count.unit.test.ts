// src/__tests__/inline-review-count.unit.test.ts
// /code-review round-2 fix: an inline-approved tool call writes TWO rows into
// audit.log — the PostToolUse execution record (source:'inline-review-approved',
// no eid) and the shippable decision row (checkedBy:'inline-review'). Every
// local counter must count that call ONCE: readers share NON_DECISION_SOURCES
// (audit/decision.ts) instead of four hand-copied 'post-hook' filters.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { aggregateReportFromAudit } from '../cli/aggregate/report-audit';
import { NON_DECISION_SOURCES } from '../audit/decision';

describe('inline-approved call counts once in node9 report', () => {
  let tmpHome: string;
  let auditLogPath: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-inlinecount-'));
    auditLogPath = path.join(tmpHome, '.node9', 'audit.log');
    vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('the execution record + the decision row = ONE counted action', () => {
    const ts = '2026-06-01T12:00:00.000Z';
    fs.mkdirSync(path.dirname(auditLogPath), { recursive: true });
    // Exactly what log.ts writes for one inline-approved `git push`:
    const rows = [
      // 1. shippable decision row (has eid, checkedBy 'inline-review', no source)
      {
        eid: 'ms0-testeid12345',
        ts,
        tool: 'Bash',
        argsHash: 'abc',
        decision: 'allow',
        checkedBy: 'inline-review',
        ruleName: 'Smart Rule: review-git-push',
        agent: 'Claude Code',
        sessionId: 's1',
      },
      // 2. the raw PostToolUse execution record (eid-less, source-tagged)
      {
        ts,
        tool: 'Bash',
        args: { command: 'git push origin main' },
        decision: 'allowed',
        source: 'inline-review-approved',
        agent: 'Claude Code',
        sessionId: 's1',
      },
    ];
    fs.writeFileSync(auditLogPath, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');

    const { data: report } = aggregateReportFromAudit('90d', {
      now: new Date('2026-06-02T00:00:00.000Z'),
      auditLogPath,
    });
    expect(report.total).toBe(1);
    expect(report.toolMap.get('Bash')?.calls).toBe(1);
  });

  it('NON_DECISION_SOURCES covers all three execution/finding source values', () => {
    expect(NON_DECISION_SOURCES.has('post-hook')).toBe(true);
    expect(NON_DECISION_SOURCES.has('inline-review-approved')).toBe(true);
    expect(NON_DECISION_SOURCES.has('response-dlp')).toBe(true);
  });
});
