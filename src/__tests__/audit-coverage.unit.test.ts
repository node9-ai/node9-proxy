// Tests for src/audit/coverage.ts — Phase 3b helper.
//
// Pure helper, so no os.homedir mocking. Seeds two temp files with crafted
// audit/hook-debug entries and asserts the report shape.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { computeAuditCoverage } from '../audit/coverage';

function writeLines(filePath: string, lines: string[]): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, lines.join('\n') + (lines.length > 0 ? '\n' : ''));
}

describe('computeAuditCoverage', () => {
  let tmpDir: string;
  let auditLogPath: string;
  let hookDebugLogPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-coverage-'));
    auditLogPath = path.join(tmpDir, 'audit.log');
    hookDebugLogPath = path.join(tmpDir, 'hook-debug.log');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('reports both files missing when neither exists', () => {
    const r = computeAuditCoverage(auditLogPath, hookDebugLogPath);
    expect(r.hasAuditFile).toBe(false);
    expect(r.hasDebugFile).toBe(false);
    expect(r.auditEntries).toBe(0);
    expect(r.hookDebugEntries).toBe(0);
    expect(r.sessionsWithDebugMissingAudit).toEqual([]);
  });

  it('counts entries and extracts session_ids from JSON lines', () => {
    writeLines(auditLogPath, [
      JSON.stringify({ ts: 't1', tool: 'Bash', decision: 'allow', sessionId: 'sess-A' }),
      JSON.stringify({ ts: 't2', tool: 'Read', decision: 'allow', sessionId: 'sess-A' }),
      JSON.stringify({ ts: 't3', tool: 'Bash', decision: 'deny', sessionId: 'sess-B' }),
    ]);
    writeLines(hookDebugLogPath, [JSON.stringify({ ts: 't1', tool: 'Bash', sessionId: 'sess-A' })]);

    const r = computeAuditCoverage(auditLogPath, hookDebugLogPath);
    expect(r.auditEntries).toBe(3);
    expect(r.hookDebugEntries).toBe(1);
    expect(r.sessionIdsWithAudit).toEqual(new Set(['sess-A', 'sess-B']));
    expect(r.sessionIdsWithDebug).toEqual(new Set(['sess-A']));
    expect(r.sessionsWithDebugMissingAudit).toEqual([]);
  });

  it('flags sessions present in hook-debug but absent from audit (potential gap)', () => {
    writeLines(auditLogPath, [
      JSON.stringify({ ts: 't1', tool: 'Bash', decision: 'allow', sessionId: 'sess-A' }),
    ]);
    writeLines(hookDebugLogPath, [
      JSON.stringify({ ts: 't2', tool: 'Bash', sessionId: 'sess-orphan' }),
      JSON.stringify({ ts: 't3', tool: 'Bash', sessionId: 'sess-A' }),
    ]);

    const r = computeAuditCoverage(auditLogPath, hookDebugLogPath);
    expect(r.sessionsWithDebugMissingAudit).toEqual(['sess-orphan']);
  });

  it('tolerates non-JSON hook-debug lines (text error format) without crashing', () => {
    writeLines(auditLogPath, [
      JSON.stringify({ ts: 't1', tool: 'Bash', decision: 'allow', sessionId: 'sess-A' }),
    ]);
    // hook-debug sometimes contains raw text like:
    //   "[2026-06-01T...] JSON_PARSE_ERROR: Unexpected token..."
    writeLines(hookDebugLogPath, [
      '[2026-06-01T12:00:00Z] JSON_PARSE_ERROR: garbage',
      '[2026-06-01T12:00:01Z] RAW: not-json-content',
      JSON.stringify({ ts: 't2', tool: 'Bash', sessionId: 'sess-B' }),
    ]);

    const r = computeAuditCoverage(auditLogPath, hookDebugLogPath);
    expect(r.hookDebugEntries).toBe(3); // counted, even if not parseable
    expect(r.sessionIdsWithDebug).toEqual(new Set(['sess-B'])); // only the JSON line contributes
    expect(r.sessionsWithDebugMissingAudit).toEqual(['sess-B']);
  });

  it('skips blank trailing lines in either file', () => {
    fs.writeFileSync(
      auditLogPath,
      JSON.stringify({ ts: 't1', tool: 'X', decision: 'allow', sessionId: 's' }) + '\n\n\n'
    );
    fs.writeFileSync(hookDebugLogPath, '\n\n');

    const r = computeAuditCoverage(auditLogPath, hookDebugLogPath);
    expect(r.auditEntries).toBe(1);
    expect(r.hookDebugEntries).toBe(0);
  });
});
