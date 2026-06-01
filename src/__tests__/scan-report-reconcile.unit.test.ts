// Phase 2a of the report-correctness verification roadmap
// (doc/roadmap/report-correctness-verification.md).
//
// Cross-source reconcile: scan reads agent session JSONL files;
// report reads ~/.node9/audit.log. For events where both sources see the
// same activity (the agent actually ran the tool, AND node9 was installed
// to write an audit row), the shared counter subset must agree.
//
// Legitimate divergence (e.g. pre-install JSONL with no audit, or a
// UserPromptSubmit-time DLP block that prevents the prompt from ever
// reaching JSONL) is documented in doc/capabilities-source-drift.md and
// is NOT asserted here — only the shared subset is.
//
// Isolation: vi.spyOn(os, 'homedir') + per-test tmp dir, identical to
// scan-golden-corpus.unit.test.ts. aggregateReportFromAudit also accepts
// explicit auditLogPath/claudeProjectsDir opts so we double-belt the path
// override.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanClaudeHistory } from '../cli/commands/scan';
import { aggregateReportFromAudit } from '../cli/aggregate/report-audit';

interface AuditLogLine {
  ts: string;
  tool: string;
  args?: Record<string, unknown>;
  decision: 'allow' | 'deny';
  checkedBy: string;
  agent?: string;
  sessionId?: string;
  hostname?: string;
}

function seedAuditLog(auditLogPath: string, entries: AuditLogLine[]): void {
  fs.mkdirSync(path.dirname(auditLogPath), { recursive: true });
  fs.writeFileSync(auditLogPath, entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
}

function seedJsonl(
  projectsDir: string,
  projDirName: string,
  sessionId: string,
  lines: string[]
): void {
  const dir = path.join(projectsDir, projDirName);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${sessionId}.jsonl`), lines.join('\n') + '\n');
}

describe('scan vs report reconcile — shared subset', () => {
  let tmpHome: string;
  let auditLogPath: string;
  let claudeProjectsDir: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-reconcile-'));
    auditLogPath = path.join(tmpHome, '.node9', 'audit.log');
    claudeProjectsDir = path.join(tmpHome, '.claude', 'projects');
    vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('single allowed Bash call appears in both sources with matching counts', () => {
    const sessionId = 'session-bash-allow';
    const ts = '2026-06-01T12:00:00.000Z';

    // JSONL: one assistant tool_use Bash call.
    seedJsonl(claudeProjectsDir, '-tmp-test', sessionId, [
      JSON.stringify({
        type: 'user',
        timestamp: '2026-06-01T11:59:59.000Z',
        message: { content: [{ type: 'text', text: 'list the dir' }] },
      }),
      JSON.stringify({
        type: 'assistant',
        timestamp: ts,
        message: {
          model: 'claude-sonnet-4-6',
          usage: {
            input_tokens: 10,
            output_tokens: 15,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
          },
          content: [
            { type: 'tool_use', id: 'toolu_01', name: 'Bash', input: { command: 'ls -la' } },
          ],
        },
      }),
    ]);

    // audit.log: one PreToolUse allow on the same Bash call.
    seedAuditLog(auditLogPath, [
      {
        ts,
        tool: 'Bash',
        args: { command: 'ls -la' },
        decision: 'allow',
        checkedBy: 'default-allow',
        agent: 'Claude Code',
        sessionId,
      },
    ]);

    const scan = scanClaudeHistory(null);
    const { data: report } = aggregateReportFromAudit('90d', {
      now: new Date('2026-06-02T00:00:00.000Z'),
      auditLogPath,
      claudeProjectsDir,
    });

    // Shared counter subset — both sources observed one Bash call.
    expect(scan.totalToolCalls).toBe(1);
    expect(scan.bashCalls).toBe(1);
    expect(report.total).toBe(1);
    expect(report.toolMap.get('Bash')?.calls).toBe(1);

    // Cross-source agreement (the actual reconcile assertion).
    expect(scan.totalToolCalls).toBe(report.total);
    expect(scan.bashCalls).toBe(report.toolMap.get('Bash')?.calls ?? 0);
  });

  it('zero events: both sources empty agree on zero', () => {
    // No JSONL files, no audit.log entries (file missing is fine).
    fs.mkdirSync(claudeProjectsDir, { recursive: true });

    const scan = scanClaudeHistory(null);
    const { data: report, hasAuditFile } = aggregateReportFromAudit('90d', {
      now: new Date('2026-06-02T00:00:00.000Z'),
      auditLogPath,
      claudeProjectsDir,
    });

    expect(scan.totalToolCalls).toBe(0);
    expect(scan.bashCalls).toBe(0);
    expect(scan.dlpFindings.length).toBe(0);
    expect(report.total).toBe(0);
    expect(report.dlpBlocked).toBe(0);
    expect(hasAuditFile).toBe(false);
  });
});
