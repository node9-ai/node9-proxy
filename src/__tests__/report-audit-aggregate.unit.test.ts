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
import { aggregateReportFromAudit, getDateRange } from '../cli/aggregate/report-audit';

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
  argsHash?: string;
  sessionId?: string;
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
    geminiTmpDir: '/nonexistent',
    ...extra,
  };
}

describe('getDateRange', () => {
  // Anchor "now" to a fixed moment so date math is deterministic.
  const now = new Date('2026-05-10T15:00:00Z');

  it('handles today: today-start to today-end', () => {
    const { start, end } = getDateRange('today', now);
    expect(start.getDate()).toBe(10);
    expect(start.getHours()).toBe(0);
    expect(end.getDate()).toBe(10);
    expect(end.getHours()).toBe(23);
  });

  it('handles 7d: rolling 7 days (today minus 6)', () => {
    const { start } = getDateRange('7d', now);
    expect(start.getDate()).toBe(4);
  });

  it('handles 30d: rolling 30 days (today minus 29)', () => {
    const { start } = getDateRange('30d', now);
    expect(start.getDate()).toBe(11); // April 11
    expect(start.getMonth()).toBe(3); // April (0-indexed)
  });

  it('handles 90d: rolling 90 days (today minus 89) — new [Q]uarter period', () => {
    const { start, end } = getDateRange('90d', now);
    // 2026-05-10 minus 89 days = 2026-02-10
    expect(start.getDate()).toBe(10);
    expect(start.getMonth()).toBe(1); // February
    expect(start.getFullYear()).toBe(2026);
    // End is still today
    expect(end.getDate()).toBe(10);
    expect(end.getMonth()).toBe(4); // May
  });

  it('handles month: first day of current month to end of today', () => {
    const { start } = getDateRange('month', now);
    expect(start.getDate()).toBe(1);
    expect(start.getMonth()).toBe(4); // May
  });
});

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

  describe('Gemini cost walker', () => {
    /** Build a fake ~/.gemini/tmp/<proj>/chats/session-x.jsonl tree. */
    function writeGeminiSession(
      proj: string,
      sessionName: string,
      turns: Array<Record<string, unknown>>
    ): string {
      const chatsDir = path.join(tmpDir, 'gemini-tmp', proj, 'chats');
      fs.mkdirSync(chatsDir, { recursive: true });
      const file = path.join(chatsDir, sessionName);
      fs.writeFileSync(file, turns.map((t) => JSON.stringify(t)).join('\n') + '\n');
      return path.join(tmpDir, 'gemini-tmp');
    }

    it('walks gemini session jsonl, dedupes by id, prices via litellm', () => {
      fs.writeFileSync(auditLogPath, '');
      // Two distinct turns, each written twice (Gemini flushes partial+final).
      // gemini-2.5-flash is in LiteLLM at $0.30 / $2.50 per Mtok with
      // a cache-read rate.
      const geminiDir = writeGeminiSession('node9', 'session-2026-05-10T10-00.jsonl', [
        { id: 'turn-1', timestamp: '2026-05-10T10:00:00Z', type: 'user', content: 'hi' },
        {
          id: 'turn-1-a',
          timestamp: '2026-05-10T10:00:01Z',
          type: 'gemini',
          tokens: { input: 1000, output: 500, cached: 0 },
          model: 'gemini-2.5-flash',
        },
        {
          id: 'turn-1-a',
          timestamp: '2026-05-10T10:00:01Z',
          type: 'gemini',
          tokens: { input: 1000, output: 500, cached: 0 },
          model: 'gemini-2.5-flash',
        },
        {
          id: 'turn-2-a',
          timestamp: '2026-05-10T10:00:05Z',
          type: 'gemini',
          tokens: { input: 2000, output: 100, cached: 1500 },
          model: 'gemini-2.5-flash',
        },
        {
          id: 'turn-2-a',
          timestamp: '2026-05-10T10:00:05Z',
          type: 'gemini',
          tokens: { input: 2000, output: 100, cached: 1500 },
          model: 'gemini-2.5-flash',
        },
      ]);
      const result = aggregateReportFromAudit(
        '7d',
        makeOpts({ geminiTmpDir: geminiDir, claudeProjectsDir: '/nonexistent' })
      );
      // After dedup we count 2 turns: 1000+2000 input, 500+100 output, 1500 cached.
      expect(result.data.cost.geminiUSD).toBeGreaterThan(0);
      expect(result.data.cost.inputTokens).toBe(3000);
      expect(result.data.cost.outputTokens).toBe(600);
      expect(result.data.cost.cacheReadTokens).toBe(1500);
      // Per-project entry uses the gemini dir name (no other agent
      // contributed, so the bare basename stands).
      expect(result.data.cost.byProject.size).toBe(1);
      expect([...result.data.cost.byProject.keys()][0]).toBe('node9');
    });

    it('falls back to gemini-2.5-flash pricing for unknown preview variants', () => {
      fs.writeFileSync(auditLogPath, '');
      const geminiDir = writeGeminiSession('node9', 'session.jsonl', [
        {
          id: 'turn-1',
          timestamp: '2026-05-10T10:00:00Z',
          type: 'gemini',
          tokens: { input: 1000, output: 500, cached: 0 },
          model: 'gemini-3-flash-preview',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts({ geminiTmpDir: geminiDir }));
      // Cost should be > 0 (proxy pricing applied), not 0 (unpriced skip).
      expect(result.data.cost.geminiUSD).toBeGreaterThan(0);
    });

    it('skips entries outside the period window', () => {
      fs.writeFileSync(auditLogPath, '');
      const geminiDir = writeGeminiSession('node9', 'session.jsonl', [
        // Inside 7d window (NOW = 2026-05-10)
        {
          id: 'in',
          timestamp: '2026-05-09T10:00:00Z',
          type: 'gemini',
          tokens: { input: 1000, output: 100, cached: 0 },
          model: 'gemini-2.5-flash',
        },
        // Outside 7d window (older than 7 days)
        {
          id: 'out',
          timestamp: '2026-04-01T10:00:00Z',
          type: 'gemini',
          tokens: { input: 9999, output: 9999, cached: 0 },
          model: 'gemini-2.5-flash',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts({ geminiTmpDir: geminiDir }));
      // Only the in-window turn counts.
      expect(result.data.cost.inputTokens).toBe(1000);
      expect(result.data.cost.outputTokens).toBe(100);
    });
  });

  // ── Smart-rule override deduplication ────────────────────────────────────
  // The orchestrator writes 3 rows for one approved override flow:
  //   1. `deny / smart-rule-block-override` (intermediate, hashed shape)
  //   2. `allow source=daemon`  (user's incoming request via daemon channel)
  //   3. `allow checkedBy=daemon` (daemon's decision record, hashed shape)
  // Rows 1 & 3 share argsHash + sessionId; the dedupe pre-pass uses that
  // pair to skip row 1 in counting. Row 2 remains the canonical "approved"
  // counter (existing user-interactive branch). Fixtures here mirror the
  // real audit-log shape.
  describe('smart-rule-block-override dedupe', () => {
    it('skips an intermediate deny when a matching daemon allow exists', () => {
      writeLog([
        // (1) Intermediate: smart rule fires
        {
          ts: '2026-05-08T12:00:00Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'smart-rule-block-override',
          argsHash: 'abc123',
          sessionId: 'sess-1',
        },
        // (2) User clicks Allow via daemon channel (incoming-request row)
        {
          ts: '2026-05-08T12:00:05Z',
          tool: 'Bash',
          decision: 'allow',
          source: 'daemon',
        },
        // (3) Daemon's decision record — hashed, pairs with (1)
        {
          ts: '2026-05-08T12:00:05.1Z',
          tool: 'Bash',
          decision: 'allow',
          checkedBy: 'daemon',
          argsHash: 'abc123',
          sessionId: 'sess-1',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts());
      // Row 1 is skipped (superseded). Row 2 → userApproved.
      // Row 3 → no counter (not source=daemon, decision is allow).
      expect(result.data.userApproved).toBe(1);
      expect(result.data.hardBlocked).toBe(0);
      // Headline event count: 3 rows in entries, 1 skipped → 2.
      expect(result.data.total).toBe(2);
    });

    it('keeps a solo deny (no matching daemon resolution) as a hard block', () => {
      writeLog([
        {
          ts: '2026-05-08T12:00:00Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'smart-rule-block-override',
          argsHash: 'abc123',
          sessionId: 'sess-1',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts());
      expect(result.data.hardBlocked).toBe(1);
      expect(result.data.userApproved).toBe(0);
      expect(result.data.total).toBe(1);
    });

    it('does not dedupe across sessions even with matching argsHash', () => {
      writeLog([
        // session 1: deny with no resolution → true block
        {
          ts: '2026-05-08T12:00:00Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'smart-rule-block-override',
          argsHash: 'abc123',
          sessionId: 'sess-1',
        },
        // session 2: daemon allow, same command coincidentally
        {
          ts: '2026-05-08T12:00:05Z',
          tool: 'Bash',
          decision: 'allow',
          checkedBy: 'daemon',
          argsHash: 'abc123',
          sessionId: 'sess-2',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts());
      expect(result.data.hardBlocked).toBe(1);
      // The sess-2 daemon allow has decision=allow but no source=daemon,
      // so it doesn't bump userApproved — it's just an uncounted record.
      expect(result.data.userApproved).toBe(0);
    });

    it('does not dedupe outside the 60s window', () => {
      writeLog([
        {
          ts: '2026-05-08T12:00:00Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'smart-rule-block-override',
          argsHash: 'abc123',
          sessionId: 'sess-1',
        },
        // 90s later — beyond the pair window
        {
          ts: '2026-05-08T12:01:30Z',
          tool: 'Bash',
          decision: 'allow',
          checkedBy: 'daemon',
          argsHash: 'abc123',
          sessionId: 'sess-1',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts());
      expect(result.data.hardBlocked).toBe(1);
    });

    it('skips rows missing argsHash or sessionId (older logs, no pairing possible)', () => {
      writeLog([
        // Old-style row with no argsHash/sessionId — counts as a normal block
        {
          ts: '2026-05-08T12:00:00Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'smart-rule-block-override',
        },
        {
          ts: '2026-05-08T12:00:05Z',
          tool: 'Bash',
          decision: 'allow',
          source: 'daemon',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts());
      expect(result.data.hardBlocked).toBe(1);
      expect(result.data.userApproved).toBe(1);
    });

    it('does not pair when tool names differ (defensive against hash collision)', () => {
      writeLog([
        {
          ts: '2026-05-08T12:00:00Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'smart-rule-block-override',
          argsHash: 'abc123',
          sessionId: 'sess-1',
        },
        // Different tool, same hash — wouldn't happen in practice but
        // the matching must be tool-scoped anyway.
        {
          ts: '2026-05-08T12:00:05Z',
          tool: 'Read',
          decision: 'allow',
          checkedBy: 'daemon',
          argsHash: 'abc123',
          sessionId: 'sess-1',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts());
      expect(result.data.hardBlocked).toBe(1);
    });
  });

  // ── local-decision re-bucketing ─────────────────────────────────────────
  // `checkedBy: 'local-decision'` deny rows record a user clicking Block
  // on a native OS popup. Same user intent as a SaaS-approver deny
  // (source=daemon, deny), just a different channel. They were previously
  // lumped into hardBlocked which made the "Auto-blocked" tile misleading.
  describe('local-decision re-bucketing', () => {
    it('counts local-decision denies as userDenied, not hardBlocked', () => {
      writeLog([
        {
          ts: '2026-05-08T12:00:00Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'local-decision',
        },
        {
          ts: '2026-05-08T12:00:01Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'local-decision',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts());
      expect(result.data.userDenied).toBe(2);
      expect(result.data.hardBlocked).toBe(0);
    });

    it('combines SaaS-approver and native-popup denials in userDenied', () => {
      writeLog([
        // SaaS approver deny
        {
          ts: '2026-05-08T12:00:00Z',
          tool: 'Bash',
          decision: 'deny',
          source: 'daemon',
        },
        // Native popup deny
        {
          ts: '2026-05-08T12:00:01Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'local-decision',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts());
      expect(result.data.userDenied).toBe(2);
      expect(result.data.hardBlocked).toBe(0);
    });

    it('keeps smart-rule-block (no override) in hardBlocked', () => {
      // Sanity: only `local-decision` moves. Other non-daemon denies
      // (smart-rule-block without resolution, persistent-deny, etc.)
      // still land in hardBlocked.
      writeLog([
        {
          ts: '2026-05-08T12:00:00Z',
          tool: 'Bash',
          decision: 'deny',
          checkedBy: 'smart-rule-block',
        },
      ]);
      const result = aggregateReportFromAudit('7d', makeOpts());
      expect(result.data.hardBlocked).toBe(1);
      expect(result.data.userDenied).toBe(0);
    });
  });
});
