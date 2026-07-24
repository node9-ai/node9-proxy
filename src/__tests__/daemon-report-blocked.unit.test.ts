/**
 * Regression — GET /report contradicted itself.
 *
 * `summary.blocked` was converged onto `classifyDecision`, but
 * `topBlockedTools` and `byAgent.blocked` kept their own
 * `!decision.startsWith('allow')` rule twelve lines below, reading the SAME
 * `entries` array. On a real 101k-row log that made one response disagree with
 * itself by 950 rows: 11,646 vs 12,596.
 *
 * The invariant these tests protect is not a number, it is an agreement:
 * every blocked count in the body comes from one rule.
 */
import { describe, it, expect } from 'vitest';
import { buildDaemonReport } from '../daemon/server';

const NOW = new Date('2026-05-10T15:00:00Z');
const TS = '2026-05-10T10:00:00Z';

/** Shapes taken from a real audit log, not invented. */
const ROWS: Array<Record<string, unknown>> = [
  { ts: TS, tool: 'Bash', decision: 'allow', checkedBy: 'local-policy', agent: 'Claude Code' },
  // Real refusals — the only rows any blocked count should include.
  { ts: TS, tool: 'Bash', decision: 'deny', checkedBy: 'smart-rule-block', agent: 'Claude Code' },
  { ts: TS, tool: 'Bash', decision: 'deny', checkedBy: 'timeout', agent: 'Claude Code' },
  // Shadow mode: flagged, but the action RAN. Not a refusal.
  {
    ts: TS,
    tool: 'Bash',
    decision: 'deny',
    checkedBy: 'observe-mode-dlp-would-block',
    agent: 'Claude Code',
  },
  {
    ts: TS,
    tool: 'Bash',
    decision: 'allow',
    checkedBy: 'observe-mode-would-block',
    agent: 'Claude Code',
  },
  // A finding and a discovery event — not verdicts at all.
  {
    ts: TS,
    tool: 'mcp__redis__redis_get',
    decision: 'mcp-discovered',
    source: 'daemon',
    agent: 'Claude Code',
  },
];

describe('buildDaemonReport — one rule for every blocked count', () => {
  it('summary.blocked, topBlockedTools and byAgent.blocked agree', () => {
    const body = buildDaemonReport(ROWS, '7d', NOW);

    const fromTop = body.topBlockedTools.reduce((n, t) => n + t.value, 0);
    const fromAgents = body.byAgent.reduce((n, a) => n + a.blocked, 0);
    const fromDaily = body.daily.reduce((n, d) => n + d.blocked, 0);

    // The agreement IS the invariant — assert it before the value.
    expect(fromTop).toBe(body.summary.blocked);
    expect(fromAgents).toBe(body.summary.blocked);
    expect(fromDaily).toBe(body.summary.blocked);

    // And the value: only the two genuine refusals.
    expect(body.summary.blocked).toBe(2);
  });

  it('does not count shadow-mode rows or findings as blocks', () => {
    const body = buildDaemonReport(ROWS, '7d', NOW);
    // 6 rows in, 2 refused. The old rule scored 4 (both observe rows minus the
    // allow-flavoured one, plus the discovery event).
    expect(body.summary.total).toBe(6);
    expect(body.summary.blocked).toBe(2);
    expect(body.byAgent.find((a) => a.agent === 'Claude Code')?.blocked).toBe(2);
    expect(body.topBlockedTools.find((t) => t.name === 'mcp__redis__redis_get')).toBeUndefined();
  });

  it('holds for the today/hourly bucketing path too', () => {
    // 'today' takes a different branch (24 pre-populated hour buckets), which
    // carried its own copy of the blocked test.
    const rows = ROWS.map((r) => ({ ...r, ts: NOW.toISOString() }));
    const body = buildDaemonReport(rows, 'today', NOW);
    const fromDaily = body.daily.reduce((n, d) => n + d.blocked, 0);
    expect(fromDaily).toBe(body.summary.blocked);
    expect(body.daily).toHaveLength(24);
  });

  it('excludes post-hook and response-dlp rows from every count', () => {
    const body = buildDaemonReport(
      [
        ...ROWS,
        { ts: TS, tool: 'Bash', decision: 'allowed', source: 'post-hook' },
        {
          ts: TS,
          tool: 'Bash',
          decision: 'dlp',
          source: 'response-dlp',
          checkedBy: 'response-dlp',
        },
      ],
      '7d',
      NOW
    );
    expect(body.summary.total).toBe(6);
    expect(body.summary.blocked).toBe(2);
  });
});
