/**
 * Unit tests for buildReportJson — the envelope used by `node9 report --json`.
 *
 * Pin schemaVersion contract, totals derivation (the totalBlocked sum and
 * blockRate), trend deltaPct math, Map→array sorting (byTool by calls desc,
 * byDay by date asc), and cost rollup.
 */
import { describe, it, expect } from 'vitest';
import { buildReportJson, type BuildReportJsonInput } from '../cli/render/report-json';

const FIXED_TIME = '2026-05-07T12:00:00.000Z';
const T0 = new Date('2026-05-01T00:00:00.000Z');
const T1 = new Date('2026-05-07T23:59:59.999Z');

function emptyInput(overrides: Partial<BuildReportJsonInput> = {}): BuildReportJsonInput {
  return {
    period: '7d',
    start: T0,
    end: T1,
    excludedTests: 0,
    total: 0,
    userApproved: 0,
    userDenied: 0,
    timedOut: 0,
    hardBlocked: 0,
    dlpBlocked: 0,
    observeDlp: 0,
    loopHits: 0,
    testPasses: 0,
    testFails: 0,
    unackedDlp: 0,
    priorBlockRate: null,
    cost: {
      claudeUSD: 0,
      codexUSD: 0,
      inputTokens: 0,
      outputTokens: 0,
      cacheWriteTokens: 0,
      cacheReadTokens: 0,
      byDay: new Map(),
      byModel: new Map(),
      byProject: new Map(),
    },
    toolMap: new Map(),
    blockMap: new Map(),
    ruleMap: new Map(),
    agentMap: new Map(),
    mcpMap: new Map(),
    dailyMap: new Map(),
    hourMap: new Map(),
    generatedAt: FIXED_TIME,
    ...overrides,
  };
}

describe('buildReportJson', () => {
  it('emits schemaVersion 1 and supplied generatedAt', () => {
    const out = buildReportJson(emptyInput());
    expect(out.schemaVersion).toBe(1);
    expect(out.generatedAt).toBe(FIXED_TIME);
  });

  it('range is serialized to ISO 8601 strings', () => {
    const out = buildReportJson(emptyInput());
    expect(out.range.start).toBe(T0.toISOString());
    expect(out.range.end).toBe(T1.toISOString());
  });

  it('totals.blocked sums all block paths', () => {
    const out = buildReportJson(
      emptyInput({
        timedOut: 1,
        hardBlocked: 2,
        dlpBlocked: 3,
        loopHits: 4,
        userDenied: 5,
        userApproved: 100,
        total: 200,
      })
    );
    expect(out.totals.blocked).toBe(15); // 1+2+3+4+5
    expect(out.totals.events).toBe(200);
    expect(out.totals.blockRate).toBeCloseTo(15 / 200);
  });

  it('blockRate is 0 when total is 0 (no divide-by-zero)', () => {
    const out = buildReportJson(emptyInput());
    expect(out.totals.blockRate).toBe(0);
  });

  it('trend.deltaPct is null when no prior data', () => {
    const out = buildReportJson(emptyInput({ priorBlockRate: null }));
    expect(out.trend.priorBlockRate).toBeNull();
    expect(out.trend.deltaPct).toBeNull();
  });

  it('trend.deltaPct is whole-percent integer of (current - prior)', () => {
    // current rate = 15/100 = 0.15; prior = 0.05; delta = +10%
    const out = buildReportJson(
      emptyInput({
        total: 100,
        timedOut: 5,
        hardBlocked: 5,
        dlpBlocked: 5, // total blocked = 15
        priorBlockRate: 0.05,
      })
    );
    expect(out.trend.deltaPct).toBe(10);
  });

  it('cost.totalUSD sums Claude + Codex', () => {
    const out = buildReportJson(
      emptyInput({
        cost: {
          ...emptyInput().cost,
          claudeUSD: 12.34,
          codexUSD: 5.67,
        },
      })
    );
    expect(out.cost.totalUSD).toBeCloseTo(18.01);
  });

  it('byTool is sorted by calls desc and includes all entries (untruncated)', () => {
    const toolMap = new Map([
      ['Read', { calls: 5, blocked: 0 }],
      ['Bash', { calls: 100, blocked: 8 }],
      ['Edit', { calls: 50, blocked: 2 }],
    ]);
    const out = buildReportJson(emptyInput({ toolMap }));
    expect(out.byTool).toEqual([
      { tool: 'Bash', calls: 100, blocked: 8 },
      { tool: 'Edit', calls: 50, blocked: 2 },
      { tool: 'Read', calls: 5, blocked: 0 },
    ]);
  });

  it('byDay is sorted by day asc (chronological for time series)', () => {
    const dailyMap = new Map([
      ['2026-05-03', { calls: 30, blocked: 1 }],
      ['2026-05-01', { calls: 10, blocked: 0 }],
      ['2026-05-02', { calls: 20, blocked: 2 }],
    ]);
    const out = buildReportJson(emptyInput({ dailyMap }));
    expect(out.byDay.map((d) => d.day)).toEqual(['2026-05-01', '2026-05-02', '2026-05-03']);
  });

  it('byHour is sorted by hour asc', () => {
    const hourMap = new Map([
      [14, 50],
      [9, 100],
      [22, 10],
    ]);
    const out = buildReportJson(emptyInput({ hourMap }));
    expect(out.byHour.map((h) => h.hour)).toEqual([9, 14, 22]);
  });

  it('cost.byDay sorted asc, cost.byModel sorted by usd desc', () => {
    const out = buildReportJson(
      emptyInput({
        cost: {
          ...emptyInput().cost,
          byDay: new Map([
            ['2026-05-02', 5],
            ['2026-05-01', 3],
          ]),
          byModel: new Map([
            ['claude-haiku', 1],
            ['claude-opus', 10],
          ]),
        },
      })
    );
    expect(out.cost.byDay.map((d) => d.day)).toEqual(['2026-05-01', '2026-05-02']);
    expect(out.cost.byModel.map((m) => m.model)).toEqual(['claude-opus', 'claude-haiku']);
  });

  it('serializes to valid JSON (round-trip)', () => {
    const out = buildReportJson(
      emptyInput({
        total: 42,
        toolMap: new Map([['Bash', { calls: 42, blocked: 1 }]]),
      })
    );
    const parsed = JSON.parse(JSON.stringify(out));
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.totals.events).toBe(42);
    expect(parsed.byTool[0].tool).toBe('Bash');
  });
});
