import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { codexSource, codexUsageInWindow, parseCodexSession, parseCodexUsage } from '../cost-codex';
import { _resetPricingCache } from '../pricing/litellm';
import { loadCodexCostAsync } from '../cli/aggregate/report-audit';
import { scanCodexHistory } from '../cli/commands/scan';
import { buildSessions } from '../cli/commands/sessions';

const json = (v: unknown) => JSON.stringify(v);
const meta = json({
  type: 'session_meta',
  payload: { id: 'mixed', cwd: '/project', timestamp: '2026-09-01T12:00:00Z' },
});
const model = (name: string) => json({ type: 'turn_context', payload: { model: name } });
const tokens = (input: number, cached = 0, output = 0, written = 0) => ({
  input_tokens: input,
  cached_input_tokens: cached,
  output_tokens: output,
  cache_write_input_tokens: written,
});
const event = (ts: string, total: unknown, last?: unknown) =>
  json({
    type: 'event_msg',
    timestamp: ts,
    payload: { type: 'token_count', info: { total_token_usage: total, last_token_usage: last } },
  });
const sum = (rows: { costUSD: number }[]) => rows.reduce((s, r) => s + r.costUSD, 0);
let home: string;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-codex-events-'));
  vi.spyOn(os, 'homedir').mockReturnValue(home);
  vi.stubEnv('CODEX_HOME', '');
  _resetPricingCache();
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  _resetPricingCache();
  fs.rmSync(home, { recursive: true, force: true });
});

function mixedSession(): string[] {
  return [
    meta,
    model('gpt-5'),
    event('2026-09-01T12:10:00Z', tokens(1_000_000, 400_000, 10_000)),
    model('gpt-5-mini'),
    event('2026-09-02T00:10:00Z', tokens(2_000_000, 800_000, 20_000)),
  ];
}
function write(lines: string[], base = path.join(home, '.codex', 'sessions')): string {
  const dir = path.join(base, '2026', '09', '01');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'rollout.jsonl'), lines.join('\n'));
  return base;
}

describe('Codex request accounting', () => {
  it('prices each model at the event date and clears the old final-model start-day row', () => {
    const rows = parseCodexSession(mixedSession());
    // First request: 600K * 1.25/M + 400K * .125/M + 10K * 10/M = .90.
    // Second request uses mini: 600K * .25/M + 400K * .025/M + 10K * 2/M = .18.
    expect(sum(rows)).toBeCloseTo(1.08, 10);
    expect(rows.find((r) => r.date === '2026-09-01' && r.model === 'gpt-5')?.costUSD).toBeCloseTo(
      0.9,
      10
    );
    expect(
      rows.find((r) => r.date === '2026-09-02' && r.model === 'gpt-5-mini')?.costUSD
    ).toBeCloseTo(0.18, 10);
    expect(rows.find((r) => r.date === '2026-09-01' && r.model === 'gpt-5-mini')?.costUSD).toBe(0);
    // Simulate the existing server's absolute upserts, including a previous
    // sync before the model switch. No obsolete row may survive the resync.
    const stored = new Map([
      ['2026-09-01:gpt-5', 99],
      ['2026-09-01:gpt-5-mini', 99],
    ]);
    for (const row of rows) stored.set(`${row.date}:${row.model}`, row.costUSD);
    expect([...stored.values()].reduce((a, b) => a + b, 0)).toBeCloseTo(1.08, 10);
  });

  it('does not rebill repeated totals even when timestamp and model change', () => {
    const total = tokens(1000, 200, 100);
    const usage = parseCodexUsage([
      meta,
      model('gpt-5'),
      event('2026-09-01T23:01:00Z', total, total),
      model('gpt-5-mini'),
      event('2026-09-02T00:01:00Z', total, total),
    ]);
    expect(usage.events).toHaveLength(1);
    expect(usage.events[0].costUSD).toBeCloseTo(0.002025, 10);
    expect(usage.events[0].model).toBe('gpt-5');
  });

  it('retains usage before a reset and counts the new epoch exactly once', () => {
    const usage = parseCodexUsage([
      meta,
      model('gpt-5'),
      event('2026-09-01T23:01:00Z', tokens(1000, 0, 100)),
      event('2026-09-01T23:02:00Z', tokens(100, 0, 10), tokens(100, 0, 10)),
      event('2026-09-01T23:03:00Z', tokens(100, 0, 10), tokens(100, 0, 10)),
      event('2026-09-01T23:04:00Z', tokens(300, 0, 30)),
    ]);
    expect(usage.events.map((e) => e.inputTokens)).toEqual([1000, 100, 200]);
    expect(sum(usage.events)).toBeCloseTo(1300 * 1.25e-6 + 130 * 10e-6, 10);
  });

  it('uses the baseline before the window and excludes events after its end', () => {
    const parsed = parseCodexUsage([
      ...mixedSession(),
      event('2026-09-03T00:00:00Z', tokens(3_000_000, 1_200_000, 30_000)),
    ]);
    const rows = codexUsageInWindow(
      parsed,
      new Date('2026-09-02T00:00:00Z'),
      new Date('2026-09-02T23:59:59Z')
    );
    expect(sum(rows)).toBeCloseTo(0.18, 10);
  });

  it('counts reasoning only as part of output, clamps cached input, and tolerates bad records', () => {
    const rows = parseCodexUsage([
      meta,
      model('gpt-5'),
      'null',
      'broken JSON',
      json({ type: 'event_msg', payload: { type: 'token_count', info: null } }),
      event('2026-09-01T23:01:00Z', { ...tokens(100, 200, 50), reasoning_output_tokens: 40 }),
    ]).events;
    expect(rows).toHaveLength(1);
    expect(rows[0].inputTokens).toBe(0);
    expect(rows[0].cacheReadTokens).toBe(100);
    expect(rows[0].costUSD).toBeCloseTo(100 * 0.125e-6 + 50 * 10e-6, 10);
  });

  it('keeps equal-size standalone requests while removing exact replays', () => {
    const first = event('2026-09-01T23:01:00Z', undefined, tokens(100));
    const second = event('2026-09-01T23:02:00Z', undefined, tokens(100));
    expect(parseCodexUsage([meta, model('gpt-5'), first, first, second]).events).toHaveLength(2);
  });

  it('does not double count when cumulative usage returns after a last-only event', () => {
    const parsed = parseCodexUsage([
      meta,
      model('gpt-5'),
      event('2026-09-01T23:01:00Z', tokens(100)),
      event('2026-09-01T23:02:00Z', undefined, tokens(100)),
      event('2026-09-01T23:03:00Z', tokens(200), tokens(100)),
      event('2026-09-01T23:04:00Z', tokens(300), tokens(100)),
    ]);
    expect(parsed.events.map((e) => e.inputTokens)).toEqual([100, 100, 100]);
  });

  it('retains partial cumulative counters and skips invalid values', () => {
    const parsed = parseCodexUsage([
      meta,
      model('gpt-5'),
      event('2026-09-01T23:01:00Z', tokens(100, 20, 10)),
      event('2026-09-01T23:02:00Z', { input_tokens: -1, output_tokens: 20 }),
      event('2026-09-01T23:03:00Z', { input_tokens: 200, output_tokens: 20 }),
    ]);
    expect(parsed.events.map((e) => e.inputTokens + e.cacheReadTokens)).toEqual([100, 100]);
    expect(parsed.events.map((e) => e.cacheReadTokens)).toEqual([20, 0]);
  });

  it('uses request input, not cumulative input, for long-context pricing', () => {
    const parsed = parseCodexUsage([
      meta,
      model('gpt-6-astra'),
      event('2026-09-01T23:01:00Z', tokens(200_000, 0, 100), tokens(200_000, 0, 100)),
      event('2026-09-01T23:02:00Z', tokens(400_000, 0, 200), tokens(200_000, 0, 100)),
      event('2026-09-01T23:03:00Z', tokens(700_000, 0, 300), tokens(300_000, 0, 100)),
    ]);
    for (const [index, cost] of [2.005, 2.005, 6.0075].entries()) {
      expect(parsed.events[index].costUSD).toBeCloseTo(cost, 10);
    }
  });

  it('applies recorded Astra fast pricing and resets the tier on a new context', () => {
    const parsed = parseCodexUsage([
      meta,
      json({ type: 'turn_context', payload: { model: 'gpt-6-astra', service_tier: 'fast' } }),
      event('2026-09-01T23:01:00Z', tokens(1000)),
      model('gpt-6-astra'),
      event('2026-09-01T23:02:00Z', tokens(2000)),
    ]);
    expect(parsed.events.map((e) => e.costUSD)).toEqual([0.02, 0.01]);
  });

  it('uses exact offline model rates instead of a shorter model prefix', () => {
    const parsed = parseCodexUsage([
      meta,
      model('gpt-5.3-codex'),
      event('2026-09-01T23:01:00Z', tokens(1000, 0, 100)),
    ]);
    expect(parsed.events[0].costUSD).toBeCloseTo(0.00315, 10);
  });

  it('uses the event timestamp even without session metadata', () => {
    const parsed = parseCodexUsage([
      model('gpt-5'),
      event('2026-09-02T03:00:00+03:00', tokens(100)),
    ]);
    expect(parsed.events[0].timestamp).toBe('2026-09-02T00:00:00.000Z');
  });

  it('prices cache writes separately from uncached input', () => {
    fs.mkdirSync(path.join(home, '.node9'));
    fs.writeFileSync(
      path.join(home, '.node9', 'model-pricing.json'),
      json({
        fetchedAt: new Date().toISOString(),
        prices: { 'gpt-6-astra': [10e-6, 50e-6, 12.5e-6, 1e-6] },
      })
    );
    const row = parseCodexUsage([
      meta,
      model('gpt-6-astra'),
      event('2026-09-02T00:00:00Z', tokens(1000, 400, 100, 200)),
    ]).events[0];
    expect(row.inputTokens).toBe(400);
    expect(row.cacheWriteTokens).toBe(200);
    expect(row.costUSD).toBeCloseTo(0.004 + 0.0004 + 0.0025 + 0.005, 10);
  });
});

describe('Codex collection and surface reconciliation', () => {
  it('upload, report, scan and sessions agree for a mixed-model session crossing midnight', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-09-03T12:00:00Z'));
    try {
      const base = write(mixedSession());
      const start = new Date('2026-09-02T00:00:00Z');
      const end = new Date('2026-09-02T23:59:59Z');
      const report = await loadCodexCostAsync(start, end, base);
      expect(report.total).toBeCloseTo(0.18, 10);
      expect(report.byModel.get('gpt-5-mini')).toBeCloseTo(0.18, 10);
      expect(sum(codexSource.collect().filter((r) => r.date === '2026-09-02'))).toBeCloseTo(
        0.18,
        10
      );
      expect(scanCodexHistory(start).totalCostUSD).toBeCloseTo(0.18, 10);
      expect(buildSessions(1).find((r) => r.agent === 'codex')?.costUSD).toBeCloseTo(0.18, 10);
    } finally {
      vi.useRealTimers();
    }
  });

  it('counts a session copied into the archive once on all surfaces', async () => {
    const base = write(mixedSession());
    write(mixedSession(), path.join(home, '.codex', 'archived_sessions'));
    expect(sum(codexSource.collect())).toBeCloseTo(1.08, 10);
    expect(scanCodexHistory(null).totalCostUSD).toBeCloseTo(1.08, 10);
    expect(
      (await loadCodexCostAsync(new Date('2026-09-01'), new Date('2026-09-03'), base)).total
    ).toBeCloseTo(1.08, 10);
  });

  it('discovers archived-only history and honors CODEX_HOME on every surface', async () => {
    const custom = path.join(home, 'custom');
    vi.stubEnv('CODEX_HOME', custom);
    write(mixedSession(), path.join(custom, 'archived_sessions'));
    expect(codexSource.available()).toBe(true);
    expect(sum(codexSource.collect())).toBeCloseTo(1.08, 10);
    expect(scanCodexHistory(null).totalCostUSD).toBeCloseTo(1.08, 10);
    expect(buildSessions(null).find((r) => r.agent === 'codex')?.costUSD).toBeCloseTo(1.08, 10);
    expect(
      (
        await loadCodexCostAsync(
          new Date('2026-09-01'),
          new Date('2026-09-03'),
          path.join(custom, 'sessions')
        )
      ).total
    ).toBeCloseTo(1.08, 10);
  });
});
