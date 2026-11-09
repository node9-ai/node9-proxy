import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  buildCostLedger,
  judgeBudget,
  readCostLedger,
  writeCostLedger,
  utcDay,
  LEDGER_STALE_MS,
} from '../cost-ledger';

// The spend ledger behind behavior.cost-budget (node9Firewall#427).

const now = new Date('2026-11-09T10:00:00');
const day = utcDay(now);
const entry = (o: Partial<Parameters<typeof buildCostLedger>[0][number]>) => ({
  date: day,
  costUSD: 1,
  inputTokens: 100,
  outputTokens: 10,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
  ...o,
});

describe('buildCostLedger', () => {
  it("sums today's entries per session; other days are left out; no session counts toward the day only", () => {
    const l = buildCostLedger(
      [
        entry({ runId: 's1', costUSD: 2.5 }),
        entry({ runId: 's1', costUSD: 1.5, outputTokens: 50 }),
        entry({ runId: 's2', costUSD: 0.25 }),
        entry({ costUSD: 3 }),
        entry({ runId: 's1', costUSD: 100, date: '2026-11-08' }),
      ],
      now
    );
    expect(l.day).toBe(day);
    expect(l.sessions.s1).toEqual({ usd: 4, tokens: 260 });
    expect(l.sessions.s2.usd).toBe(0.25);
    expect(l.dayUSD).toBe(7.25);
  });
});

describe('judgeBudget', () => {
  const ledger = buildCostLedger(
    [entry({ runId: 's1', costUSD: 6 }), entry({ runId: 's2', costUSD: 3 })],
    now
  );
  const t = now.getTime();
  it('no ceiling: nothing to judge', () => {
    expect(judgeBudget(ledger, 's1', {}, t)).toBeNull();
  });
  it('the session past its ceiling, under it, and a session the ledger has not seen', () => {
    expect(judgeBudget(ledger, 's1', { sessionUSD: 5 }, t)).toEqual({
      over: 'session',
      spent: 6,
      ceiling: 5,
    });
    expect(judgeBudget(ledger, 's2', { sessionUSD: 5 }, t)).toBeNull();
    expect(judgeBudget(ledger, 's9', { sessionUSD: 5 }, t)).toBe('unknown');
    // With a day ceiling too, an unseen session is judged by the day.
    expect(judgeBudget(ledger, 's9', { sessionUSD: 5, dayUSD: 100 }, t)).toBeNull();
  });
  it('the day past its ceiling wins over the session', () => {
    expect(judgeBudget(ledger, 's2', { sessionUSD: 5, dayUSD: 8 }, t)).toEqual({
      over: 'day',
      spent: 9,
      ceiling: 8,
    });
  });
  it('no ledger, a stale one, or another day: unknown', () => {
    expect(judgeBudget(null, 's1', { sessionUSD: 5 }, t)).toBe('unknown');
    expect(judgeBudget(ledger, 's1', { sessionUSD: 5 }, t + LEDGER_STALE_MS + 1)).toBe('unknown');
    expect(judgeBudget({ ...ledger, day: '2026-11-08' }, 's1', { sessionUSD: 5 }, t)).toBe(
      'unknown'
    );
  });
});

describe('the file', () => {
  it('round-trips, and a missing or broken file reads as none', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-ledger-'));
    expect(readCostLedger(home)).toBeNull();
    const l = buildCostLedger([entry({ runId: 's1', costUSD: 2 })], now);
    writeCostLedger(l, home);
    expect(readCostLedger(home)).toEqual(l);
    fs.writeFileSync(path.join(home, '.node9', 'cost', 'sessions.json'), 'not-json{{{');
    expect(readCostLedger(home)).toBeNull();
    fs.rmSync(home, { recursive: true, force: true });
  });
});
