import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanCopilotHistory } from '../cli/commands/scan';
import { _resetPricingCache } from '../pricing/litellm';

// `scanCopilotHistory` hardcoded `totalCostUSD: 0` with the comment "event
// logs carry no token/cost rollup". That was wrong: session.shutdown carries a
// modelMetrics rollup, and costSync had been pricing it all along — the upload
// path reported $0.0426 of gpt-5-mini while `node9 scan` showed $0.00.
//
// A $0 beside a real agent does not read as "no data", it reads as "free".

let home: string;
const DAY = 86_400_000;
const iso = (msAgo: number): string => new Date(Date.now() - msAgo).toISOString();

function writeSession(id: string, startedMsAgo: number, tokens: number): void {
  const d = path.join(home, '.copilot', 'session-state', id);
  fs.mkdirSync(d, { recursive: true });
  const lines = [
    {
      type: 'session.start',
      timestamp: iso(startedMsAgo),
      data: { sessionId: id, startTime: iso(startedMsAgo), context: { cwd: '/p' } },
    },
    {
      type: 'session.shutdown',
      timestamp: iso(startedMsAgo),
      data: {
        modelMetrics: {
          'gpt-5-mini': {
            usage: {
              inputTokens: tokens,
              outputTokens: tokens,
              cacheReadTokens: 0,
              cacheWriteTokens: 0,
            },
            // Copilot's own cost is 0 because GitHub bills a subscription, not
            // tokens. Trusting it would report real consumption as free — the
            // same confusion the "API value" relabel exists to prevent.
            requests: { cost: 0 },
          },
        },
      },
    },
  ];
  fs.writeFileSync(path.join(d, 'events.jsonl'), lines.map((l) => JSON.stringify(l)).join('\n'));
}

beforeEach(() => {
  _resetPricingCache();
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-copilot-'));
  vi.spyOn(os, 'homedir').mockReturnValue(home);
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
});

describe('scanCopilotHistory — cost', () => {
  it('prices a session from its token rollup instead of reporting zero', () => {
    writeSession('s1', 5 * DAY, 1_000_000);
    expect(scanCopilotHistory(null).totalCostUSD).toBeGreaterThan(0);
  });

  it('does not take Copilot at its word that the session cost nothing', () => {
    // requests.cost is 0 in the fixture, as it is in real transcripts. The
    // tokens are what we measure.
    writeSession('s1', 5 * DAY, 1_000_000);
    const cost = scanCopilotHistory(null).totalCostUSD;
    expect(cost).not.toBe(0);
  });

  it('excludes a session outside the window', () => {
    writeSession('old', 60 * DAY, 1_000_000);
    expect(scanCopilotHistory(new Date(Date.now() - 30 * DAY)).totalCostUSD).toBe(0);
  });

  it('counts everything when there is no window', () => {
    writeSession('old', 60 * DAY, 1_000_000);
    writeSession('recent', 5 * DAY, 1_000_000);
    const all = scanCopilotHistory(null).totalCostUSD;
    const windowed = scanCopilotHistory(new Date(Date.now() - 30 * DAY)).totalCostUSD;
    expect(all).toBeGreaterThan(windowed);
    expect(windowed).toBeGreaterThan(0);
  });

  it('stays at zero when a session never shut down, so there is no rollup', () => {
    const d = path.join(home, '.copilot', 'session-state', 'live');
    fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(
      path.join(d, 'events.jsonl'),
      JSON.stringify({ type: 'session.start', data: { sessionId: 'live' } })
    );
    expect(scanCopilotHistory(null).totalCostUSD).toBe(0);
  });
});
