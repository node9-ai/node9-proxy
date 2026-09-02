import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { scanCodexHistory } from '../cli/commands/scan';
import { _resetPricingCache } from '../pricing/litellm';

// `node9 scan --days 30` reported EVERY Codex session ever recorded, because
// total_token_usage is cumulative and nothing windowed the cost. Measured on
// real data: 41 sessions / $13.69 from scan, 25 / $1.04 from report — same
// pricing function, 13x apart.

let home: string;

const DAY = 86_400_000;
const iso = (msAgo: number): string => new Date(Date.now() - msAgo).toISOString();

/** One rollout-*.jsonl in the layout scanCodexHistory walks. */
function writeSession(id: string, startedMsAgo: number, tokens: number): void {
  const d = path.join(home, '.codex', 'sessions', '2026', '09', '01');
  fs.mkdirSync(d, { recursive: true });
  const lines = [
    { type: 'session_meta', payload: { timestamp: iso(startedMsAgo), id, cwd: '/p' } },
    { type: 'turn_context', payload: { model: 'gpt-5', cwd: '/p' } },
    {
      type: 'event_msg',
      payload: {
        type: 'token_count',
        info: {
          total_token_usage: {
            input_tokens: tokens,
            cached_input_tokens: 0,
            output_tokens: tokens,
          },
        },
      },
    },
  ];
  fs.writeFileSync(
    path.join(d, `rollout-${id}.jsonl`),
    lines.map((l) => JSON.stringify(l)).join('\n')
  );
}

function costFor(startDate: Date | null): number {
  return scanCodexHistory(startDate).totalCostUSD;
}

beforeEach(() => {
  _resetPricingCache(); // deterministic bundled snapshot
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-codexwin-'));
  vi.spyOn(os, 'homedir').mockReturnValue(home);
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
});

describe('scanCodexHistory — cost window', () => {
  it('excludes a session that started before the window', () => {
    writeSession('old', 60 * DAY, 1_000_000);
    const cost = costFor(new Date(Date.now() - 30 * DAY));
    expect(cost).toBe(0);
  });

  it('includes a session that started inside the window', () => {
    writeSession('recent', 5 * DAY, 1_000_000);
    const cost = costFor(new Date(Date.now() - 30 * DAY));
    expect(cost).toBeGreaterThan(0);
  });

  it('counts only the in-window session when both exist', () => {
    writeSession('old', 60 * DAY, 1_000_000);
    writeSession('recent', 5 * DAY, 1_000_000);
    const windowed = costFor(new Date(Date.now() - 30 * DAY));

    // Same window, with the old session removed: the totals must match, which
    // proves the excluded session contributed exactly nothing rather than a
    // little less.
    fs.rmSync(path.join(home, '.codex'), { recursive: true, force: true });
    writeSession('recent', 5 * DAY, 1_000_000);
    const only = costFor(new Date(Date.now() - 30 * DAY));

    expect(windowed).toBeCloseTo(only, 10);
    expect(only).toBeGreaterThan(0); // the comparison must not be 0 === 0
  });

  it('counts EVERYTHING when there is no window — `--all` must not regress', () => {
    // The obvious way to write this filter also silences the full-history
    // scan, which is the one place the whole lifetime is the right answer.
    writeSession('old', 60 * DAY, 1_000_000);
    writeSession('recent', 5 * DAY, 1_000_000);
    const all = costFor(null);
    const windowed = costFor(new Date(Date.now() - 30 * DAY));
    expect(all).toBeGreaterThan(windowed);
  });

  it('drops a session with no start timestamp, exactly as report does', () => {
    // No session_meta, so startTime stays ''. Found by mutation testing: the
    // first version of this test only asserted "did not crash", which every
    // variant passed. It cannot be placed in time, and report-audit.ts:656
    // drops it outright — the whole point here is that the two paths agree, so
    // scan must drop it too rather than invent a placement.
    const d = path.join(home, '.codex', 'sessions', '2026', '09', '01');
    fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(
      path.join(d, 'rollout-nometa.jsonl'),
      [
        JSON.stringify({ type: 'turn_context', payload: { model: 'gpt-5', cwd: '/p' } }),
        JSON.stringify({
          type: 'event_msg',
          payload: {
            type: 'token_count',
            info: {
              total_token_usage: {
                input_tokens: 1_000_000,
                cached_input_tokens: 0,
                output_tokens: 1_000_000,
              },
            },
          },
        }),
      ].join('\n')
    );
    expect(costFor(new Date(Date.now() - 30 * DAY))).toBe(0);
    // ...but with no window at all it still counts, since nothing is excluded.
    expect(costFor(null)).toBeGreaterThan(0);
  });
});
