// The daemon's cost upload: deferred past startup, and incremental.
//
// A full-history parse is synchronous and took tens of seconds on a heavy
// machine. Run at daemon startup it blocked the event loop through the
// takeover handshake, so a refresh after an upgrade gave up and the old
// daemon kept running; run every ten minutes it stalled the daemon each time.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const creds = { apiKey: 'key-1', apiUrl: 'https://api.example' };
vi.mock('../config', async (orig) => ({
  ...(await orig<typeof import('../config')>()),
  getCredentials: () => creds,
}));
vi.mock('../pricing/litellm.js', async (orig) => ({
  ...(await orig<typeof import('../pricing/litellm.js')>()),
  ensurePricingLoaded: async () => {},
}));

import { FIRST_RUN_DELAY_MS, startCostSync, syncCost } from '../costSync';
import { readCostLedger } from '../cost-ledger';

let home: string;
const homeSpy = vi.spyOn(os, 'homedir');
let fetchMock: ReturnType<typeof vi.fn>;

function assistantRow(ts: string, inp: number): string {
  return JSON.stringify({
    type: 'assistant',
    timestamp: ts,
    cwd: '/projects/a',
    message: {
      model: 'claude-sonnet-4-20251101',
      usage: {
        input_tokens: inp,
        output_tokens: 1,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
      },
    },
  });
}

function writeSession(sessionId: string, rows: string[], mtime: Date): void {
  const dir = path.join(home, '.claude', 'projects', '-projects-a');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${sessionId}.jsonl`);
  fs.writeFileSync(file, rows.join('\n') + '\n');
  fs.utimesSync(file, mtime, mtime);
}

/** The runIds of every row posted, in order. */
function postedRunIds(): string[] {
  return fetchMock.mock.calls.flatMap((c) =>
    (JSON.parse((c[1] as { body: string }).body).entries as Array<{ runId: string }>).map(
      (e) => e.runId
    )
  );
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-costinc-'));
  homeSpy.mockReturnValue(home);
  fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  homeSpy.mockReset();
  fs.rmSync(home, { recursive: true, force: true });
});

describe('syncCost: incremental upload', () => {
  const old = new Date(Date.now() - 3 * 24 * 3600_000);

  it('sends all history once, then only the sessions written since', async () => {
    writeSession('sid-old', [assistantRow('2026-11-20T10:00:00Z', 100)], old);
    await syncCost();
    expect(postedRunIds()).toEqual(['sid-old']);

    // Nothing changed: nothing is parsed or sent.
    fetchMock.mockClear();
    await syncCost();
    expect(fetchMock).not.toHaveBeenCalled();

    // A new session: only it goes out, with its whole total.
    fetchMock.mockClear();
    writeSession(
      'sid-new',
      [assistantRow('2026-11-23T10:00:00Z', 5), assistantRow('2026-11-23T10:01:00Z', 7)],
      new Date()
    );
    await syncCost();
    expect(postedRunIds()).toEqual(['sid-new']);
    const sent = JSON.parse((fetchMock.mock.calls[0][1] as { body: string }).body).entries[0];
    expect(sent.inputTokens).toBe(12);
  });

  it('sends the same sessions again after a failed batch', async () => {
    writeSession('sid-old', [assistantRow('2026-11-20T10:00:00Z', 100)], old);
    fetchMock.mockResolvedValueOnce({ ok: false, status: 503 });
    await syncCost();
    fetchMock.mockClear();
    await syncCost();
    expect(postedRunIds()).toEqual(['sid-old']);
  });

  it('starts from all history for another account', async () => {
    writeSession('sid-old', [assistantRow('2026-11-20T10:00:00Z', 100)], old);
    await syncCost();
    fetchMock.mockClear();
    creds.apiKey = 'key-2';
    try {
      await syncCost();
    } finally {
      creds.apiKey = 'key-1';
    }
    expect(postedRunIds()).toEqual(['sid-old']);
  });
});

describe('startCostSync', () => {
  it('parses nothing at startup; the first run comes after the delay', () => {
    vi.useFakeTimers();
    startCostSync();
    expect(readCostLedger()).toBeNull();
    vi.advanceTimersByTime(FIRST_RUN_DELAY_MS);
    expect(readCostLedger()).not.toBeNull();
    vi.clearAllTimers();
  });
});
