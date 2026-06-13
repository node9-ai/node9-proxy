import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import {
  parseJSONLFile,
  decodeProjectDirName,
  chunk,
  postCostBatches,
  COST_BATCH_SIZE,
  type DailyEntry,
} from '../costSync';

// Build a tiny tmp dir for fixtures; all tests write into and clean up here.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-cost-test-'));

afterAll(() => {
  try {
    fs.rmSync(TMP, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

function writeFixture(name: string, rows: object[]): string {
  const file = path.join(TMP, name);
  fs.writeFileSync(file, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  return file;
}

function row(opts: { ts: string; model?: string; inp?: number; out?: number; cwd?: string }) {
  return {
    type: 'assistant',
    timestamp: opts.ts,
    message: {
      model: opts.model ?? 'claude-sonnet-4-20251101',
      usage: {
        input_tokens: opts.inp ?? 100,
        output_tokens: opts.out ?? 50,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
      },
    },
    ...(opts.cwd !== undefined ? { cwd: opts.cwd } : {}),
  };
}

describe('cost upload batching (survives the SaaS 200-row cap)', () => {
  const row = (model: string): DailyEntry => ({
    date: '2026-06-12',
    model,
    workingDir: '/w',
    runId: 'r',
    costUSD: 1,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
  });

  it('chunk splits into <= size pieces, in order, covering every item', () => {
    const arr = Array.from({ length: 250 }, (_, i) => i);
    const cs = chunk(arr, COST_BATCH_SIZE);
    expect(cs.length).toBe(2);
    expect(cs[0].length).toBe(200);
    expect(cs[1].length).toBe(50);
    expect(cs.flat()).toEqual(arr); // nothing dropped or reordered
    expect(chunk([], 200)).toEqual([]);
  });

  it('posts every row across multiple <=cap POSTs — non-Claude agents are NOT dropped', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);

    // Mirror the bug: 214 Claude rows FIRST (registry order), then codex/gemini
    // — exactly the layout that made the single oversized POST drop everything
    // past row 200.
    const entries: DailyEntry[] = [
      ...Array.from({ length: 214 }, () => row('claude-opus-4-8')),
      ...Array.from({ length: 12 }, () => row('gpt-5.4')),
      ...Array.from({ length: 16 }, () => row('gemini-2.5-pro')),
    ];

    await postCostBatches('https://api.example', 'k', 'mach', entries);

    // 242 rows → two POSTs (200 + 42), not one truncated-to-200.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const sent = fetchMock.mock.calls.flatMap(
      (c) => JSON.parse((c[1] as { body: string }).body).entries as DailyEntry[]
    );
    expect(sent.length).toBe(242); // every row made it onto the wire
    expect(sent.filter((e) => e.model === 'gpt-5.4').length).toBe(12); // codex survived
    expect(sent.filter((e) => e.model === 'gemini-2.5-pro').length).toBe(16);
    // No single POST exceeds the cap.
    for (const call of fetchMock.mock.calls) {
      const n = JSON.parse((call[1] as { body: string }).body).entries.length;
      expect(n).toBeLessThanOrEqual(COST_BATCH_SIZE);
    }
    vi.unstubAllGlobals();
  });

  it('a failing batch is logged but does not abort the remaining batches', async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error('network'))
      .mockResolvedValue({ ok: true });
    vi.stubGlobal('fetch', fetchMock);
    const entries = Array.from({ length: 250 }, () => row('claude-opus-4-8'));
    await expect(
      postCostBatches('https://api.example', 'k', 'mach', entries)
    ).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2); // second batch still attempted
    vi.unstubAllGlobals();
  });

  // ── Guard 2: observe a server-side shortfall ────────────────────────────
  const okWith = (body: unknown) => ({ ok: true, json: () => Promise.resolve(body) });
  const logOf = (spy: ReturnType<typeof vi.spyOn>) =>
    spy.mock.calls.map((c: unknown[]) => String(c[1])).join('');

  it('logs a shortfall when the SaaS stored fewer rows than were sent', async () => {
    const appendSpy = vi.spyOn(fs, 'appendFileSync').mockImplementation(() => {});
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okWith({ received: 200, stored: 150 })));
    await postCostBatches(
      'https://api.example',
      'k',
      'mach',
      Array.from({ length: 200 }, () => row('claude-opus-4-8'))
    );
    expect(logOf(appendSpy)).toMatch(/dropped 50 of 200/);
    appendSpy.mockRestore();
    vi.unstubAllGlobals();
  });

  it('does not log when stored === sent', async () => {
    const appendSpy = vi.spyOn(fs, 'appendFileSync').mockImplementation(() => {});
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okWith({ received: 10, stored: 10 })));
    await postCostBatches(
      'https://api.example',
      'k',
      'mach',
      Array.from({ length: 10 }, () => row('claude-opus-4-8'))
    );
    expect(logOf(appendSpy)).not.toMatch(/dropped/);
    appendSpy.mockRestore();
    vi.unstubAllGlobals();
  });

  it('tolerates an old SaaS response with no stored field (no false shortfall)', async () => {
    const appendSpy = vi.spyOn(fs, 'appendFileSync').mockImplementation(() => {});
    // Old SaaS: { ok: true } with no `stored` (and historically no json()).
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
    await postCostBatches(
      'https://api.example',
      'k',
      'mach',
      Array.from({ length: 5 }, () => row('claude-opus-4-8'))
    );
    expect(logOf(appendSpy)).not.toMatch(/dropped/);
    appendSpy.mockRestore();
    vi.unstubAllGlobals();
  });
});

describe('decodeProjectDirName', () => {
  it('replaces leading dash with slash and inner dashes with slashes', () => {
    expect(decodeProjectDirName('-home-nadav-node9')).toBe('/home/nadav/node9');
  });
  it('handles a single dash prefix correctly', () => {
    expect(decodeProjectDirName('-tmp')).toBe('/tmp');
  });
});

describe('parseJSONLFile — workingDir behaviour', () => {
  beforeEach(() => {
    // ensure tmp is clean before each test
    for (const f of fs.readdirSync(TMP)) fs.unlinkSync(path.join(TMP, f));
  });

  it('uses the per-row cwd field when present', () => {
    const file = writeFixture('a.jsonl', [
      row({ ts: '2026-04-29T10:00:00Z', cwd: '/projects/payments-api' }),
    ]);
    const entries = [...parseJSONLFile(file, '/fallback').values()];
    expect(entries).toHaveLength(1);
    expect(entries[0].workingDir).toBe('/projects/payments-api');
  });

  it('falls back to the decoded dir name when row.cwd is missing', () => {
    const file = writeFixture('b.jsonl', [
      row({ ts: '2026-04-29T10:00:00Z' }), // no cwd
    ]);
    const entries = [...parseJSONLFile(file, '/home/nadav/node9').values()];
    expect(entries).toHaveLength(1);
    expect(entries[0].workingDir).toBe('/home/nadav/node9');
  });

  it('falls back when row.cwd is non-absolute (defensive)', () => {
    const file = writeFixture('c.jsonl', [
      row({ ts: '2026-04-29T10:00:00Z', cwd: 'relative/path' }),
    ]);
    const entries = [...parseJSONLFile(file, '/fallback').values()];
    expect(entries[0].workingDir).toBe('/fallback');
  });

  it('aggregates separately per workingDir on the same day + model', () => {
    // Two rows, same date, same model, different cwd → two entries.
    const file = writeFixture('d.jsonl', [
      row({ ts: '2026-04-29T10:00:00Z', cwd: '/projects/a', inp: 100 }),
      row({ ts: '2026-04-29T11:00:00Z', cwd: '/projects/b', inp: 200 }),
    ]);
    const entries = [...parseJSONLFile(file, '/fallback').values()];
    expect(entries).toHaveLength(2);
    const dirs = entries.map((e) => e.workingDir).sort();
    expect(dirs).toEqual(['/projects/a', '/projects/b']);
  });

  it('still aggregates within the same workingDir', () => {
    const file = writeFixture('e.jsonl', [
      row({ ts: '2026-04-29T10:00:00Z', cwd: '/projects/a', inp: 100 }),
      row({ ts: '2026-04-29T11:00:00Z', cwd: '/projects/a', inp: 200 }),
    ]);
    const entries = [...parseJSONLFile(file, '/fallback').values()];
    expect(entries).toHaveLength(1);
    expect(entries[0].inputTokens).toBe(300);
    expect(entries[0].workingDir).toBe('/projects/a');
  });
});

describe('parseJSONLFile — runId (per-session correlation)', () => {
  beforeEach(() => {
    for (const f of fs.readdirSync(TMP)) fs.unlinkSync(path.join(TMP, f));
  });

  it('stamps every entry with the JSONL filename stem as runId', () => {
    // Claude Code names JSONL files by their session_id (UUID).
    const sessionId = 'ea385d8a-0c49-4ebe-8b66-c649672cc19e';
    const file = writeFixture(`${sessionId}.jsonl`, [
      row({ ts: '2026-04-29T10:00:00Z', cwd: '/projects/a', inp: 100 }),
    ]);
    const entries = [...parseJSONLFile(file, '/fallback').values()];
    expect(entries).toHaveLength(1);
    expect(entries[0].runId).toBe(sessionId);
  });

  it('aggregates rows from the same session into a single entry', () => {
    // Same session, same date, same project — one combined row.
    const file = writeFixture('sid-A.jsonl', [
      row({ ts: '2026-04-29T10:00:00Z', cwd: '/projects/a', inp: 100 }),
      row({ ts: '2026-04-29T11:00:00Z', cwd: '/projects/a', inp: 200 }),
    ]);
    const entries = [...parseJSONLFile(file, '/fallback').values()];
    expect(entries).toHaveLength(1);
    expect(entries[0].inputTokens).toBe(300);
    expect(entries[0].runId).toBe('sid-A');
  });

  it('does not merge two separate sessions even on identical day/model/cwd', () => {
    // The whole point: two parallel Claude sessions in the same project
    // produce two cost rows, not one merged total.
    const fileA = writeFixture('sid-A.jsonl', [
      row({ ts: '2026-04-29T10:00:00Z', cwd: '/projects/a', inp: 100 }),
    ]);
    const fileB = writeFixture('sid-B.jsonl', [
      row({ ts: '2026-04-29T11:00:00Z', cwd: '/projects/a', inp: 200 }),
    ]);
    const entriesA = [...parseJSONLFile(fileA, '/fallback').values()];
    const entriesB = [...parseJSONLFile(fileB, '/fallback').values()];
    expect(entriesA[0].runId).toBe('sid-A');
    expect(entriesB[0].runId).toBe('sid-B');
    expect(entriesA[0].inputTokens).toBe(100);
    expect(entriesB[0].inputTokens).toBe(200);
  });

  it('produces two rows when a session straddles midnight (per-day rollup preserved)', () => {
    const file = writeFixture('sid-night.jsonl', [
      row({ ts: '2026-04-29T23:00:00Z', cwd: '/projects/a', inp: 100 }),
      row({ ts: '2026-04-30T01:00:00Z', cwd: '/projects/a', inp: 50 }),
    ]);
    const entries = [...parseJSONLFile(file, '/fallback').values()];
    expect(entries).toHaveLength(2);
    expect(entries.map((e) => e.runId)).toEqual(['sid-night', 'sid-night']);
    expect(entries.map((e) => e.date).sort()).toEqual(['2026-04-29', '2026-04-30']);
  });
});
