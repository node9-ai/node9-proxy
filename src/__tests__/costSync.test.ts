import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { parseJSONLFile, decodeProjectDirName } from '../costSync';

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
