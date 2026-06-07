// src/__tests__/cost-sources.test.ts
//
// GAP-3 Phase 1 — regression test for the CostSource registry refactor.
// collectEntries() now merges across a registry of sources (claude + later
// codex). This proves the registry path produces the same Claude output as
// before: walk ~/.claude/projects, parse session JSONL, aggregate per
// (date, model, workingDir, runId). Pure-function behaviour (parseJSONLFile /
// decodeProjectDirName) is covered by costSync.test.ts.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { collectEntries, claudeSource } from '../costSync';

let TMP: string;
const homeSpy = vi.spyOn(os, 'homedir');

function assistantRow(opts: { ts: string; inp: number; out: number; cwd?: string }) {
  return JSON.stringify({
    type: 'assistant',
    timestamp: opts.ts,
    message: {
      model: 'claude-sonnet-4-20251101',
      usage: {
        input_tokens: opts.inp,
        output_tokens: opts.out,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
      },
    },
    ...(opts.cwd !== undefined ? { cwd: opts.cwd } : {}),
  });
}

function writeSession(encodedDir: string, sessionId: string, rows: string[]) {
  const dir = path.join(TMP, '.claude', 'projects', encodedDir);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${sessionId}.jsonl`), rows.join('\n') + '\n');
}

beforeEach(() => {
  TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-costsrc-'));
  homeSpy.mockReturnValue(TMP);
});

afterEach(() => {
  homeSpy.mockReset();
  try {
    fs.rmSync(TMP, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

describe('GAP-3 Phase 1 — CostSource registry', () => {
  it('claudeSource.available() reflects ~/.claude/projects presence', () => {
    expect(claudeSource.available()).toBe(false); // not created yet
    fs.mkdirSync(path.join(TMP, '.claude', 'projects'), { recursive: true });
    expect(claudeSource.available()).toBe(true);
  });

  it('collectEntries returns [] when no Claude data is present', () => {
    expect(collectEntries()).toEqual([]);
  });

  it('aggregates a single session into one entry (registry → claude path)', () => {
    writeSession('-projects-a', 'sid-A', [
      assistantRow({ ts: '2026-04-29T10:00:00Z', inp: 100, out: 50, cwd: '/projects/a' }),
      assistantRow({ ts: '2026-04-29T11:00:00Z', inp: 200, out: 20, cwd: '/projects/a' }),
    ]);
    const entries = collectEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].inputTokens).toBe(300);
    expect(entries[0].outputTokens).toBe(70);
    expect(entries[0].runId).toBe('sid-A');
    expect(entries[0].workingDir).toBe('/projects/a');
    expect(entries[0].costUSD).toBeGreaterThan(0);
  });

  it('keeps two parallel sessions in the same project as separate rows', () => {
    writeSession('-projects-a', 'sid-A', [
      assistantRow({ ts: '2026-04-29T10:00:00Z', inp: 100, out: 10, cwd: '/projects/a' }),
    ]);
    writeSession('-projects-a', 'sid-B', [
      assistantRow({ ts: '2026-04-29T11:00:00Z', inp: 200, out: 20, cwd: '/projects/a' }),
    ]);
    const entries = collectEntries().sort((a, b) => (a.runId! < b.runId! ? -1 : 1));
    expect(entries).toHaveLength(2);
    expect(entries.map((e) => e.runId)).toEqual(['sid-A', 'sid-B']);
    expect(entries.map((e) => e.inputTokens)).toEqual([100, 200]);
  });

  it('respects the sinceMs mtime cutoff', () => {
    writeSession('-projects-a', 'sid-old', [
      assistantRow({ ts: '2020-01-01T10:00:00Z', inp: 100, out: 10, cwd: '/projects/a' }),
    ]);
    // Cutoff in the future → the (just-written, but content-dated-2020) file is
    // skipped only if its mtime is older. Force an old mtime to simulate.
    const f = path.join(TMP, '.claude', 'projects', '-projects-a', 'sid-old.jsonl');
    const old = new Date('2020-01-02T00:00:00Z');
    fs.utimesSync(f, old, old);
    expect(collectEntries(Date.now())).toEqual([]); // cutoff = now → old file skipped
    expect(collectEntries(0)).toHaveLength(1); // cutoff = epoch → included
  });
});
