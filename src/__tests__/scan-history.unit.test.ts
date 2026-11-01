/**
 * Unit tests for scan-history.ts — the read/write/diff helpers behind
 * the "▲N since K days ago" trend suffix in `node9 scan`.
 *
 * Each test isolates the on-disk file by passing an explicit `path` so
 * we never touch the user's real ~/.node9/scan-history.json.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  appendScanHistory,
  SCAN_HISTORY_CAP,
  type ScanHistoryRecord,
} from '../cli/render/scan-history';

let tmpDir: string;
let historyPath: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-history-'));
  historyPath = path.join(tmpDir, 'scan-history.json');
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function rec(score: number, daysAgo = 0): ScanHistoryRecord {
  return {
    timestamp: new Date(Date.now() - daysAgo * 86_400_000).toISOString(),
    score,
    blocked: 0,
    review: 0,
    leaks: 0,
    loops: 0,
    totalCalls: 0,
  };
}

describe('appendScanHistory', () => {
  it('creates the file and parent directory if missing', () => {
    const nested = path.join(tmpDir, 'a', 'b', 'c', 'history.json');
    appendScanHistory(rec(80), { path: nested });
    expect(fs.existsSync(nested)).toBe(true);
    const arr = JSON.parse(fs.readFileSync(nested, 'utf8'));
    expect(arr).toHaveLength(1);
    expect(arr[0].score).toBe(80);
  });

  it('appends to an existing file (does not overwrite)', () => {
    appendScanHistory(rec(50), { path: historyPath });
    appendScanHistory(rec(60), { path: historyPath });
    const arr = JSON.parse(fs.readFileSync(historyPath, 'utf8'));
    expect(arr).toHaveLength(2);
    expect(arr.map((r: ScanHistoryRecord) => r.score)).toEqual([50, 60]);
  });

  it('caps to SCAN_HISTORY_CAP entries (oldest dropped)', () => {
    const cap = 3;
    for (let i = 0; i < cap + 2; i++) {
      appendScanHistory(rec(10 * i), { path: historyPath, cap });
    }
    const arr = JSON.parse(fs.readFileSync(historyPath, 'utf8'));
    expect(arr).toHaveLength(cap);
    // Records 0,1 were dropped; we expect 20,30,40 (indices 2,3,4).
    expect(arr.map((r: ScanHistoryRecord) => r.score)).toEqual([20, 30, 40]);
  });

  it('exposes default SCAN_HISTORY_CAP as 30', () => {
    expect(SCAN_HISTORY_CAP).toBe(30);
  });

  it('starts fresh when existing file is corrupt (does not throw)', () => {
    fs.writeFileSync(historyPath, '{not json');
    expect(() => appendScanHistory(rec(50), { path: historyPath })).not.toThrow();
    const arr = JSON.parse(fs.readFileSync(historyPath, 'utf8'));
    expect(arr).toHaveLength(1);
  });

  it('does not throw on write failure (warns to stderr instead)', () => {
    const stderrWrites: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      stderrWrites.push(typeof chunk === 'string' ? chunk : chunk.toString());
      return true;
    }) as typeof process.stderr.write;
    try {
      // Path that resolves into a regular file (treats it as a directory)
      const blockedPath = path.join(historyPath, 'inside.json');
      fs.writeFileSync(historyPath, '[]');
      expect(() => appendScanHistory(rec(50), { path: blockedPath })).not.toThrow();
      expect(stderrWrites.join('')).toContain('could not write scan-history.json');
    } finally {
      process.stderr.write = origWrite;
    }
  });
});
