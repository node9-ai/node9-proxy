// src/cli/render/scan-history.ts
//
// Per-scan trend storage. Each non-screenshot run of `node9 scan`
// appends a small record to ~/.node9/scan-history.json. Nothing in the CLI
// reads it since fw#421 (the trend line went with the scan score); the
// file stays for a later consumer and for users who already have one.
//
// Fail-soft: read errors return null (no prior data), write errors
// warn to stderr but never break the scan. A corrupt history file
// shouldn't cause a green build to red over reporting alone.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { atomicWriteSync } from '../../utils/atomic-write';

export interface ScanHistoryRecord {
  /** ISO 8601 timestamp at which this scan ran. */
  timestamp: string;
  score: number;
  blocked: number;
  review: number;
  leaks: number;
  /** Decoys tripped. Absent on records written before the canary feature;
   *  readers must treat a missing value as 0, never as invalid. */
  canaries?: number;
  loops: number;
  totalCalls: number;
}

/** Capped at 30 — three months of weekly scans, ~60 days of every-other-day. */
export const SCAN_HISTORY_CAP = 30;

export function defaultHistoryPath(): string {
  return path.join(os.homedir(), '.node9', 'scan-history.json');
}

/**
 * Append `record` to the history file, capping to SCAN_HISTORY_CAP
 * entries. Best-effort: any I/O failure is logged to stderr and
 * swallowed — a broken trend file must not break the scan output.
 */
export function appendScanHistory(
  record: ScanHistoryRecord,
  opts: { path?: string; cap?: number } = {}
): void {
  const filePath = opts.path ?? defaultHistoryPath();
  const cap = opts.cap ?? SCAN_HISTORY_CAP;
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    let history: ScanHistoryRecord[] = [];
    if (fs.existsSync(filePath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (Array.isArray(parsed)) {
          history = parsed.filter(isValidRecord);
        }
      } catch {
        // Corrupt file — start fresh rather than refuse to write.
      }
    }
    history.push(record);
    if (history.length > cap) {
      history = history.slice(history.length - cap);
    }
    atomicWriteSync(filePath, JSON.stringify(history, null, 2));
  } catch (err) {
    process.stderr.write(
      `[node9] Warning: could not write scan-history.json: ${(err as Error).message}\n`
    );
  }
}

function isValidRecord(x: unknown): x is ScanHistoryRecord {
  if (typeof x !== 'object' || x === null) return false;
  const r = x as Record<string, unknown>;
  return (
    typeof r.timestamp === 'string' &&
    typeof r.score === 'number' &&
    typeof r.blocked === 'number' &&
    typeof r.review === 'number' &&
    typeof r.leaks === 'number' &&
    typeof r.loops === 'number' &&
    typeof r.totalCalls === 'number'
  );
}
