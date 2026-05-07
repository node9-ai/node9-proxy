// src/cli/render/scan-history.ts
//
// Per-scan trend storage. Each non-screenshot run of `node9 scan`
// appends a small record to ~/.node9/scan-history.json so the next
// run can show "▲N since K days ago" next to the headline score.
//
// Fail-soft: read errors return null (no prior data), write errors
// warn to stderr but never break the scan. A corrupt history file
// shouldn't cause a green build to red over reporting alone.

import fs from 'fs';
import path from 'path';
import os from 'os';

export interface ScanHistoryRecord {
  /** ISO 8601 timestamp at which this scan ran. */
  timestamp: string;
  score: number;
  blocked: number;
  review: number;
  leaks: number;
  loops: number;
  totalCalls: number;
}

/** Capped at 30 — three months of weekly scans, ~60 days of every-other-day. */
export const SCAN_HISTORY_CAP = 30;

export function defaultHistoryPath(): string {
  return path.join(os.homedir(), '.node9', 'scan-history.json');
}

/**
 * Read the history file and return the most recent record older than
 * `now`. Used to compute the trend on the current run. Returns null on
 * any error (missing file, parse error, malformed shape).
 */
export function readPreviousScan(opts: { path?: string } = {}): ScanHistoryRecord | null {
  const filePath = opts.path ?? defaultHistoryPath();
  try {
    if (!fs.existsSync(filePath)) return null;
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) return null;
    // Records are appended chronologically; the last one is the most
    // recent prior scan from the caller's perspective.
    const last = parsed[parsed.length - 1];
    if (!isValidRecord(last)) return null;
    return last;
  } catch {
    return null;
  }
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
    fs.writeFileSync(filePath, JSON.stringify(history, null, 2));
  } catch (err) {
    process.stderr.write(
      `[node9] Warning: could not write scan-history.json: ${(err as Error).message}\n`
    );
  }
}

export interface ScanDelta {
  scoreDelta: number; // current.score - previous.score
  daysAgo: number; // floor of (now - previous.timestamp) in days
}

/**
 * Compute the delta a renderer should show. Returns null if no comparison
 * is meaningful (no prior, same-day double-scan with identical numbers).
 */
export function computeScanDelta(
  current: ScanHistoryRecord,
  previous: ScanHistoryRecord | null,
  now: number = Date.now()
): ScanDelta | null {
  if (!previous) return null;
  const prevMs = Date.parse(previous.timestamp);
  if (Number.isNaN(prevMs)) return null;
  const scoreDelta = current.score - previous.score;
  const daysAgo = Math.max(0, Math.floor((now - prevMs) / 86_400_000));
  if (scoreDelta === 0 && daysAgo === 0) return null;
  return { scoreDelta, daysAgo };
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
