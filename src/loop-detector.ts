// src/loop-detector.ts
// Agent Loop / Runaway Detection.
// Tracks recent tool calls in a file-based sliding window.
// When the same tool + args hash exceeds a threshold within the window, signals a loop.

import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

/** Evaluated lazily so tests can override HOME/USERPROFILE between calls. */
function loopStateFile(): string {
  return path.join(os.homedir(), '.node9', 'loop-state.json');
}

interface ToolCallRecord {
  /** tool name */
  t: string;
  /** args hash (16 hex chars) */
  h: string;
  /** timestamp ms */
  ts: number;
}

const MAX_RECORDS = 500;

export function computeArgsHash(args: unknown): string {
  const str = JSON.stringify(args ?? '');
  return crypto.createHash('sha256').update(str).digest('hex').slice(0, 16);
}

function readState(): ToolCallRecord[] {
  try {
    if (!fs.existsSync(loopStateFile())) return [];
    const raw = fs.readFileSync(loopStateFile(), 'utf-8');
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed as ToolCallRecord[];
  } catch {
    // Corrupt file — start fresh (lesson from PR #81)
    return [];
  }
}

function writeState(records: ToolCallRecord[]): void {
  const dir = path.dirname(loopStateFile());
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  // Atomic write: write to tmp, rename (pattern from auth/state.ts)
  const tmpPath = `${loopStateFile()}.${os.hostname()}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(records));
  fs.renameSync(tmpPath, loopStateFile());
}

export interface LoopCheckResult {
  looping: boolean;
  count: number;
}

export function recordAndCheck(
  tool: string,
  args: unknown,
  threshold = 3,
  windowMs = 120_000
): LoopCheckResult {
  try {
    const hash = computeArgsHash(args);
    const now = Date.now();
    const cutoff = now - windowMs;

    // Read existing, filter expired entries, append current
    const records = readState().filter((r) => r.ts >= cutoff);
    records.push({ t: tool, h: hash, ts: now });

    // Count matching entries (same tool + same args hash)
    const count = records.filter((r) => r.t === tool && r.h === hash).length;

    // Write back, capped to prevent unbounded growth
    writeState(records.slice(-MAX_RECORDS));

    return { looping: count >= threshold, count };
  } catch {
    // Fail-open: if we can't read/write loop state (mocked fs, permissions,
    // missing directory), skip loop detection rather than blocking the tool call.
    return { looping: false, count: 0 };
  }
}

/** Deletes the loop state file. Exported for testing. */
export function resetLoopState(): void {
  try {
    fs.unlinkSync(loopStateFile());
  } catch {
    // File may not exist — that's fine
  }
}
