// src/loop-detector.ts
// Agent Loop / Runaway Detection — host wrapper around @node9/policy-engine's
// pure window math. This file owns the loop-state file: read on entry, write
// on exit. Threshold/window math + arg hashing live in the engine.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { evaluateLoopWindow, type ToolCallRecord } from '@node9/policy-engine';
import { forecastRun } from './auth/forecast-context';

export { computeArgsHash } from '@node9/policy-engine';

/** Evaluated lazily so tests can override HOME/USERPROFILE between calls. */
function loopStateFile(): string {
  return path.join(os.homedir(), '.node9', 'loop-state.json');
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
    // A forecast keeps the window in the replayed session, at the call's clock.
    const forecast = forecastRun();
    if (forecast) {
      const r = evaluateLoopWindow(
        forecast.session.loopRecords,
        tool,
        args,
        threshold,
        windowMs,
        forecast.now
      );
      forecast.session.loopRecords = r.nextRecords;
      return { looping: r.looping, count: r.count };
    }
    const result = evaluateLoopWindow(readState(), tool, args, threshold, windowMs, Date.now());
    writeState(result.nextRecords);
    return { looping: result.looping, count: result.count };
  } catch {
    // Fail-open: if we can't read/write loop state (mocked fs, permissions,
    // missing directory), skip loop detection rather than blocking the tool call.
    return { looping: false, count: 0 };
  }
}

/** Deletes the loop state file. Exported for testing. */
// ── Fan-out: subagents spawned per session (behavior.fanout, node9Firewall#427)
// The same shape as the loop window, keyed by session: timestamps of the
// spawns in the last window. A forecast keeps them in the replayed session.

const FANOUT_MAX_RECORDS = 200;

function fanoutStateFile(): string {
  return path.join(os.homedir(), '.node9', 'fanout-state.json');
}

function readFanoutState(): Record<string, number[]> {
  try {
    if (!fs.existsSync(fanoutStateFile())) return {};
    const parsed: unknown = JSON.parse(fs.readFileSync(fanoutStateFile(), 'utf-8'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, number[]>)
      : {};
  } catch {
    return {};
  }
}

function writeFanoutState(state: Record<string, number[]>): void {
  const dir = path.dirname(fanoutStateFile());
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmpPath = `${fanoutStateFile()}.${os.hostname()}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(state));
  fs.renameSync(tmpPath, fanoutStateFile());
}

export interface FanoutCheckResult {
  /** Spawns in the window, this one included. */
  count: number;
  /** More than `threshold` spawns in the window. */
  over: boolean;
}

/** Record a spawn in `sessionId` and say whether the window now holds more than `threshold`. */
export function recordSpawnAndCheck(
  sessionId: string,
  threshold: number,
  windowMs: number
): FanoutCheckResult {
  const forecast = forecastRun();
  const now = forecast ? forecast.now : Date.now();
  const cutoff = now - windowMs;
  if (forecast) {
    const fresh = forecast.session.spawnRecords.filter((ts) => ts >= cutoff);
    fresh.push(now);
    forecast.session.spawnRecords = fresh.slice(-FANOUT_MAX_RECORDS);
    return { count: fresh.length, over: fresh.length > threshold };
  }
  try {
    const state = readFanoutState();
    const key = sessionId || 'no-session';
    const fresh = (Array.isArray(state[key]) ? state[key] : []).filter(
      (ts) => typeof ts === 'number' && ts >= cutoff
    );
    fresh.push(now);
    // Other sessions' records older than the window are dropped too, so the file stays small.
    const next: Record<string, number[]> = {};
    for (const [k, v] of Object.entries(state)) {
      if (k === key || !Array.isArray(v)) continue;
      const kept = v.filter((ts) => typeof ts === 'number' && ts >= cutoff);
      if (kept.length > 0) next[k] = kept;
    }
    next[key] = fresh.slice(-FANOUT_MAX_RECORDS);
    writeFanoutState(next);
    return { count: fresh.length, over: fresh.length > threshold };
  } catch {
    return { count: 1, over: false };
  }
}

export function resetLoopState(): void {
  try {
    fs.unlinkSync(loopStateFile());
  } catch {
    // File may not exist — that's fine
  }
}
