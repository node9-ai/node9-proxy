// src/loop-detector.ts
// Agent Loop / Runaway Detection — host wrapper around @node9/policy-engine's
// pure window math. This file owns the loop-state file: read on entry, write
// on exit. Threshold/window math + arg hashing live in the engine.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { evaluateLoopWindow, type ToolCallRecord } from '@node9/policy-engine';

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
export function resetLoopState(): void {
  try {
    fs.unlinkSync(loopStateFile());
  } catch {
    // File may not exist — that's fine
  }
}
