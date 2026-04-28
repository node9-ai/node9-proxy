// Pure window math for agent-loop / runaway detection.
//
// The host owns persistence (reading/writing the loop-state file). This
// module owns: hashing args, expiring records past the window cutoff,
// counting recurrence of (tool + args hash), and capping the record
// buffer so it never grows unbounded.
//
// `crypto` is a pure Node stdlib (no I/O, no env), so importing it
// keeps the engine platform-agnostic.

import crypto from 'crypto';

export interface ToolCallRecord {
  /** tool name */
  t: string;
  /** args hash (16 hex chars) */
  h: string;
  /** timestamp ms */
  ts: number;
}

/** Hard cap on how many records we keep around — prevents unbounded growth. */
export const LOOP_MAX_RECORDS = 500;

/** Stable hash of the tool args. Same input → same 16-char hex string. */
export function computeArgsHash(args: unknown): string {
  const str = JSON.stringify(args ?? '');
  return crypto.createHash('sha256').update(str).digest('hex').slice(0, 16);
}

export interface LoopWindowEvaluation {
  /** Records to persist next: existing within-window entries + the new call, capped. */
  nextRecords: ToolCallRecord[];
  /** Number of matching (tool + hash) entries inside the window after this call. */
  count: number;
  /** True when count meets or exceeds the threshold — caller should treat as a loop. */
  looping: boolean;
}

/**
 * Pure evaluation of one tool call against the current sliding-window state.
 *
 * Steps:
 *   1. Drop records older than (now - windowMs).
 *   2. Append the new call.
 *   3. Count entries matching (tool, computeArgsHash(args)).
 *   4. Return the next state (capped) plus loop verdict.
 *
 * The host wraps this with disk read/write — see node9-proxy/src/loop-detector.ts.
 */
export function evaluateLoopWindow(
  records: ToolCallRecord[],
  tool: string,
  args: unknown,
  threshold: number,
  windowMs: number,
  now: number
): LoopWindowEvaluation {
  const hash = computeArgsHash(args);
  const cutoff = now - windowMs;
  const fresh = records.filter((r) => r.ts >= cutoff);
  fresh.push({ t: tool, h: hash, ts: now });

  const count = fresh.filter((r) => r.t === tool && r.h === hash).length;
  const nextRecords = fresh.slice(-LOOP_MAX_RECORDS);
  return { nextRecords, count, looping: count >= threshold };
}
