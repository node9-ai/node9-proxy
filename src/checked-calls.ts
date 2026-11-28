// src/checked-calls.ts
// Proof that the before-run hook finished for a call (node9Firewall#383,
// phase 3).
//
// `hook-error.ts` records a check that failed inside node9. This file is for
// the check that never came back at all: the agent's host killed the hook at
// its timeout, the process died without running a line of the error path, or
// no before-run hook is registered. The host then runs the call, and nothing
// node9 wrote says so.
//
// The evidence is a journal under ~/.node9/checked-calls/. `check` appends
// one line for a call when its process exits in an orderly way, whatever the
// verdict; a process the host kills never reaches that line. When the
// after-run hook fires for a call that has no line, the call ran without a
// before-run verdict, and `log` writes one `hook-error` audit row for it.
//
// A line is a short hash of the call's key, never the key or an argument.
// Noting a call is one stat and one small append; looking one up reads the
// tail of the journal. Every operation is best-effort and MUST NOT throw into
// a hook path.
import { createHash } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { blockedCallKey } from './blocked-calls';

// Resolved at call time so HOME takes effect in a hook subprocess.
function storeDir(): string {
  return path.join(os.homedir(), '.node9', 'checked-calls');
}
const CURRENT = 'current.log';
/** The journal before the last rotation. A hook that was appending while the
 *  file was renamed wrote here, so a lookup reads both. */
const PREVIOUS = 'previous.log';
/** When this machine began keeping the journal, in ms. Written once. */
const SINCE = 'since';

/** 16 hex characters and a newline. */
const LINE_BYTES = 17;
/** Start a new journal past this size: about 120,000 calls. */
const ROTATE_BYTES = 2 * 1024 * 1024;
/** The first read of a lookup: the last 3,800 calls, which is nearly always
 *  enough. The whole of both files is read only when that misses. */
const FIRST_READ_BYTES = 64 * 1024;

/**
 * A call is only reported when the journal is older than this. The before-run
 * hook of a call that was already running when node9 was installed or
 * upgraded wrote no line; without the wait, its after-run hook would report a
 * check that did run. Longer than the hook timeout plus a long call.
 */
export const JOURNAL_SETTLE_MS = 60 * 60 * 1000;

function lineOf(key: string): string {
  return createHash('sha256')
    .update(key)
    .digest('hex')
    .slice(0, LINE_BYTES - 1);
}

/**
 * The journal key of a call, or null when the call is not tracked: the same
 * per-call id and the same agents as a blocked call (blocked-calls.ts), since
 * both rest on the after-run event meaning "this call ran".
 */
export function checkedCallKey(
  payload: Record<string, unknown>,
  agent: string | undefined
): string | null {
  return blockedCallKey(payload, agent);
}

/**
 * The agents a missing note is reported for. It takes more than a note being
 * written: the agent must run its before-run hook for every call whose
 * after-run hook it runs, or a healthy machine reports calls that were never
 * handed to node9. Measured for Claude Code on two weeks of real use
 * (2026-11-14 to 2026-11-28): 15,539 calls that ran, 2 without an earlier
 * before-run payload. Not measured for Codex, whose calls are noted so the
 * journal is ready, and not reported: a false "not checked" costs more than a
 * missing one.
 */
const NO_VERDICT_REPORTED_AGENTS: ReadonlySet<string> = new Set(['Claude Code']);

/** The key to look a call up under when its after-run hook fires, or null
 *  when a missing note must not be reported for this agent. */
export function reportableCallKey(
  payload: Record<string, unknown>,
  agent: string | undefined
): string | null {
  if (!agent || !NO_VERDICT_REPORTED_AGENTS.has(agent)) return null;
  return checkedCallKey(payload, agent);
}

/**
 * Note that the before-run hook finished for this call. Runs in `check`'s
 * exit handler: synchronous, and never throws.
 */
export function noteCheckedCall(key: string, now: number = Date.now()): void {
  try {
    const dir = storeDir();
    const current = path.join(dir, CURRENT);
    let size = -1;
    try {
      size = fs.statSync(current).size;
    } catch {
      /* no journal yet */
    }
    if (size < 0) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      // `wx`: the first hook ever writes the start time, later ones keep it.
      try {
        fs.writeFileSync(path.join(dir, SINCE), String(now), { mode: 0o600, flag: 'wx' });
      } catch {
        /* already there */
      }
    } else if (size > ROTATE_BYTES) {
      // A rename, so no line is lost: a hook appending right now writes to
      // the same file under its new name.
      try {
        fs.renameSync(current, path.join(dir, PREVIOUS));
      } catch {
        /* another hook rotated first */
      }
    }
    fs.appendFileSync(current, lineOf(key) + '\n', { mode: 0o600 });
  } catch {
    /* a lost line can only cost a false report, never a verdict */
  }
}

/** Whether the last `bytes` of a journal file (all of it when undefined)
 *  hold the line. A missing file holds nothing. */
function fileHasLine(file: string, want: string, bytes?: number): boolean {
  let fd: number;
  try {
    fd = fs.openSync(file, 'r');
  } catch {
    return false;
  }
  try {
    const size = fs.fstatSync(fd).size;
    const length = bytes === undefined ? size : Math.min(size, bytes);
    const buf = Buffer.alloc(length);
    fs.readSync(fd, buf, 0, length, size - length);
    const text = buf.toString('latin1');
    // A whole line: at the start of what was read, or after a newline.
    return text.startsWith(want + '\n') || text.includes('\n' + want + '\n');
  } finally {
    fs.closeSync(fd);
  }
}

export type CheckedState =
  /** The before-run hook finished for this call. */
  | 'checked'
  /** It did not: the call ran with no before-run verdict. */
  | 'unchecked'
  /** Not known: no journal, a young one, or one that cannot be read. */
  | 'unknown';

/** Whether the before-run hook finished for this call. Never throws. */
export function checkedCallState(key: string, now: number = Date.now()): CheckedState {
  try {
    const dir = storeDir();
    const current = path.join(dir, CURRENT);
    const want = lineOf(key);
    if (fileHasLine(current, want, FIRST_READ_BYTES)) return 'checked';
    const since = Number(fs.readFileSync(path.join(dir, SINCE), 'utf-8'));
    // Too young to speak for a call that may have started before it existed.
    if (!Number.isFinite(since) || since <= 0 || now - since < JOURNAL_SETTLE_MS) return 'unknown';
    if (fileHasLine(current, want) || fileHasLine(path.join(dir, PREVIOUS), want)) return 'checked';
    return 'unchecked';
  } catch {
    return 'unknown';
  }
}
