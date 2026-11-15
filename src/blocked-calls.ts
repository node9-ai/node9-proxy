// src/blocked-calls.ts
// Proof that a block held (enforcement-proof-design.md, node9Firewall#461).
// When the before-run hook delivers a block (check.ts `sendBlock`), a marker
// for that call is noted here. A blocked call does not run, so its after-run
// hook never fires; when one does fire for a marked call (log.ts), the agent
// ran a call node9 blocked, and log.ts writes a `ran-after-block` audit row.
// On 2026-11-10 this is what 34 of 40 Codex blocks on one machine did
// (node9Firewall#473): the decision was right and its delivery was ignored.
//
// One file per call under ~/.node9/blocked-calls/, named by a hash of the
// call's key: hooks of parallel tool calls never rewrite each other's marker,
// and the after-run hook claims a marker by removing its file, so two hooks
// for one call write one row. Every operation is best-effort and MUST NOT
// throw into a hook path: losing a marker loses the proof, never the block.
import { createHash } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Resolved at call time so HOME and the test seam take effect in a hook
// subprocess. Production always uses ~/.node9/blocked-calls.
function storeDir(): string {
  return process.env.NODE9_BLOCKED_CALLS_DIR || path.join(os.homedir(), '.node9', 'blocked-calls');
}

/** A blocked call that runs, runs at once; a day covers the longest tool run
 *  between the block and the after-run event. */
export const BLOCKED_CALL_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 500;

/**
 * Agents whose hooks fire no after-run event for a call the before-run hook
 * blocked, verified: Claude Code (PostToolUse follows a completed tool) and
 * Codex (the 6 of 40 blocks that held on 2026-11-10 left no after-run row).
 * For any other agent an after-run event is not evidence that a call ran,
 * and a false "ran after a block" costs more than a missing one.
 */
const AFTER_RUN_VERIFIED_AGENTS: ReadonlySet<string> = new Set(['Claude Code', 'Codex']);

export interface BlockedCall {
  key: string;
  tool: string;
  agent?: string;
  sessionId?: string;
  /** The catalog check and the rule behind the block, for the audit row. */
  checkId?: string;
  ruleName?: string;
  /** The block's own row is a test call's and stays on the machine; so does
   *  the row written for a run of this call. */
  testRun?: boolean;
  ts: number;
}

/**
 * The per-call id both hook payloads of one call carry, within its session.
 * The session is part of the key: a model provider that numbers calls from
 * zero would otherwise match a block in one session to a call in another.
 */
function callKey(payload: Record<string, unknown>): string | null {
  if (typeof payload.tool_use_id !== 'string' || !payload.tool_use_id) return null;
  const session = typeof payload.session_id === 'string' ? payload.session_id : '';
  return `tuid:${session}|${payload.tool_use_id}`;
}

/**
 * The key a block is noted under, or null when this call is not tracked.
 * Only a per-call id qualifies: a (session, tool, args hash) key also matches
 * a later identical command that was allowed.
 */
export function blockedCallKey(
  payload: Record<string, unknown>,
  agent: string | undefined
): string | null {
  if (!agent || !AFTER_RUN_VERIFIED_AGENTS.has(agent)) return null;
  return callKey(payload);
}

/** A hash, so nothing an agent wrote into its call id reaches a file name. */
function fileOf(key: string): string {
  return path.join(storeDir(), `${createHash('sha256').update(key).digest('hex')}.json`);
}

/** Removes expired markers and, past the cap, the oldest. Run on a block
 *  only: a rare event, and the after-run hook never lists the directory. */
function sweep(now: number): void {
  try {
    const dir = storeDir();
    const live: Array<{ file: string; mtime: number }> = [];
    for (const name of fs.readdirSync(dir)) {
      const file = path.join(dir, name);
      let mtime: number;
      try {
        mtime = fs.statSync(file).mtimeMs;
      } catch {
        continue;
      }
      // A marker past its day, or a temporary file a crashed hook left.
      if (now - mtime >= BLOCKED_CALL_TTL_MS || (!name.endsWith('.json') && now - mtime > 60_000))
        fs.rmSync(file, { force: true });
      else if (name.endsWith('.json')) live.push({ file, mtime });
    }
    live.sort((a, b) => a.mtime - b.mtime);
    for (const old of live.slice(0, Math.max(0, live.length - MAX_ENTRIES)))
      fs.rmSync(old.file, { force: true });
  } catch {
    /* best-effort */
  }
}

/** Note that node9 delivered a block for this call. */
export function noteBlockedCall(entry: BlockedCall): void {
  try {
    const dir = storeDir();
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = fileOf(entry.key);
    // tmp + rename: the after-run hook never reads a half-written marker.
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(entry), { mode: 0o600 });
    fs.renameSync(tmp, file);
    fs.utimesSync(file, entry.ts / 1000, entry.ts / 1000);
    sweep(entry.ts);
  } catch {
    /* never affect the block */
  }
}

/**
 * The after-run event of a call: its block marker, claimed, or null when the
 * call was never blocked (the ordinary case, one failed stat). Claiming is
 * the removal of the file: of two after-run hooks for one call, one gets the
 * marker. No agent check here: a marker exists only for an agent
 * `blockedCallKey` accepted.
 */
export function resolveBlockedCall(
  payload: Record<string, unknown>,
  now: number = Date.now()
): BlockedCall | null {
  try {
    const key = callKey(payload);
    if (!key) return null;
    const file = fileOf(key);
    if (!fs.existsSync(file)) return null;
    const parsed = JSON.parse(fs.readFileSync(file, 'utf-8')) as Partial<BlockedCall> | null;
    fs.unlinkSync(file); // throws when another hook claimed it first
    if (!parsed || parsed.key !== key || typeof parsed.ts !== 'number') return null;
    if (now - parsed.ts >= BLOCKED_CALL_TTL_MS) return null;
    return {
      key,
      tool: typeof parsed.tool === 'string' ? parsed.tool : 'unknown',
      ...(typeof parsed.agent === 'string' && { agent: parsed.agent }),
      ...(typeof parsed.sessionId === 'string' && { sessionId: parsed.sessionId }),
      ...(typeof parsed.checkId === 'string' && { checkId: parsed.checkId }),
      ...(typeof parsed.ruleName === 'string' && { ruleName: parsed.ruleName }),
      ...(parsed.testRun === true && { testRun: true }),
      ts: parsed.ts,
    };
  } catch {
    return null;
  }
}
