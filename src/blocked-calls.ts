// src/blocked-calls.ts
// Proof that a block held (enforcement-proof-design.md, node9Firewall#461).
// When the before-run hook delivers a block (check.ts `sendBlock`), a marker
// for that call is noted here. A blocked call does not run, so its after-run
// hook never fires; when one does fire for a marked call (log.ts), the agent
// ran a call node9 blocked, and log.ts writes a `ran-after-block` audit row.
// On 2026-11-10 this is what 34 of 40 Codex blocks on one machine did
// (node9Firewall#473): the decision was right and its delivery was ignored.
//
// Every operation is best-effort and MUST NOT throw into a hook path: losing
// a marker loses the proof, never the block.
import fs from 'fs';
import os from 'os';
import path from 'path';

// Resolved at call time so HOME and the test seam take effect in a hook
// subprocess. Production always uses ~/.node9/blocked-calls.json.
function storePath(): string {
  return (
    process.env.NODE9_BLOCKED_CALLS_STORE || path.join(os.homedir(), '.node9', 'blocked-calls.json')
  );
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
  /** The block matched a credential or personal data in the arguments: the
   *  row written for a run of this call must not carry them. */
  sensitive?: boolean;
  ts: number;
}

interface Store {
  entries: BlockedCall[];
}

/** The per-call id both hook payloads of one call carry, as a store key. */
function callKey(payload: Record<string, unknown>): string | null {
  return typeof payload.tool_use_id === 'string' && payload.tool_use_id
    ? `tuid:${payload.tool_use_id}`
    : null;
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

function read(): Store {
  try {
    const parsed = JSON.parse(fs.readFileSync(storePath(), 'utf-8')) as Partial<Store> | null;
    if (parsed && Array.isArray(parsed.entries)) {
      return {
        entries: parsed.entries.filter(
          (e) => !!e && typeof e.key === 'string' && typeof e.ts === 'number'
        ),
      };
    }
  } catch {
    /* missing or corrupt: empty */
  }
  return { entries: [] };
}

function write(store: Store): void {
  try {
    const p = storePath();
    if (store.entries.length === 0) {
      fs.rmSync(p, { force: true });
      return;
    }
    fs.mkdirSync(path.dirname(p), { recursive: true });
    // tmp + rename: a concurrent hook never reads a half-written file.
    const tmp = `${p}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(store), { mode: 0o600 });
    fs.renameSync(tmp, p);
  } catch {
    /* best-effort */
  }
}

function prune(entries: BlockedCall[], now: number): BlockedCall[] {
  const fresh = entries.filter((e) => now - e.ts < BLOCKED_CALL_TTL_MS);
  return fresh.length > MAX_ENTRIES ? fresh.slice(fresh.length - MAX_ENTRIES) : fresh;
}

/** Note that node9 delivered a block for this call. */
export function noteBlockedCall(entry: BlockedCall): void {
  try {
    const store = read();
    write({ entries: prune([...store.entries, entry], entry.ts) });
  } catch {
    /* never affect the block */
  }
}

/**
 * The after-run event of a call: its block marker, removed, or null when the
 * call was never blocked (the ordinary case). No agent check here: a marker
 * exists only for an agent `blockedCallKey` accepted. With no store on disk
 * this is one failed stat and no write.
 */
export function resolveBlockedCall(
  payload: Record<string, unknown>,
  now: number = Date.now()
): BlockedCall | null {
  try {
    const key = callKey(payload);
    if (!key || !fs.existsSync(storePath())) return null;
    const store = read();
    const live = prune(store.entries, now);
    const match = live.find((e) => e.key === key) ?? null;
    const kept = match ? live.filter((e) => e.key !== key) : live;
    if (kept.length !== store.entries.length) write({ entries: kept });
    return match;
  } catch {
    return null;
  }
}
