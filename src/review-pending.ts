// src/review-pending.ts
// Outcome capture for inline-ask reviews (phase 4). When a `review` verdict is
// deferred to an agent's inline prompt (check.ts `sendAsk`), a pending marker is
// recorded here; when the tool later executes (log.ts PostToolUse), the marker
// resolves -> the user APPROVED. Denials are unobservable (no hook fires when a
// tool is declined), so unresolved markers are pruned by TTL / cap rather than
// recorded. Every operation is best-effort and MUST NOT throw into a hook path.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { hashArgs } from './audit/hasher';

// Resolved at call time (not a module const) so HOME / the test override take
// effect, and so subprocess hooks pick up the right home. NODE9_PENDING_STORE is
// a test seam; production always uses ~/.node9/pending-reviews.json.
function storePath(): string {
  return (
    process.env.NODE9_PENDING_STORE || path.join(os.homedir(), '.node9', 'pending-reviews.json')
  );
}
const TTL_MS = 6 * 60 * 60 * 1000; // 6h — a review older than this is treated as abandoned
const MAX_ENTRIES = 500; // hard cap so the file can't grow unbounded without a deny-sweep

export interface PendingReview {
  key: string;
  agent?: string;
  tool: string;
  sessionId?: string;
  ts: number;
  label?: string;
}

interface Store {
  entries: PendingReview[];
}

/**
 * Correlation key shared by the Pre (check.ts) and Post (log.ts) sides — derived
 * purely from the hook payload so both sides compute the identical value.
 *   - Claude Code: per-tool-call `tool_use_id` (verified present + identical Pre/Post).
 *   - Others (GitHub Copilot): heuristic `session_id | tool_name | hashArgs(tool_input)`
 *     (Pre/Post share all three; same command twice in a session is the known edge).
 * Returns null when the payload can't be correlated (capture is then a no-op).
 */
export function reviewCorrelationKey(payload: Record<string, unknown>): string | null {
  if (typeof payload.tool_use_id === 'string' && payload.tool_use_id) {
    return `tuid:${payload.tool_use_id}`;
  }
  const sid = payload.session_id ?? payload.conversationId;
  const tool = payload.tool_name;
  if (typeof sid === 'string' && sid && typeof tool === 'string' && tool) {
    return `h:${sid}|${tool}|${hashArgs(payload.tool_input)}`;
  }
  return null;
}

function read(): Store {
  try {
    const parsed = JSON.parse(fs.readFileSync(storePath(), 'utf-8'));
    if (parsed && Array.isArray(parsed.entries)) return parsed as Store;
  } catch {
    /* missing / corrupt → empty */
  }
  return { entries: [] };
}

function write(store: Store): void {
  try {
    const p = storePath();
    const dir = path.dirname(p);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    // tmp + rename = atomic replace (concurrent hooks can't observe a half-written file).
    const tmp = `${p}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(store));
    fs.renameSync(tmp, p);
  } catch {
    /* best-effort */
  }
}

/** Drop expired entries, then cap to the most-recent MAX_ENTRIES. */
function prune(entries: PendingReview[], now: number): PendingReview[] {
  const fresh = entries.filter((e) => now - e.ts < TTL_MS);
  return fresh.length > MAX_ENTRIES ? fresh.slice(fresh.length - MAX_ENTRIES) : fresh;
}

/** Record a deferred review awaiting the agent's inline approve/deny. */
export function recordPendingReview(entry: PendingReview): void {
  try {
    const store = read();
    store.entries = prune(store.entries, entry.ts);
    store.entries.push(entry);
    write(store);
  } catch {
    /* never block the ask emit */
  }
}

/**
 * Find + remove the OLDEST entry with this key (FIFO — deterministic for the
 * Copilot "same command twice" edge). Returns the entry (→ approved) or null (miss).
 * Prunes on every call so the store can't grow without a deny-sweep.
 */
export function resolvePendingReview(key: string, now: number = Date.now()): PendingReview | null {
  try {
    const store = read();
    const idx = store.entries.findIndex((e) => e.key === key);
    if (idx === -1) {
      const pruned = prune(store.entries, now);
      if (pruned.length !== store.entries.length) write({ entries: pruned });
      return null;
    }
    const [match] = store.entries.splice(idx, 1);
    write({ entries: prune(store.entries, now) });
    return match;
  } catch {
    return null;
  }
}
