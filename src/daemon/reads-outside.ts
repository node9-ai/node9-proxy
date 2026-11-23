// Reads outside the project, collected for the heartbeat (cases-session
// stage 2, change 6).
//
// The audit shipper sees each post-hook row the log hook marked with
// `readOutside` and notes it here; the heartbeat takes what is pending and
// sends it. Held in memory only: a daemon restart before the next beat loses
// at most one interval of reads, never a row or a count.

/** Mirrors the cloud heartbeat schema (be heartbeat.schema.ts). */
export const READS_OUTSIDE_MAX_SESSIONS = 100;
export const READS_OUTSIDE_MAX_PATHS = 50;
const MAX_PATH = 256;
const SESSION_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
/** Past this many pending sessions new ones are dropped until a beat drains
 *  them: memory stays bounded however long the cloud is unreachable. */
const MAX_PENDING_SESSIONS = 500;
/** Per session, in either map. */
const MAX_SESSION_PATHS = 1000;

export interface SessionReads {
  sessionId: string;
  paths: string[];
}

const pending = new Map<string, Set<string>>();
/** Paths already sent per session, so a re-read is not resent every beat.
 *  Bounded like `pending`; cleared wholesale when it grows past the cap. */
const sent = new Map<string, Set<string>>();

export function noteReadOutside(sessionId: unknown, readPath: unknown): void {
  if (typeof sessionId !== 'string' || !SESSION_ID_RE.test(sessionId)) return;
  if (typeof readPath !== 'string' || !readPath || readPath.length > MAX_PATH) return;
  if (sent.get(sessionId)?.has(readPath)) return;
  let set = pending.get(sessionId);
  if (!set) {
    if (pending.size >= MAX_PENDING_SESSIONS) return;
    set = new Set();
    pending.set(sessionId, set);
  }
  if (set.size < MAX_SESSION_PATHS) set.add(readPath);
}

/** Up to one beat's worth of pending reads, removed from the queue. What does
 *  not fit stays for the next beat. */
export function takeReadsOutside(): SessionReads[] {
  const out: SessionReads[] = [];
  for (const [sessionId, set] of pending) {
    if (out.length >= READS_OUTSIDE_MAX_SESSIONS) break;
    const paths = [...set].slice(0, READS_OUTSIDE_MAX_PATHS);
    for (const p of paths) set.delete(p);
    if (set.size === 0) pending.delete(sessionId);
    out.push({ sessionId, paths });
  }
  return out;
}

/** The beat carrying these reads was delivered: do not send them again. */
export function markReadsOutsideSent(reads: SessionReads[]): void {
  if (sent.size >= MAX_PENDING_SESSIONS) sent.clear();
  for (const { sessionId, paths } of reads) {
    let set = sent.get(sessionId);
    if (!set) sent.set(sessionId, (set = new Set()));
    for (const p of paths) if (set.size < MAX_SESSION_PATHS) set.add(p);
  }
}

/** The beat failed: put the reads back for the next one. */
export function restoreReadsOutside(reads: SessionReads[]): void {
  for (const { sessionId, paths } of reads) for (const p of paths) noteReadOutside(sessionId, p);
}

/** Test seam. */
export function _resetReadsOutside(): void {
  pending.clear();
  sent.clear();
}
