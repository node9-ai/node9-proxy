// src/daemon/exposure-store.ts
// Session exposure: the session READ outside content (an email, a web page,
// an issue), whether or not anything in it looked hostile. A sibling of the
// session taint in taint-store.ts, which records a DETECTION; this records
// the fact of reading. The next call that sends is judged against it: a
// destination that appeared in the content read is the strongest signal.
//
// Per agent session, in memory, like taint: lost on a daemon restart, which
// is acceptable for "this session just read something". Refreshed on every
// read; the daemon never sees a session end, so the TTL is the only clock.
// Design: docs/roadmap/active/untrusted-content-proxy-code-design.md, 4.1.

export interface ExposureSource {
  /** The tool as the hook saw it: 'WebFetch', 'mcp__gmail__get_message', 'Bash'. */
  tool: string;
  /** The MCP server's config name, when the tool is namespaced. */
  server?: string;
  /** What was read, as the prompt names it: 'email', 'web page', 'issue', 'repository'. */
  word?: string;
  /** fw#318 2b: the eid of the audit row that recorded the read, so a send
   *  held after it can name it (the session graph's edge). */
  eid?: string;
  at: number;
}

export interface SessionExposureRecord {
  sessionId: string;
  sources: ExposureSource[];
  /** Normalised destinations seen in content read: 'email:a@b.c', 'host:x.y', 'iban:..'. */
  destinations: string[];
  /** Destinations the user typed in a prompt this session. */
  userMentioned: string[];
  /** '<tool>|<destination>' keys an approval cleared (ask-once). */
  approved: string[];
  createdAt: number;
  expiresAt: number;
}

interface Entry {
  sessionId: string;
  sources: ExposureSource[];
  destinations: Set<string>;
  userMentioned: Set<string>;
  approved: Set<string>;
  createdAt: number;
  expiresAt: number;
}

/** Four hours, refreshed on every read: a long session keeps its guard; a
 *  reused id after a day does not inherit a stale record. Design 8.5. */
export const SESSION_EXPOSURE_TTL_MS = 4 * 60 * 60 * 1000;
export const MAX_SOURCES = 20;
export const MAX_VALUES = 200;
/** Sessions kept at once; the oldest record goes when a new one would exceed it. */
export const MAX_SESSIONS = 1000;
const MAX_SESSION_ID = 256;

function addCapped(set: Set<string>, values: readonly string[], cap: number): void {
  for (const v of values) {
    if (set.size >= cap) return;
    if (typeof v === 'string' && v.length > 0 && v.length <= 512) set.add(v);
  }
}

export class SessionExposureStore {
  private records = new Map<string, Entry>();

  private live(sessionId: string): Entry | null {
    if (!sessionId) return null;
    const e = this.records.get(sessionId);
    if (!e) return null;
    if (Date.now() > e.expiresAt) {
      this.records.delete(sessionId);
      return null;
    }
    return e;
  }

  private ensure(sessionId: string, ttlMs: number): Entry {
    const now = Date.now();
    let e = this.live(sessionId);
    if (!e) {
      if (this.records.size >= MAX_SESSIONS) {
        this.prune();
        if (this.records.size >= MAX_SESSIONS) {
          const oldest = this.records.keys().next().value;
          if (oldest !== undefined) this.records.delete(oldest);
        }
      }
      e = {
        sessionId,
        sources: [],
        destinations: new Set(),
        userMentioned: new Set(),
        approved: new Set(),
        createdAt: now,
        expiresAt: now + ttlMs,
      };
      this.records.set(sessionId, e);
    }
    return e;
  }

  /** The session read outside content. Merges destinations, refreshes the TTL. */
  mark(
    sessionId: string,
    source: ExposureSource,
    destinations: readonly string[] = [],
    ttlMs = SESSION_EXPOSURE_TTL_MS
  ): void {
    if (!sessionId || sessionId.length > MAX_SESSION_ID) return;
    const e = this.ensure(sessionId, ttlMs);
    e.sources.push({
      tool: source.tool,
      server: source.server,
      ...(source.word ? { word: source.word } : {}),
      ...(source.eid ? { eid: source.eid } : {}),
      at: source.at || Date.now(),
    });
    if (e.sources.length > MAX_SOURCES) e.sources.splice(0, e.sources.length - MAX_SOURCES);
    addCapped(e.destinations, destinations, MAX_VALUES);
    e.expiresAt = Date.now() + ttlMs;
  }

  /** The user named these destinations in a prompt. Does not create exposure
   *  by itself: a record is made so a later read finds the mentions, but it
   *  reports `exposed` only once a source was read. */
  mention(
    sessionId: string,
    destinations: readonly string[],
    ttlMs = SESSION_EXPOSURE_TTL_MS
  ): void {
    if (!sessionId || sessionId.length > MAX_SESSION_ID || destinations.length === 0) return;
    const e = this.ensure(sessionId, ttlMs);
    addCapped(e.userMentioned, destinations, MAX_VALUES);
  }

  /** An approval cleared these '<tool>|<destination>' keys (ask-once). */
  approve(sessionId: string, keys: readonly string[]): boolean {
    const e = this.live(sessionId);
    if (!e) return false;
    addCapped(e.approved, keys, MAX_VALUES);
    return true;
  }

  /** The record when the session read at least one source, else null. */
  check(sessionId: string): SessionExposureRecord | null {
    const e = this.live(sessionId);
    if (!e || e.sources.length === 0) return null;
    return toRecord(e);
  }

  clearSession(sessionId: string): boolean {
    return this.records.delete(sessionId);
  }

  list(): SessionExposureRecord[] {
    this.prune();
    return [...this.records.values()].filter((e) => e.sources.length > 0).map(toRecord);
  }

  prune(): void {
    const now = Date.now();
    for (const [key, e] of this.records) if (now > e.expiresAt) this.records.delete(key);
  }

  clear(): void {
    this.records.clear();
  }
}

function toRecord(e: Entry): SessionExposureRecord {
  return {
    sessionId: e.sessionId,
    sources: [...e.sources],
    destinations: [...e.destinations],
    userMentioned: [...e.userMentioned],
    approved: [...e.approved],
    createdAt: e.createdAt,
    expiresAt: e.expiresAt,
  };
}
