// src/daemon/written-store.ts
// Files an agent session wrote, by absolute path. The hook records a write
// (Write, Edit, a shell redirect, tee, cp) before it happens and asks, when a
// later command runs a script by path, whether the session wrote that file;
// if so the script's content is judged by the same shell checks as a typed
// command (fw#372 A3). The fact of writing, not a detection: a sibling of
// the session exposure store.
//
// Daemon-lifetime, in memory, like taint: lost on a restart, which only
// means a script written before the restart is run unexamined, as every
// script was before this store existed.

import path from 'path';

/** Four hours, refreshed on every write: a long session keeps its record. */
export const SESSION_WRITE_TTL_MS = 4 * 60 * 60 * 1000;
/** Entries kept at once; the oldest goes when a new one would exceed it. */
export const MAX_WRITTEN = 5000;
const MAX_PATH = 4096;

export class SessionWriteStore {
  private records = new Map<string, number>();

  private key(p: string): string | null {
    if (typeof p !== 'string' || !p || p.length > MAX_PATH) return null;
    return path.resolve(p);
  }

  /** Record that these absolute paths were (or are about to be) written. */
  record(paths: readonly string[], ttlMs = SESSION_WRITE_TTL_MS): void {
    const now = Date.now();
    for (const p of paths) {
      const k = this.key(p);
      if (k === null) continue;
      this.records.delete(k);
      this.records.set(k, now + ttlMs);
      while (this.records.size > MAX_WRITTEN) {
        const oldest = this.records.keys().next().value;
        if (oldest === undefined) break;
        this.records.delete(oldest);
      }
    }
  }

  /** The subset of `paths` the session wrote and whose record is live. */
  check(paths: readonly string[]): string[] {
    const now = Date.now();
    const out: string[] = [];
    for (const p of paths) {
      const k = this.key(p);
      if (k === null) continue;
      const expires = this.records.get(k);
      if (expires === undefined) continue;
      if (now > expires) {
        this.records.delete(k);
        continue;
      }
      out.push(k);
    }
    return out;
  }

  /** Remove expired records. Called periodically by the daemon. */
  prune(): void {
    const now = Date.now();
    for (const [k, expires] of this.records) if (now > expires) this.records.delete(k);
  }

  size(): number {
    return this.records.size;
  }

  clear(): void {
    this.records.clear();
  }
}
