// src/daemon/taint-store.ts
// In-memory taint store: tracks files that contain sensitive data so that
// later operations (uploads, copies) can be escalated automatically.
//
// Taint lifetime is daemon-lifetime — records are lost on daemon restart.
// That is intentional: files are unlikely to still hold secrets after a
// restart, and persisting taint to disk creates its own privacy risk.

import fs from 'fs';
import path from 'path';

export interface TaintRecord {
  path: string; // absolute resolved path
  source: string; // e.g. "DLP:AnthropicApiKey", "DLP:GitHubToken"
  createdAt: number;
  expiresAt: number;
}

const DEFAULT_TTL_MS = 60 * 60 * 1000; // 1 hour

export class TaintStore {
  private records = new Map<string, TaintRecord>();

  /** Add or refresh taint on an absolute path. */
  taint(filePath: string, source: string, ttlMs = DEFAULT_TTL_MS): void {
    const resolved = this._resolve(filePath);
    const now = Date.now();
    this.records.set(resolved, {
      path: resolved,
      source,
      createdAt: now,
      expiresAt: now + ttlMs,
    });
  }

  /**
   * Check whether a path is currently tainted.
   * Returns the TaintRecord if tainted (and not expired), null otherwise.
   * Expired records are pruned on access.
   */
  check(filePath: string): TaintRecord | null {
    const resolved = this._resolve(filePath);
    const record = this.records.get(resolved);
    if (!record) return null;
    if (Date.now() > record.expiresAt) {
      this.records.delete(resolved);
      return null;
    }
    return record;
  }

  /**
   * Propagate taint from sourcePath to destPath (e.g. cp, mv).
   * For mv semantics (clearSource=true) the source taint is removed.
   */
  propagate(sourcePath: string, destPath: string, clearSource = false): void {
    const taintRecord = this.check(sourcePath);
    if (!taintRecord) return;
    const remainingMs = taintRecord.expiresAt - Date.now();
    if (remainingMs > 0) {
      // Strip any existing "propagated:" prefix so chained copies don't
      // produce "propagated:propagated:..." — one level of prefix is enough.
      const baseSource = taintRecord.source.replace(/^(propagated:)+/, '');
      this.taint(destPath, `propagated:${baseSource}`, remainingMs);
    }
    if (clearSource) {
      this.records.delete(this._resolve(sourcePath));
    }
  }

  /** Remove all expired records. Called periodically by the daemon. */
  prune(): void {
    const now = Date.now();
    for (const [key, record] of this.records) {
      if (now > record.expiresAt) this.records.delete(key);
    }
  }

  /** Return all non-expired taint records (for audit/debug). */
  list(): TaintRecord[] {
    this.prune();
    return [...this.records.values()];
  }

  /** Remove all taint records atomically. Used by tests to reset state between runs. */
  clear(): void {
    this.records.clear();
  }

  /** Resolve to absolute path, falling back to path.resolve if file doesn't exist yet. */
  private _resolve(filePath: string): string {
    try {
      return fs.realpathSync.native(path.resolve(filePath));
    } catch {
      return path.resolve(filePath);
    }
  }
}

// ── Session taint (gap1 — tool-output enforcement) ──────────────────────────
// A SESSION-scoped taint, distinct from the path-keyed TaintStore above. When a
// tool's OUTPUT is flagged (a secret surfaced, or — later — an injected
// instruction), node9 can't always redact it (Claude/Codex post-tool hooks are
// observe-only), so it taints the whole session: the next high-risk tool call
// (network/write) is routed to human review until the taint expires. Keyed by
// the agent's session id; per-session TTL, auto-expires (deliberately short —
// the risk is "this session just saw something poisoned", not a durable fact).

export interface SessionTaintRecord {
  sessionId: string;
  source: string; // e.g. "output-secret:GitHubToken"
  createdAt: number;
  expiresAt: number;
}

const SESSION_TAINT_TTL_MS = 30 * 60 * 1000; // 30 min — roughly one working session

export class SessionTaintStore {
  private records = new Map<string, SessionTaintRecord>();

  /** Taint a session (or refresh an existing taint). No-op on an empty id. */
  taint(sessionId: string, source: string, ttlMs = SESSION_TAINT_TTL_MS): void {
    if (!sessionId) return;
    const now = Date.now();
    this.records.set(sessionId, {
      sessionId,
      source,
      createdAt: now,
      expiresAt: now + ttlMs,
    });
  }

  /** Return the taint record if the session is currently tainted, else null.
   *  Expired records are pruned on access. */
  check(sessionId: string): SessionTaintRecord | null {
    if (!sessionId) return null;
    const record = this.records.get(sessionId);
    if (!record) return null;
    if (Date.now() > record.expiresAt) {
      this.records.delete(sessionId);
      return null;
    }
    return record;
  }

  /** Clear a session's taint (e.g. the user resolved it). */
  clearSession(sessionId: string): void {
    this.records.delete(sessionId);
  }

  /** Remove all expired records. Called periodically by the daemon. */
  prune(): void {
    const now = Date.now();
    for (const [key, record] of this.records) {
      if (now > record.expiresAt) this.records.delete(key);
    }
  }

  /** Remove all records. Used by tests to reset state between runs. */
  clear(): void {
    this.records.clear();
  }
}
