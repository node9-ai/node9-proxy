// Replayed session state for a forecast run.
//
// The live gate asks the daemon what it knows about a session: tainted files,
// a tainted session (a secret surfaced in an earlier tool output), exposure to
// outside content, files the session wrote, the loop window. In a forecast the
// daemon is never consulted (design 4.2: never consult today's daemon as
// yesterday's state). The caller that walks a transcript feeds this object in
// event order, and the daemon client answers from it.

import type { ToolCallRecord } from '@node9/policy-engine';
import type { TaintRecord, SessionTaintRecord } from '../daemon/taint-store';
import type { ExposureSource, SessionExposureRecord } from '../daemon/exposure-store';

const TAINT_TTL_MS = 60 * 60 * 1000;
const SESSION_TAINT_TTL_MS = 30 * 60 * 1000;
const EXPOSURE_TTL_MS = 4 * 60 * 60 * 1000;

export class ForecastSessionState {
  readonly sessionId: string;
  readonly taintedPaths = new Map<string, TaintRecord>();
  sessionTaint: SessionTaintRecord | null = null;
  exposure: SessionExposureRecord | null = null;
  readonly writtenFiles = new Set<string>();
  loopRecords: ToolCallRecord[] = [];
  /** True when the caller cannot feed this state (a transcript without tool
   *  results): every state-dependent layer then reports `session-state`. */
  readonly blind: boolean;

  constructor(sessionId: string, opts: { blind?: boolean } = {}) {
    this.sessionId = sessionId;
    this.blind = opts.blind === true;
  }

  // ── Feeders (what the PostToolUse hook and the daemon do on the live path) ──

  /** A secret surfaced in a tool output: the session is tainted (log.ts). */
  noteOutputSecret(patternName: string, at: number): void {
    this.sessionTaint = {
      sessionId: this.sessionId,
      source: `output-secret:${patternName}`,
      createdAt: at,
      expiresAt: at + SESSION_TAINT_TTL_MS,
    };
  }

  /** A file holds a flagged value (the DLP block on a write, `notifyTaint`). */
  taintPath(filePath: string, source: string, at: number, fromEid?: string): void {
    this.taintedPaths.set(filePath, {
      path: filePath,
      source,
      createdAt: at,
      expiresAt: at + TAINT_TTL_MS,
      ...(fromEid && { fromEid }),
    });
  }

  /** The session read outside content through `source` (log.ts exposure). */
  noteOutsideContent(source: ExposureSource, destinations: string[] = []): void {
    const at = source.at;
    if (!this.exposure) {
      this.exposure = {
        sessionId: this.sessionId,
        sources: [],
        destinations: [],
        userMentioned: [],
        approved: [],
        createdAt: at,
        expiresAt: at + EXPOSURE_TTL_MS,
      };
    }
    this.exposure.sources.push(source);
    for (const d of destinations)
      if (!this.exposure.destinations.includes(d)) this.exposure.destinations.push(d);
    this.exposure.expiresAt = at + EXPOSURE_TTL_MS;
  }

  noteWritten(paths: readonly string[]): void {
    for (const p of paths) this.writtenFiles.add(p);
  }

  // ── Answers (what the daemon would have said at `now`) ─────────────────────

  checkTaint(paths: readonly string[], now: number): TaintRecord | null {
    for (const p of paths) {
      const r = this.taintedPaths.get(p);
      if (r && r.expiresAt > now) return r;
    }
    return null;
  }

  checkSessionTaint(now: number): SessionTaintRecord | null {
    const r = this.sessionTaint;
    return r && r.expiresAt > now ? r : null;
  }

  checkExposure(now: number): SessionExposureRecord | null {
    const r = this.exposure;
    return r && r.expiresAt > now ? r : null;
  }

  approveExposure(keys: readonly string[]): void {
    if (!this.exposure) return;
    for (const k of keys) if (!this.exposure.approved.includes(k)) this.exposure.approved.push(k);
  }

  written(paths: readonly string[]): string[] {
    return paths.filter((p) => this.writtenFiles.has(p));
  }
}
