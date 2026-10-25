// src/exposure/marker.ts
// A per-session marker file that says "this session may be exposed" (fw#318,
// review finding 8). The daemon's SessionExposureStore stays the record; the
// marker only lets the hot path (every file edit, every redirected command)
// skip the daemon round trip in a session that never read outside content.
//
// Written by whoever marks exposure (the PostToolUse hook, the gateway);
// checked before calls whose only reason to be judged is a write or a plain
// fetch. A missing marker means "not exposed": the same fail-open the daemon
// check has when the daemon is down. A stale marker (daemon restarted, record
// gone) only costs one round trip that answers "not exposed".
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SESSION_EXPOSURE_TTL_MS } from '../daemon/exposure-store';
import { forecastRun } from '../auth/forecast-context';

function dir(): string {
  return path.join(os.homedir(), '.node9', 'exposure-sessions');
}

function file(sessionId: string): string {
  const id = crypto.createHash('sha256').update(sessionId).digest('hex').slice(0, 32);
  return path.join(dir(), id);
}

/** Note that `sessionId` read outside content. Best-effort, never throws. */
export function markSessionExposed(sessionId: string): void {
  if (!sessionId) return;
  // The replayed state is the record in a forecast; no marker file.
  if (forecastRun()) return;
  try {
    fs.mkdirSync(dir(), { recursive: true, mode: 0o700 });
    const f = file(sessionId);
    const now = new Date();
    try {
      fs.utimesSync(f, now, now);
    } catch {
      fs.writeFileSync(f, '', { mode: 0o600 });
    }
    // Opportunistic cleanup: markers older than a day are noise.
    if (Math.random() < 0.05) {
      const cutoff = Date.now() - 24 * 60 * 60 * 1000;
      for (const name of fs.readdirSync(dir())) {
        try {
          const p = path.join(dir(), name);
          if (fs.statSync(p).mtimeMs < cutoff) fs.unlinkSync(p);
        } catch {
          /* raced with another hook */
        }
      }
    }
  } catch {
    /* the daemon record is the truth; a missing marker only fails open */
  }
}

/**
 * May `sessionId` be exposed? False only when no marker exists or it is older
 * than the exposure TTL. Any error answers true (ask the daemon).
 */
export function maybeSessionExposed(sessionId: string): boolean {
  if (!sessionId) return false;
  const forecast = forecastRun();
  if (forecast) return forecast.session.checkExposure(forecast.now) !== null;
  try {
    const st = fs.statSync(file(sessionId));
    return Date.now() - st.mtimeMs < SESSION_EXPOSURE_TTL_MS;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== 'ENOENT';
  }
}

export function clearSessionMarkers(sessionId?: string): void {
  try {
    if (sessionId) fs.unlinkSync(file(sessionId));
    else fs.rmSync(dir(), { recursive: true, force: true });
  } catch {
    /* nothing to clear */
  }
}
