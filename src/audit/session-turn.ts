// src/audit/session-turn.ts
// The turn a session is in: how many prompts it had received when a call was
// made. The prompt hook counts, every audit row carries the number, and the
// dashboard groups a long session into one chapter per prompt.
//
// A number and nothing else. The prompt's text is never read here, never
// written and never sent: what a chapter says comes from what the calls did.
//
// One small file per session under ~/.node9/session-turns, named by a hash of
// the session id (the exposure marker's pattern). Best-effort on both sides:
// a session whose agent has no prompt hook has no file, and its rows carry no
// turn.
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { forecastRun } from '../auth/forecast-context';

/** The count stops here; the cloud accepts up to this. */
export const MAX_TURN = 100000;
/** A session can pause for days and go on: its count must still be there. */
const KEEP_MS = 30 * 24 * 60 * 60 * 1000;

function dir(): string {
  return path.join(os.homedir(), '.node9', 'session-turns');
}

function file(sessionId: string): string {
  const id = crypto.createHash('sha256').update(sessionId).digest('hex').slice(0, 32);
  return path.join(dir(), id);
}

function read(f: string): number {
  try {
    const text = fs.readFileSync(f, 'utf-8').trim();
    if (!/^\d{1,6}$/.test(text)) return 0;
    const n = Number(text);
    return n <= MAX_TURN ? n : 0;
  } catch {
    return 0;
  }
}

/** Count a prompt the session received. Best-effort, never throws. */
export function noteSessionPrompt(sessionId: string | undefined): void {
  if (!sessionId) return;
  // A forecast replays recorded calls; it starts no turn.
  if (forecastRun()) return;
  try {
    fs.mkdirSync(dir(), { recursive: true, mode: 0o700 });
    const f = file(sessionId);
    const next = Math.min(read(f) + 1, MAX_TURN);
    // Written beside the file and renamed over it, so a gate reading at the
    // same moment sees the old number or the new one, never half of one.
    const tmp = `${f}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, String(next), { mode: 0o600 });
    fs.renameSync(tmp, f);
    if (Math.random() < 0.02) {
      const cutoff = Date.now() - KEEP_MS;
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
    /* rows of this turn carry the previous number, or none */
  }
}

/** The turn the session is in, or undefined when no prompt was counted. */
export function sessionTurn(sessionId: string | undefined): number | undefined {
  if (!sessionId) return undefined;
  if (forecastRun()) return undefined;
  const n = read(file(sessionId));
  return n > 0 ? n : undefined;
}
