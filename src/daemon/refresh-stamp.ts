// src/daemon/refresh-stamp.ts
// The hook's half of "a hook on a newer build refreshes an older daemon"
// (docs/roadmap/active/daemon-stale-refresh-design.md): is the running daemon
// an older build than this process, and is a refresh attempt due.
//
// Loaded by the hook bundle on every tool call, so it imports nothing beyond
// fs / os / path and build-id, and none of it may throw into the hook.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { type BuildId, compareBuild, parseBuildId } from './build-id';

/** What the daemon wrote about itself into its pid file. */
export interface PidBuild {
  buildId: string | null;
  /** The launcher the daemon runs from, links resolved; null for a daemon
   *  from before the field. */
  entry: string | null;
}

/** Never throws: an absent or unreadable pid file names nothing. */
export function readPidBuild(home: string = os.homedir()): PidBuild {
  try {
    const raw = fs.readFileSync(path.join(home, '.node9', 'daemon.pid'), 'utf-8');
    const pid = JSON.parse(raw) as { buildId?: unknown; entry?: unknown };
    return {
      buildId: typeof pid.buildId === 'string' ? pid.buildId : null,
      entry: typeof pid.entry === 'string' ? pid.entry : null,
    };
  } catch {
    return { buildId: null, entry: null };
  }
}

/**
 * Should a hook of build `mine` ask for the running daemon to be replaced.
 *
 * - A daemon of an older VERSION: yes, whichever install it runs from (the
 *   upgrade: `npm install -g`, or a newer install under another Node).
 * - The same version and an older file (a dev rebuild; npm installs all carry
 *   one fixed mtime): only when the daemon runs from this very install.
 *   Without that, `check` run from any other checkout whose dist happens to
 *   be newer would replace the user's live daemon with that checkout's code.
 *   `myEntry` is asked only in this case, so the common path pays no realpath.
 * - No build in the pid file (a daemon from before the build id, or an
 *   adopted orphan) or one that does not parse: unknown, never stale. Startup
 *   yields to such a holder too, and `doctor` reports it.
 */
export function isDaemonStale(pid: PidBuild, mine: BuildId, myEntry: () => string | null): boolean {
  const theirs = parseBuildId(pid.buildId);
  if (theirs === null || compareBuild(mine, theirs) <= 0) return false;
  const newerVersion =
    compareBuild({ version: mine.version, mtimeMs: 0 }, { version: theirs.version, mtimeMs: 0 }) >
    0;
  if (newerVersion) return true;
  return pid.entry !== null && pid.entry === myEntry();
}

/** Wait before attempt N+1 for the same installed build: 1 min, 10 min, 1 h,
 *  then a day. A refresh that cannot work (a holder that refuses /shutdown, a
 *  service unit that starts another install) must not cost a process per tool
 *  call, and through the service it would restart the daemon each time. */
export const REFRESH_BACKOFF_MS = [60_000, 10 * 60_000, 60 * 60_000];
export const REFRESH_BACKOFF_MAX_MS = 24 * 60 * 60_000;

export function refreshDelayMs(attempts: number): number {
  if (attempts <= 0) return 0;
  return REFRESH_BACKOFF_MS[attempts - 1] ?? REFRESH_BACKOFF_MAX_MS;
}

export interface RefreshStamp {
  /** The installed build the attempts were made for (buildIdString). */
  build: string;
  /** Attempts made for that build since the last success. */
  attempts: number;
  /** Epoch ms of the last attempt. The stamp's own time, never the file's mtime. */
  at: number;
  /** Why the last attempt changed nothing; `doctor` prints it. */
  reason?: string;
}

export const REFRESH_STAMP = (home: string = os.homedir()): string =>
  path.join(home, '.node9', '.daemon-refresh-stamp');

/** Null when absent, unreadable or not a stamp. Never throws. */
export function readRefreshStamp(home: string = os.homedir()): RefreshStamp | null {
  try {
    const s = JSON.parse(fs.readFileSync(REFRESH_STAMP(home), 'utf-8')) as Partial<RefreshStamp>;
    if (
      !s ||
      typeof s.build !== 'string' ||
      typeof s.attempts !== 'number' ||
      !Number.isInteger(s.attempts) ||
      s.attempts < 0 ||
      typeof s.at !== 'number' ||
      !Number.isFinite(s.at)
    ) {
      return null;
    }
    return {
      build: s.build,
      attempts: s.attempts,
      at: s.at,
      ...(typeof s.reason === 'string' && { reason: s.reason }),
    };
  } catch {
    return null;
  }
}

/** Temp file + rename, so a hook reading at the same moment sees a whole
 *  stamp. THROWS when it cannot write: the caller must not go on to spawn
 *  with the throttle unarmed. */
export function writeRefreshStamp(stamp: RefreshStamp, home: string = os.homedir()): void {
  const file = REFRESH_STAMP(home);
  const dir = path.dirname(file);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(stamp), 'utf-8');
    fs.renameSync(tmp, file);
  } catch (err) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* never created */
    }
    throw err;
  }
}

export function clearRefreshStamp(home: string = os.homedir()): void {
  try {
    fs.unlinkSync(REFRESH_STAMP(home));
  } catch {
    /* absent */
  }
}

/** May an attempt for build `mine` be made now. A stamp for another build
 *  does not count: a new install starts its own series. */
export function refreshDue(stamp: RefreshStamp | null, mine: string, now: number): boolean {
  if (!stamp || stamp.build !== mine) return true;
  // Math.abs: a stamp dated in the future (a corrected clock) would otherwise
  // read as "just attempted" for as long as the clock stays behind it.
  return Math.abs(now - stamp.at) >= refreshDelayMs(stamp.attempts);
}

/** Count one attempt for `mine`, before it is made. Throws when the stamp
 *  cannot be written (see writeRefreshStamp). */
export function armRefreshStamp(mine: string, now: number, home: string = os.homedir()): void {
  const prev = readRefreshStamp(home);
  const same = prev !== null && prev.build === mine;
  writeRefreshStamp(
    {
      build: mine,
      attempts: same ? prev.attempts + 1 : 1,
      at: now,
      ...(same && prev.reason !== undefined && { reason: prev.reason }),
    },
    home
  );
}

/** The attempt changed nothing, for `reason`. The count stands. Never throws. */
export function noteRefreshFailure(
  mine: string,
  reason: string,
  now: number,
  home: string = os.homedir()
): void {
  try {
    const prev = readRefreshStamp(home);
    const same = prev !== null && prev.build === mine;
    writeRefreshStamp(
      {
        build: mine,
        attempts: same ? Math.max(prev.attempts, 1) : 1,
        at: same ? prev.at : now,
        reason: reason.slice(0, 200),
      },
      home
    );
  } catch {
    /* the stamp is best effort here: the attempt is already over */
  }
}

/** The attempt was put off (an approval card is open): try again after the
 *  shortest delay, without counting it as a failure. Never throws. */
export function deferRefresh(mine: string, now: number, home: string = os.homedir()): void {
  try {
    const prev = readRefreshStamp(home);
    const same = prev !== null && prev.build === mine;
    // The hook counted this attempt before it started the helper: take it
    // back, but never below 1, or the next tool call would start another.
    writeRefreshStamp(
      { build: mine, attempts: same ? Math.max(prev.attempts - 1, 1) : 1, at: now },
      home
    );
  } catch {
    /* best effort */
  }
}
