import fs from 'fs';
import path from 'path';

/** Which directory a check saw, so later steps can tell it was not swapped. */
export interface OwnDir {
  dev: number;
  ino: number;
}

/** Suffix of node9's per-session flag files. No project file carries it, so a
 *  clean-up that matches it cannot delete anything but node9's own flags. */
export const SESSION_FLAG_SUFFIX = '.node9-flag';

const SESSION_FLAG_NAME = /^[A-Za-z0-9_-]{1,128}\.node9-flag$/;

export function isSessionFlagName(name: string): boolean {
  return SESSION_FLAG_NAME.test(name);
}

function ownRealDir(st: fs.Stats): boolean {
  if (st.isSymbolicLink() || !st.isDirectory()) return false;
  return typeof process.getuid !== 'function' || st.uid === process.getuid();
}

/**
 * Creates `dir` if needed (mode 0700) and returns its identity when it is safe
 * to keep node9 state in: a real directory, not a link, owned by this user.
 *
 * Directories under ~/.node9 are reachable by the agent with mv and ln. A link
 * planted there would point node9's own writes, reads and clean-ups at a
 * directory the agent chose, so callers skip their state on null. Any
 * filesystem error also returns null.
 */
export function ensureOwnDir(dir: string): OwnDir | null {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const st = fs.lstatSync(dir);
    return ownRealDir(st) ? { dev: st.dev, ino: st.ino } : null;
  } catch {
    return null;
  }
}

/** True when `dir` is still the directory `ensureOwnDir` returned: call it
 *  right before each write or delete, so a swap between the first check and
 *  the action is caught. */
export function isSameOwnDir(dir: string, seen: OwnDir): boolean {
  try {
    const st = fs.lstatSync(dir);
    return ownRealDir(st) && st.dev === seen.dev && st.ino === seen.ino;
  } catch {
    return false;
  }
}

/** Removes `name` from `dir` when it is a node9 flag file older than
 *  `cutoffMs` and the directory is still the one that was checked. */
export function removeOldFlag(dir: string, seen: OwnDir, name: string, cutoffMs: number): void {
  if (!isSessionFlagName(name)) return;
  const p = path.join(dir, name);
  try {
    const st = fs.lstatSync(p);
    if (!st.isFile() || st.mtimeMs >= cutoffMs) return;
    if (!isSameOwnDir(dir, seen)) return;
    fs.unlinkSync(p);
  } catch {
    /* another hook removed it, or it is unreadable: leave it */
  }
}
