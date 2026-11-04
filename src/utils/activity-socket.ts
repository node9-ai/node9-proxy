// Where the daemon's flight-recorder socket lives, and whether the hook may
// connect to it (activity-socket-ownership design, 2026-11-02).
//
// On Linux the socket used to be /tmp/node9-activity.sock: a directory every
// local user shares, with no owner check on either side, so another user who
// bound that path first received every tool call the agent made (name,
// arguments, session id) and could slow each one. On Windows the pipe name was
// fixed and global. The socket now sits in a directory only this user can
// reach, the daemon records its path in ~/.node9/daemon.pid (mode 0600), and
// the hook connects only to a socket this user owns there.

import fs from 'fs';
import path from 'path';
import { createHash, randomBytes } from 'crypto';
import { ensureOwnDir } from './own-dir';

const SOCKET_NAME = 'activity.sock';

/** Longest Unix socket path, in bytes, including the terminating NUL. */
function maxSocketPathBytes(platform: NodeJS.Platform): number {
  return platform === 'darwin' ? 104 : 108;
}

const currentUid = (): number | undefined =>
  typeof process.getuid === 'function' ? process.getuid() : undefined;

/** A real directory (not a link) owned by `uid`, writable by nobody else. */
function isPrivateDir(dir: string, uid = currentUid()): boolean {
  try {
    const st = fs.lstatSync(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) return false;
    if (uid !== undefined && st.uid !== uid) return false;
    return (st.mode & 0o022) === 0;
  } catch {
    return false;
  }
}

/** `dir` created if needed (0700) and private: a real directory of this
 *  user that nobody else can enter. */
function privateDir(dir: string): boolean {
  if (!ensureOwnDir(dir)) return false;
  try {
    const st = fs.lstatSync(dir);
    if ((st.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
  } catch {
    return false;
  }
  return isPrivateDir(dir);
}

/** `$XDG_RUNTIME_DIR/node9-<home hash>`, or null without an absolute
 *  XDG_RUNTIME_DIR. One directory per HOME: a daemon started with another
 *  HOME (a test, an isolated scan) must not share, or remove, the real
 *  daemon's socket. */
function perHomeRuntimeDir(env: NodeJS.ProcessEnv, home: string): string | null {
  const xdg = env.XDG_RUNTIME_DIR;
  if (!xdg || !path.isAbsolute(xdg)) return null;
  return path.join(xdg, `node9-${createHash('sha256').update(home).digest('hex').slice(0, 12)}`);
}

/**
 * The socket path for this user, POSIX only: `$XDG_RUNTIME_DIR/node9-<home hash>` when
 * XDG_RUNTIME_DIR is a private directory of this user (systemd's
 * /run/user/<uid>), else `~/.node9/run`. A path too long for a Unix socket
 * moves to the next candidate. Null when no candidate is usable: the daemon
 * then runs without the socket, and the hook tells it over HTTP instead.
 */
export function chooseActivitySocketPath(
  env: NodeJS.ProcessEnv,
  home: string,
  platform: NodeJS.Platform = process.platform
): string | null {
  const candidates: string[] = [];
  const xdgDir = perHomeRuntimeDir(env, home);
  if (xdgDir && isPrivateDir(path.dirname(xdgDir))) candidates.push(xdgDir);
  candidates.push(path.join(home, '.node9', 'run'));
  for (const dir of candidates) {
    const socketPath = path.join(dir, SOCKET_NAME);
    if (Buffer.byteLength(socketPath) >= maxSocketPathBytes(platform)) continue;
    if (privateDir(dir)) return socketPath;
  }
  return null;
}

/** Makes sure the socket's directory exists and is private again (it may
 *  have been removed while the daemon ran: systemd removes /run/user/<uid>
 *  when the user's last session ends). */
export function ensureActivitySocketDir(socketPath: string): boolean {
  return privateDir(path.dirname(socketPath));
}

/** Windows: a pipe name another user cannot create first, because only the
 *  daemon.pid file (readable by this user alone) holds it. */
export function windowsActivityPipeName(): string {
  return `\\\\.\\pipe\\node9-activity-${randomBytes(16).toString('hex')}`;
}

const WINDOWS_PIPE = /^\\\\\.\\pipe\\node9-activity-[0-9a-f]{32}$/;

/**
 * Whether the hook may connect to `socketPath`. POSIX: a socket (not a link)
 * owned by `uid`, in a directory of that user that nobody else can write.
 * Windows: a node9 pipe name with its random part. Any doubt: false, and the
 * hook tells the daemon over HTTP.
 */
export function isTrustedActivitySocket(socketPath: string, uid = currentUid()): boolean {
  if (process.platform === 'win32') return WINDOWS_PIPE.test(socketPath);
  try {
    const st = fs.lstatSync(socketPath);
    if (!st.isSocket()) return false;
    if (uid !== undefined && st.uid !== uid) return false;
  } catch {
    return false;
  }
  return isPrivateDir(path.dirname(socketPath), uid);
}

/** The socket file the daemon may remove before binding: a socket of this
 *  user at that path. Never a file of anyone else, never a link. */
export function isOwnStaleSocket(socketPath: string): boolean {
  try {
    const st = fs.lstatSync(socketPath);
    const uid = currentUid();
    return st.isSocket() && (uid === undefined || st.uid === uid);
  } catch {
    return false;
  }
}

/**
 * Removes the socket's directory when the daemon stops, so a run that starts
 * many daemons with throwaway HOMEs does not leave one directory per HOME in
 * /run/user/<uid> (a tmpfs). Only the per-HOME directory under
 * XDG_RUNTIME_DIR for this HOME, never ~/.node9/run or another HOME's; only
 * when it is a real directory of this user (not a link) and empty. True when
 * it was removed.
 */
export function removeOwnSocketDir(
  socketPath: string,
  env: NodeJS.ProcessEnv,
  home: string,
  platform: NodeJS.Platform = process.platform
): boolean {
  if (platform === 'win32') return false;
  const dir = path.dirname(socketPath);
  if (dir !== perHomeRuntimeDir(env, home)) return false;
  try {
    const st = fs.lstatSync(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) return false;
    const uid = currentUid();
    if (uid !== undefined && st.uid !== uid) return false;
    if (fs.readdirSync(dir).length > 0) return false;
    // rmdir refuses a directory that gained an entry since the check.
    fs.rmdirSync(dir);
    return true;
  } catch {
    return false;
  }
}
