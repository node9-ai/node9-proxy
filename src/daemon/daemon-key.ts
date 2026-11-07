// The daemon key (node9Firewall#445): 32 random bytes in ~/.node9/daemon.key
// that only this HOME's daemons read. A daemon proves it holds the key by
// answering GET /health?nonce=<n> with an HMAC of the nonce and its pid, so a
// start that finds the port held can tell a node9 daemon of this HOME from any
// other process that answers HTTP there. The key never goes over the wire.
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ensureOwnDir } from '../utils/own-dir';

const KEY_FILE = 'daemon.key';
const KEY_TEXT = /^[0-9a-f]{64}$/;
const PROOF_TEXT = /^[0-9a-f]{64}$/;
export const HEALTH_NONCE = /^[0-9a-f]{32}$/;

/**
 * This HOME's daemon key, created on first use. Null when it cannot be kept
 * safely: ~/.node9 is not a real directory of this user, the key file is a
 * link, not a regular file, readable by others, owned by someone else, or
 * damaged. A damaged key is left for the user to remove, never replaced:
 * replacing it would cut off a running daemon that still holds the old one.
 */
export function loadDaemonKey(home = os.homedir(), opts: { create?: boolean } = {}): Buffer | null {
  const dir = path.join(home, '.node9');
  if (!ensureOwnDir(dir)) return null;
  const file = path.join(dir, KEY_FILE);
  if (opts.create !== false) createKey(dir, file);
  return readKey(file);
}

/** Writes a complete key under a temporary name and links it into place, so a
 *  second daemon starting at the same moment reads either no key or a whole
 *  one. The link fails when a key already exists, which keeps that key. */
function createKey(dir: string, file: string): void {
  if (fs.existsSync(file) || isLink(file)) return;
  const tmp = path.join(
    dir,
    `.${KEY_FILE}.${process.pid}.${crypto.randomBytes(4).toString('hex')}`
  );
  try {
    fs.writeFileSync(tmp, crypto.randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
    fs.linkSync(tmp, file);
  } catch {
    /* another daemon won the race, or the directory is not writable */
  } finally {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* never created */
    }
  }
}

function isLink(file: string): boolean {
  try {
    return fs.lstatSync(file).isSymbolicLink();
  } catch {
    return false;
  }
}

function readKey(file: string): Buffer | null {
  let fd: number;
  try {
    fd = fs.openSync(
      file,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0)
    );
  } catch {
    return null;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size !== 64) return null;
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) return null;
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) return null;
    }
    const buf = Buffer.alloc(64);
    if (fs.readSync(fd, buf, 0, 64, 0) !== 64) return null;
    const text = buf.toString('utf8');
    return KEY_TEXT.test(text) ? Buffer.from(text, 'hex') : null;
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

export function newHealthNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

export function healthProof(key: Buffer, nonce: string, pid: number): string {
  return crypto.createHmac('sha256', key).update(`health:${nonce}:${pid}`).digest('hex');
}

export function verifyHealthProof(
  key: Buffer,
  nonce: string,
  pid: number,
  proof: unknown
): boolean {
  if (typeof proof !== 'string' || !PROOF_TEXT.test(proof)) return false;
  return crypto.timingSafeEqual(
    Buffer.from(healthProof(key, nonce, pid), 'hex'),
    Buffer.from(proof, 'hex')
  );
}

/** What the process holding the daemon port says about itself. */
export interface PortHolder {
  /** Something answered GET /health with JSON. */
  answered: boolean;
  pid: number | null;
  buildId: string | null;
  /** valid: it holds this HOME's key. invalid: it sent a proof that does not
   *  check out. absent: no proof (a build before the key, or not node9). */
  proof: 'valid' | 'invalid' | 'absent';
}

const MAX_PID = 4_194_304;

/** Asks the holder of host:port to prove it is a daemon of this HOME. With no
 *  key of our own there is nothing to check against: every proof is absent. */
export async function probePortHolder(
  key: Buffer | null,
  host: string,
  port: number,
  timeoutMs = 800
): Promise<PortHolder> {
  const nonce = newHealthNonce();
  let body: Record<string, unknown> | null = null;
  try {
    const res = await fetch(`http://${host}:${port}/health?nonce=${nonce}`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.ok) body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  } catch {
    /* nothing answered */
  }
  if (!body || typeof body !== 'object') {
    return { answered: false, pid: null, buildId: null, proof: 'absent' };
  }
  const pid =
    typeof body.pid === 'number' &&
    Number.isInteger(body.pid) &&
    body.pid > 0 &&
    body.pid <= MAX_PID
      ? body.pid
      : null;
  const buildId = typeof body.buildId === 'string' ? body.buildId : null;
  if (body.proof === undefined || key === null)
    return { answered: true, pid, buildId, proof: 'absent' };
  const valid = pid !== null && verifyHealthProof(key, nonce, pid, body.proof);
  return { answered: true, pid, buildId, proof: valid ? 'valid' : 'invalid' };
}
