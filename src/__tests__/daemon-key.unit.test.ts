// The daemon key (node9Firewall#445): a secret only this HOME's daemons hold,
// so a process that answers on the daemon port can be told from a daemon.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  loadDaemonKey,
  healthProof,
  verifyHealthProof,
  newHealthNonce,
} from '../daemon/daemon-key';

const posix = it.skipIf(process.platform === 'win32');

let home: string;
const keyFile = () => path.join(home, '.node9', 'daemon.key');

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-key-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('loadDaemonKey', () => {
  it('creates a 32-byte key on first use and returns the same key after', () => {
    const first = loadDaemonKey(home);
    expect(first).not.toBeNull();
    expect(first!.length).toBe(32);
    expect(loadDaemonKey(home)!.equals(first!)).toBe(true);
    expect(fs.readFileSync(keyFile(), 'utf-8')).toMatch(/^[0-9a-f]{64}$/);
  });

  posix('the key file is readable by this user only', () => {
    loadDaemonKey(home);
    expect(fs.statSync(keyFile()).mode & 0o777).toBe(0o600);
  });

  it('another HOME gets its own key', () => {
    const other = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-key-'));
    try {
      expect(loadDaemonKey(home)!.equals(loadDaemonKey(other)!)).toBe(false);
    } finally {
      fs.rmSync(other, { recursive: true, force: true });
    }
  });

  posix('a link in place of the key is refused and its target left alone', () => {
    const target = path.join(home, 'elsewhere.key');
    fs.writeFileSync(target, 'a'.repeat(64), { mode: 0o600 });
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.symlinkSync(target, keyFile());
    expect(loadDaemonKey(home)).toBeNull();
    expect(fs.readFileSync(target, 'utf-8')).toBe('a'.repeat(64));
  });

  posix('a key others can read is refused', () => {
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(keyFile(), 'b'.repeat(64), { mode: 0o644 });
    fs.chmodSync(keyFile(), 0o644);
    expect(loadDaemonKey(home)).toBeNull();
  });

  it('a damaged key file is refused, not replaced', () => {
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(keyFile(), 'not a key', { mode: 0o600 });
    expect(loadDaemonKey(home)).toBeNull();
    expect(fs.readFileSync(keyFile(), 'utf-8')).toBe('not a key');
  });

  it('without create, a missing key stays missing', () => {
    expect(loadDaemonKey(home, { create: false })).toBeNull();
    expect(fs.existsSync(keyFile())).toBe(false);
  });
});

describe('health proof', () => {
  it('verifies with the same key, nonce and pid only', () => {
    const key = loadDaemonKey(home)!;
    const other = Buffer.alloc(32, 7);
    const nonce = newHealthNonce();
    const proof = healthProof(key, nonce, 4242);
    expect(verifyHealthProof(key, nonce, 4242, proof)).toBe(true);
    expect(verifyHealthProof(other, nonce, 4242, proof)).toBe(false);
    expect(verifyHealthProof(key, newHealthNonce(), 4242, proof)).toBe(false);
    expect(verifyHealthProof(key, nonce, 4243, proof)).toBe(false);
  });

  it('a missing or malformed proof does not verify', () => {
    const key = loadDaemonKey(home)!;
    const nonce = newHealthNonce();
    for (const bad of [undefined, null, 42, '', 'zz', healthProof(key, nonce, 1).slice(1)]) {
      expect(verifyHealthProof(key, nonce, 1, bad)).toBe(false);
    }
  });

  it('nonces are 32 hex characters and differ', () => {
    const a = newHealthNonce();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(newHealthNonce()).not.toBe(a);
  });
});
