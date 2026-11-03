// The activity socket lives in a directory only this user can reach, and the
// hook connects only to a socket this user owns (activity-socket-ownership
// design, 2026-11-02). On Linux it used to sit in the shared /tmp, where any
// local user could bind it first and receive every tool call.
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import {
  chooseActivitySocketPath,
  isTrustedActivitySocket,
  windowsActivityPipeName,
} from '../utils/activity-socket';

const posix = it.skipIf(process.platform === 'win32');
const rooms: string[] = [];
const room = (): string => {
  const r = fs.mkdtempSync(path.join(os.tmpdir(), 'n9s-'));
  rooms.push(r);
  return r;
};
const servers: net.Server[] = [];
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
  for (const r of rooms.splice(0)) fs.rmSync(r, { recursive: true, force: true });
});
const listen = (p: string) =>
  new Promise<void>((resolve) => {
    const s = net.createServer(() => {});
    servers.push(s);
    s.listen(p, () => resolve());
  });

describe('chooseActivitySocketPath', () => {
  posix(
    'uses a per-HOME directory under XDG_RUNTIME_DIR when it is a private directory of this user',
    () => {
      const home = room();
      const xdg = room();
      fs.chmodSync(xdg, 0o700);
      const p = chooseActivitySocketPath({ XDG_RUNTIME_DIR: xdg }, home, process.platform);
      expect(path.dirname(path.dirname(p!))).toBe(xdg);
      expect(path.basename(path.dirname(p!))).toMatch(/^node9-[0-9a-f]{12}$/);
      expect(path.basename(p!)).toBe('activity.sock');
      expect(fs.statSync(path.dirname(p!)).mode & 0o077).toBe(0);
    }
  );

  posix('two HOMEs never share a socket under XDG_RUNTIME_DIR', () => {
    const xdg = room();
    fs.chmodSync(xdg, 0o700);
    const a = chooseActivitySocketPath({ XDG_RUNTIME_DIR: xdg }, room(), process.platform);
    const b = chooseActivitySocketPath({ XDG_RUNTIME_DIR: xdg }, room(), process.platform);
    expect(a).not.toBe(b);
  });

  posix('falls back to ~/.node9/run without XDG_RUNTIME_DIR, or when it is not private', () => {
    const home = room();
    const open = room();
    fs.chmodSync(open, 0o777);
    expect(chooseActivitySocketPath({}, home, process.platform)).toBe(
      path.join(home, '.node9', 'run', 'activity.sock')
    );
    expect(chooseActivitySocketPath({ XDG_RUNTIME_DIR: open }, home, process.platform)).toBe(
      path.join(home, '.node9', 'run', 'activity.sock')
    );
    expect(fs.statSync(path.join(home, '.node9', 'run')).mode & 0o077).toBe(0);
  });

  posix('never picks the shared temp directory', () => {
    const home = room();
    const p = chooseActivitySocketPath({ XDG_RUNTIME_DIR: os.tmpdir() }, home, process.platform);
    expect(p).not.toBe(path.join(os.tmpdir(), 'node9-activity.sock'));
    expect(path.dirname(path.dirname(p!))).not.toBe(os.tmpdir());
  });

  posix('a run directory that is a link is refused', () => {
    const home = room();
    const elsewhere = room();
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.symlinkSync(elsewhere, path.join(home, '.node9', 'run'));
    expect(chooseActivitySocketPath({}, home, process.platform)).toBeNull();
  });

  posix('a path longer than a Unix socket allows moves to the other candidate', () => {
    const home = room();
    const deep = path.join(room(), 'x'.repeat(120));
    fs.mkdirSync(deep, { mode: 0o700 });
    expect(chooseActivitySocketPath({ XDG_RUNTIME_DIR: deep }, home, process.platform)).toBe(
      path.join(home, '.node9', 'run', 'activity.sock')
    );
  });

  it('Windows: a pipe name nobody can guess, fresh per daemon', () => {
    const a = windowsActivityPipeName();
    const b = windowsActivityPipeName();
    expect(a).toMatch(/^\\\\\.\\pipe\\node9-activity-[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});

describe('isTrustedActivitySocket', () => {
  posix('a socket this user owns, in a private directory, is trusted', async () => {
    const dir = path.join(room(), 'run');
    fs.mkdirSync(dir, { mode: 0o700 });
    const p = path.join(dir, 'activity.sock');
    await listen(p);
    expect(isTrustedActivitySocket(p)).toBe(true);
  });

  posix('a link in place of the socket is not trusted', async () => {
    const dir = path.join(room(), 'run');
    fs.mkdirSync(dir, { mode: 0o700 });
    const real = path.join(room(), 'real.sock');
    await listen(real);
    const p = path.join(dir, 'activity.sock');
    fs.symlinkSync(real, p);
    expect(isTrustedActivitySocket(p)).toBe(false);
  });

  posix('a socket in a directory others can write is not trusted', async () => {
    const dir = path.join(room(), 'run');
    fs.mkdirSync(dir);
    fs.chmodSync(dir, 0o777);
    const p = path.join(dir, 'activity.sock');
    await listen(p);
    expect(isTrustedActivitySocket(p)).toBe(false);
  });

  posix('a socket owned by another user is not trusted', async () => {
    const dir = path.join(room(), 'run');
    fs.mkdirSync(dir, { mode: 0o700 });
    const p = path.join(dir, 'activity.sock');
    await listen(p);
    expect(isTrustedActivitySocket(p, (process.getuid?.() ?? 0) + 1)).toBe(false);
  });

  posix('a regular file is not a socket', () => {
    const dir = path.join(room(), 'run');
    fs.mkdirSync(dir, { mode: 0o700 });
    const p = path.join(dir, 'activity.sock');
    fs.writeFileSync(p, 'x');
    expect(isTrustedActivitySocket(p)).toBe(false);
  });

  it('Windows: only a node9 pipe name with the random part is trusted', () => {
    if (process.platform !== 'win32') return;
    expect(isTrustedActivitySocket(windowsActivityPipeName())).toBe(true);
    expect(isTrustedActivitySocket('\\\\.\\pipe\\node9-activity')).toBe(false);
  });
});
