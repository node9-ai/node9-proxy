// The daemon leaves no activity socket and no per-HOME directory behind when
// it stops. Before the fix it had no SIGTERM/SIGINT handler, so `node9 daemon
// stop` (which sends SIGTERM) ended it without the 'exit' event: the socket
// stayed, and nothing ever removed its directory. A harness that starts many
// daemons with throwaway HOMEs left one directory per HOME in /run/user/<uid>.
//
// Every daemon here runs with its own HOME, its own private XDG_RUNTIME_DIR,
// NODE9_TESTING=1 and a port of its own. Only the pid of the child this test
// spawned is ever signalled.
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const posix = it.skipIf(process.platform === 'win32');

const rooms: string[] = [];
const children: ChildProcess[] = [];

beforeAll(() => {
  if (process.platform === 'win32') return;
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found. Run "npm run build" first. Expected: ${CLI}`);
  }
});

afterEach(() => {
  for (const c of children.splice(0)) {
    if (c.exitCode === null && c.signalCode === null) c.kill('SIGKILL');
  }
  for (const r of rooms.splice(0)) fs.rmSync(r, { recursive: true, force: true });
});

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}

interface Sandbox {
  home: string;
  xdg: string;
  env: NodeJS.ProcessEnv;
}

async function sandbox(withXdg = true): Promise<Sandbox> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'n9c-'));
  rooms.push(root);
  const home = path.join(root, 'h');
  const xdg = path.join(root, 'x');
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.mkdirSync(xdg, { mode: 0o700 });
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ settings: { mode: 'audit', autoStartDaemon: false } })
  );
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_DAEMON_PORT: String(await freePort()),
  };
  delete env.XDG_RUNTIME_DIR;
  if (withXdg) env.XDG_RUNTIME_DIR = xdg;
  return { home, xdg, env };
}

interface Running {
  child: ChildProcess;
  socketPath: string;
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

/** Starts a daemon and waits until its daemon.pid names a bound socket. */
async function startDaemon(sb: Sandbox): Promise<Running> {
  const child = spawn(process.execPath, [CLI, 'daemon', 'start'], {
    env: sb.env,
    stdio: 'ignore',
  });
  children.push(child);
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((r) =>
    child.once('exit', (code, signal) => r({ code, signal }))
  );
  const pidFile = path.join(sb.home, '.node9', 'daemon.pid');
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    try {
      const data = JSON.parse(fs.readFileSync(pidFile, 'utf-8')) as Record<string, unknown>;
      const socketPath = typeof data.activitySocket === 'string' ? data.activitySocket : '';
      if (data.pid === child.pid && socketPath && fs.existsSync(socketPath))
        return { child, socketPath, exited };
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('daemon did not bind its activity socket within 8s');
}

describe('activity socket clean-up on shutdown', () => {
  for (const [signal, code] of [
    ['SIGTERM', 0],
    ['SIGINT', 130],
  ] as const) {
    posix(
      `${signal}: the socket and its per-HOME directory are gone, exit ${code}`,
      async () => {
        const sb = await sandbox();
        const d = await startDaemon(sb);
        const dir = path.dirname(d.socketPath);
        expect(path.dirname(dir)).toBe(sb.xdg);
        d.child.kill(signal);
        expect(await d.exited).toEqual({ code, signal: null });
        expect(fs.existsSync(d.socketPath)).toBe(false);
        expect(fs.existsSync(dir)).toBe(false);
        expect(fs.readdirSync(sb.xdg)).toEqual([]);
      },
      20_000
    );
  }

  posix(
    '`node9 daemon stop` leaves nothing behind',
    async () => {
      const sb = await sandbox();
      const d = await startDaemon(sb);
      // startDaemon() checked that this HOME's daemon.pid names the child we
      // spawned, so the stop below signals only that child.
      spawnSync(process.execPath, [CLI, 'daemon', 'stop'], { env: sb.env, timeout: 5000 });
      expect(await d.exited).toEqual({ code: 0, signal: null });
      expect(fs.readdirSync(sb.xdg)).toEqual([]);
    },
    20_000
  );

  posix(
    'a directory that is not empty is left, with what is in it',
    async () => {
      const sb = await sandbox();
      const d = await startDaemon(sb);
      const other = path.join(path.dirname(d.socketPath), 'other');
      fs.writeFileSync(other, 'x');
      d.child.kill('SIGTERM');
      expect((await d.exited).code).toBe(0);
      expect(fs.existsSync(d.socketPath)).toBe(false);
      expect(fs.readFileSync(other, 'utf-8')).toBe('x');
    },
    20_000
  );

  posix(
    'a link in place of the per-HOME directory is left alone',
    async () => {
      const sb = await sandbox();
      // Learn this HOME's directory name from a first run, then plant a link
      // there. The daemon refuses the link and falls back to ~/.node9/run.
      const first = await startDaemon(sb);
      const dir = path.dirname(first.socketPath);
      first.child.kill('SIGTERM');
      await first.exited;
      const target = fs.mkdtempSync(path.join(os.tmpdir(), 'n9t-'));
      rooms.push(target);
      fs.symlinkSync(target, dir);

      const d = await startDaemon(sb);
      expect(d.socketPath).toBe(path.join(sb.home, '.node9', 'run', 'activity.sock'));
      d.child.kill('SIGTERM');
      expect((await d.exited).code).toBe(0);
      expect(fs.lstatSync(dir).isSymbolicLink()).toBe(true);
      expect(fs.existsSync(target)).toBe(true);
      // ~/.node9/run is never removed, only the socket in it.
      expect(fs.existsSync(d.socketPath)).toBe(false);
      expect(fs.existsSync(path.dirname(d.socketPath))).toBe(true);
    },
    30_000
  );

  posix(
    'after SIGKILL the directory stays, and the next daemon with the same HOME binds again',
    async () => {
      const sb = await sandbox();
      const first = await startDaemon(sb);
      first.child.kill('SIGKILL');
      expect((await first.exited).signal).toBe('SIGKILL');
      expect(fs.existsSync(first.socketPath)).toBe(true);

      const d = await startDaemon(sb);
      expect(d.socketPath).toBe(first.socketPath);
      const connected = await new Promise<boolean>((resolve) => {
        const c = net.createConnection(d.socketPath);
        c.on('connect', () => {
          c.end();
          resolve(true);
        });
        c.on('error', () => resolve(false));
      });
      expect(connected).toBe(true);
      d.child.kill('SIGTERM');
      expect((await d.exited).code).toBe(0);
      expect(fs.readdirSync(sb.xdg)).toEqual([]);
    },
    30_000
  );
});
