// Who may become "the daemon" (node9Firewall#445). A start that finds the port
// held adopts the holder, or yields to it, only when the holder proves it holds
// this HOME's daemon key. Every daemon here runs in a temp HOME on a port of its
// own (NODE9_TESTING + NODE9_DAEMON_PORT), and only processes this file spawned
// are ever signalled. Requires `npm run build`.
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import { CLI, freePort, waitFor } from './helpers/daemon-hook';
import { keySafeEnv } from './helpers/env';

const itUnix = it.skipIf(process.platform === 'win32');

const homes: string[] = [];
const children: ChildProcess[] = [];
const servers: http.Server[] = [];

beforeAll(() => {
  expect(fs.existsSync(CLI), `${CLI} missing — run npm run build`).toBe(true);
});

afterEach(async () => {
  for (const c of children.splice(0)) if (c.exitCode === null) c.kill('SIGKILL');
  for (const s of servers.splice(0)) {
    s.closeAllConnections();
    await new Promise((r) => s.close(r));
  }
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});

function newHome(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-porttrust-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  homes.push(h);
  return h;
}

function daemonEnv(home: string, port: number) {
  const env = keySafeEnv({
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_NO_AUTO_DAEMON: '1',
    NODE9_DAEMON_PORT: String(port),
    NO_COLOR: '1',
  });
  delete env.XDG_RUNTIME_DIR;
  return env;
}

/** A real daemon, kept running until the test ends. */
async function startDaemon(home: string, port: number): Promise<ChildProcess> {
  const child = spawn(process.execPath, [CLI, 'daemon', 'start'], {
    env: daemonEnv(home, port),
    cwd: os.tmpdir(),
    stdio: 'ignore',
  });
  children.push(child);
  expect(await waitFor(`http://127.0.0.1:${port}/health`, 20_000)).toBe(true);
  return child;
}

/** A second start against a held port: it must decide and exit. */
function secondStart(home: string, port: number): Promise<number | null> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'daemon', 'start'], {
      env: daemonEnv(home, port),
      cwd: os.tmpdir(),
      stdio: 'ignore',
    });
    children.push(child);
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('second daemon start did not exit within 25 s'));
    }, 25_000);
    child.on('exit', (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}

/** Not node9: answers every route with 200 and `body`. */
async function fakeDaemon(port: number, body: Record<string, unknown> = {}): Promise<string[]> {
  const seen: string[] = [];
  const srv = http.createServer((req, res) => {
    seen.push(`${req.method} ${req.url} ${req.headers['x-node9-internal'] ?? ''}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ pid: process.pid, ...body }));
  });
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(port, '127.0.0.1', () => r()));
  return seen;
}

const pidFile = (home: string) => path.join(home, '.node9', 'daemon.pid');
const startupState = (home: string) =>
  JSON.parse(fs.readFileSync(path.join(home, '.node9', 'daemon-startup-state.json'), 'utf-8')) as {
    outcome: string;
    kind?: string;
    detail?: string;
  };

describe('adoption needs the key (fw#445 a)', () => {
  itUnix('a process that only answers HTTP on the port is not adopted', async () => {
    const port = await freePort();
    const home = newHome();
    await fakeDaemon(port);

    expect(await secondStart(home, port)).toBe(0);

    expect(fs.existsSync(pidFile(home))).toBe(false);
    const state = startupState(home);
    expect(state.outcome).toBe('failed');
    expect(state.kind).toBe('port-held-unverified');
    expect(state.detail).toMatch(/could not prove/);
  });

  itUnix("another HOME's daemon on the port is not adopted", async () => {
    const port = await freePort();
    await startDaemon(newHome(), port);
    const home = newHome();

    expect(await secondStart(home, port)).toBe(0);

    expect(fs.existsSync(pidFile(home))).toBe(false);
    expect(startupState(home).kind).toBe('port-held-unverified');
  });

  itUnix('a daemon of this HOME that lost its daemon.pid is adopted', async () => {
    const port = await freePort();
    const home = newHome();
    const first = await startDaemon(home, port);
    fs.rmSync(pidFile(home));

    expect(await secondStart(home, port)).toBe(0);

    const record = JSON.parse(fs.readFileSync(pidFile(home), 'utf-8'));
    expect(record.pid).toBe(first.pid);
    expect(record.port).toBe(port);
    expect(startupState(home).outcome).toBe('ok-elsewhere');
  });
});

describe('takeover and yield need the key (fw#445 a)', () => {
  itUnix('a holder that claims a newer build without the proof is not yielded to', async () => {
    const port = await freePort();
    const home = newHome();
    const seen = await fakeDaemon(port, { version: '999.0.0', buildId: '999.0.0+1' });
    // daemon.pid names a live process (this runner), as after a pid reuse.
    fs.writeFileSync(
      pidFile(home),
      JSON.stringify({ pid: process.pid, port, internalToken: 'secret-token' })
    );

    expect(await secondStart(home, port)).toBe(0);

    const state = startupState(home);
    expect(state.outcome).toBe('failed');
    expect(state.kind).toBe('port-held-unverified');
    expect(seen.some((s) => s.includes('secret-token'))).toBe(false);
  });

  itUnix('a holder that answers with a wrong proof never receives the token', async () => {
    const port = await freePort();
    const home = newHome();
    const seen = await fakeDaemon(port, {
      version: '0.0.1',
      buildId: '0.0.1+1',
      proof: 'f'.repeat(64),
    });
    fs.writeFileSync(
      pidFile(home),
      JSON.stringify({ pid: process.pid, port, internalToken: 'secret-token' })
    );

    expect(await secondStart(home, port)).toBe(0);

    expect(startupState(home).kind).toBe('port-held-unverified');
    expect(seen.some((s) => s.includes('secret-token'))).toBe(false);
  });
});
