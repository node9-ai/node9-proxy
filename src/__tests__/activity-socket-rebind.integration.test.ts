/**
 * Integration test for the activity-socket self-healing logic (Layer 2).
 *
 * Failure mode this guards against:
 *   The daemon's flight-recorder Unix socket at /tmp/node9-activity.sock can
 *   disappear at runtime (systemd-tmpfiles cleanup, manual rm, tmp on tmpfs
 *   after suspend). When that happens, every PreToolUse / PostToolUse hook's
 *   notifyActivitySocket() silently returns false, and `node9 tail` shows no
 *   live events. Pre-fix recovery required `node9 daemon restart`.
 *
 *   The fix watches the socket path and rebinds automatically. This test
 *   spawns the daemon, deletes the socket file, then verifies it gets
 *   recreated and a subsequent send is delivered (broadcast over SSE).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import http from 'http';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const DAEMON_PORT = 7391;
const ACTIVITY_SOCKET_PATH = path.join(os.tmpdir(), 'node9-activity.sock');

function makeTempHome(): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-rebind-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(
    path.join(node9Dir, 'config.json'),
    JSON.stringify({ settings: { mode: 'audit', autoStartDaemon: false } })
  );
  return tmpHome;
}

function makeEnv(home: string): NodeJS.ProcessEnv {
  return { ...process.env, HOME: home, USERPROFILE: home, NODE9_TESTING: '1' };
}

function isPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => server.close(() => resolve(true)));
    server.listen(port, '127.0.0.1');
  });
}

async function waitForDaemon(timeoutMs = 6000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/settings`);
      if (res.ok) return true;
    } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

async function waitForFile(p: string, timeoutMs = 5000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(p)) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

function readAuthToken(home: string): string {
  const data = JSON.parse(
    fs.readFileSync(path.join(home, '.node9', 'daemon.pid'), 'utf-8')
  ) as Record<string, unknown>;
  return typeof data.internalToken === 'string' ? data.internalToken : '';
}

function sendOverSocket(payload: string): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.createConnection(ACTIVITY_SOCKET_PATH);
    sock.on('connect', () => {
      sock.on('close', () => resolve(true));
      sock.end(payload);
    });
    sock.on('error', () => resolve(false));
  });
}

/** Open SSE and resolve on the first 'activity' or 'activity-result' event whose id matches. */
function waitForActivityEvent(authToken: string, id: string, timeoutMs = 4000): Promise<boolean> {
  return new Promise((resolve) => {
    let buf = '';
    let settled = false;
    const done = (v: boolean) => {
      if (settled) return;
      settled = true;
      try {
        req.destroy();
      } catch {}
      resolve(v);
    };
    const req = http.get(
      `http://127.0.0.1:${DAEMON_PORT}/events`,
      { headers: { 'X-Node9-Internal': authToken } },
      (res) => {
        res.setEncoding('utf-8');
        res.on('data', (chunk: string) => {
          buf += chunk;
          // Each SSE message ends with a blank line. Scan for our id.
          if (buf.includes(`"id":"${id}"`)) done(true);
        });
        res.on('end', () => done(false));
        res.on('error', () => done(false));
      }
    );
    req.on('error', () => done(false));
    setTimeout(() => done(false), timeoutMs);
  });
}

describe('activity socket — self-healing rebind (#tail-stability)', () => {
  let tmpHome: string;
  let daemonProc: ChildProcess;
  let authToken: string;
  let portWasFree = false;

  beforeAll(async () => {
    // The daemon binds a Windows named pipe (\\.\pipe\node9-activity), not a
    // socket file under os.tmpdir(). The test's polling/unlink/connect helpers
    // all assume a filesystem socket, so they cannot exercise the rebind path
    // on Windows. The self-heal logic in src/daemon/state.ts is itself gated
    // on `process.platform !== 'win32'` — skipping here matches that contract.
    if (process.platform === 'win32') return;
    if (!fs.existsSync(CLI)) {
      throw new Error(`dist/cli.js not found. Run "npm run build" first. Expected: ${CLI}`);
    }
    portWasFree = await isPortFree(DAEMON_PORT);
    if (!portWasFree) return;

    tmpHome = makeTempHome();
    daemonProc = spawn(process.execPath, [CLI, 'daemon', 'start'], {
      env: makeEnv(tmpHome),
      stdio: 'pipe',
    });

    const ready = await waitForDaemon(6000);
    if (!ready) {
      daemonProc.kill();
      throw new Error('Daemon did not start within 6s');
    }
    authToken = readAuthToken(tmpHome);

    // Socket should be created on startup
    const bound = await waitForFile(ACTIVITY_SOCKET_PATH, 3000);
    if (!bound) {
      daemonProc.kill();
      throw new Error('Activity socket was never bound after daemon start');
    }
  }, 15_000);

  afterAll(() => {
    if (process.platform === 'win32') return;
    if (!portWasFree) return;
    spawnSync(process.execPath, [CLI, 'daemon', 'stop'], {
      env: makeEnv(tmpHome),
      timeout: 3000,
    });
    if (daemonProc?.exitCode === null) daemonProc.kill();
    try {
      fs.rmSync(tmpHome, { recursive: true, force: true });
    } catch {}
  });

  it('binds the activity socket on startup', ({ skip }) => {
    if (process.platform === 'win32') skip();
    if (!portWasFree) skip();
    expect(fs.existsSync(ACTIVITY_SOCKET_PATH)).toBe(true);
  });

  it('rebinds the socket after it is unlinked at runtime', async ({ skip }) => {
    if (process.platform === 'win32') skip();
    if (!portWasFree) skip();

    // Simulate the bug: socket disappears (systemd-tmpfiles, manual rm, etc.)
    fs.unlinkSync(ACTIVITY_SOCKET_PATH);
    expect(fs.existsSync(ACTIVITY_SOCKET_PATH)).toBe(false);

    // Daemon should rebind via fs.watch (synchronous on Linux) within a few seconds.
    const rebound = await waitForFile(ACTIVITY_SOCKET_PATH, 5000);
    expect(rebound).toBe(true);

    // After rebind, a fresh activity payload must travel: socket → daemon → SSE broadcast.
    const id = `rebind-test-${Date.now()}`;
    const payload = JSON.stringify({
      id,
      ts: Date.now(),
      tool: 'Bash',
      args: { command: 'echo rebind' },
      status: 'pending',
      agent: 'TestAgent',
    });

    // Open SSE listener, then send the payload — the daemon should broadcast it.
    const ssePromise = waitForActivityEvent(authToken, id, 4000);
    // Brief pause so the SSE GET is established before we send
    await new Promise((r) => setTimeout(r, 200));
    const sent = await sendOverSocket(payload);
    expect(sent).toBe(true);
    expect(await ssePromise).toBe(true);
  }, 15_000);
});
