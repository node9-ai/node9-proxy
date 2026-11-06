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
// A port of its own (NODE9_DAEMON_PORT, honoured under NODE9_TESTING=1), so
// the test runs beside a developer's live daemon on 7391 instead of skipping.
let DAEMON_PORT = 0;
async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}
// The daemon picks a private socket path per HOME and records it in its
// daemon.pid (activity-socket-ownership design); read once the daemon is up.
let ACTIVITY_SOCKET_PATH = '';
function socketFromPidFile(home: string): string {
  const pid = JSON.parse(fs.readFileSync(path.join(home, '.node9', 'daemon.pid'), 'utf-8'));
  return String(pid.activitySocket ?? '');
}

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
  // No XDG_RUNTIME_DIR: the test daemon's socket stays under its own HOME and
  // nothing is left in the developer's /run/user directory.
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    NODE9_TESTING: '1',
    NODE9_DAEMON_PORT: String(DAEMON_PORT),
  };
  delete env.XDG_RUNTIME_DIR;
  return env;
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
    // The daemon binds a Windows named pipe (\\.\pipe\node9-activity-<random>), not a
    // socket file under os.tmpdir(). The test's polling/unlink/connect helpers
    // all assume a filesystem socket, so they cannot exercise the rebind path
    // on Windows. The self-heal logic in src/daemon/state.ts is itself gated
    // on `process.platform !== 'win32'` — skipping here matches that contract.
    if (process.platform === 'win32') return;
    if (!fs.existsSync(CLI)) {
      throw new Error(`dist/cli.js not found. Run "npm run build" first. Expected: ${CLI}`);
    }
    DAEMON_PORT = await freePort();
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
    ACTIVITY_SOCKET_PATH = socketFromPidFile(tmpHome);
    if (!ACTIVITY_SOCKET_PATH) {
      daemonProc.kill();
      throw new Error('daemon.pid names no activity socket');
    }
    expect(ACTIVITY_SOCKET_PATH.startsWith(os.tmpdir() + path.sep + 'node9-activity')).toBe(false);

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

    // Simulate the bug: socket disappears (systemd-tmpfiles, manual rm, etc.).
    // We deliberately avoid asserting intermediate state (existsSync, inode
    // comparison) because both race the daemon's own self-heal — the
    // end-to-end SSE assertion below is the only race-free proof of
    // self-heal: if the daemon hadn't rebound, the new connect() would fail
    // with ENOENT, sendOverSocket would return false, and the SSE event
    // would never arrive.
    fs.unlinkSync(ACTIVITY_SOCKET_PATH);

    // Wait for the file to come back. The polling probe runs every ~2s, so
    // the upper bound is one probe interval plus bind latency. Cap at 6s
    // to give comfortable headroom on slow CI runners without blowing
    // overall test runtime.
    const rebound = await waitForFile(ACTIVITY_SOCKET_PATH, 6000);
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

  // Review, 2026-11-03: systemd removes /run/user/<uid> when the user's last
  // session ends, with the daemon still running. Removing the directory must
  // not leave the flight recorder down: the rebind makes it again.
  it('rebinds after the socket directory itself is removed', async ({ skip }) => {
    if (process.platform === 'win32') skip();
    if (!portWasFree) skip();
    fs.rmSync(path.dirname(ACTIVITY_SOCKET_PATH), { recursive: true, force: true });
    expect(await waitForFile(ACTIVITY_SOCKET_PATH, 6000)).toBe(true);
    expect(fs.statSync(path.dirname(ACTIVITY_SOCKET_PATH)).mode & 0o077).toBe(0);
    expect(socketFromPidFile(tmpHome)).toBe(ACTIVITY_SOCKET_PATH);
    const id = `dir-rebind-${Date.now()}`;
    const ssePromise = waitForActivityEvent(authToken, id, 4000);
    await new Promise((r) => setTimeout(r, 200));
    const sent = await sendOverSocket(
      JSON.stringify({ id, ts: Date.now(), tool: 'Bash', args: {}, status: 'pending', agent: 'T' })
    );
    expect(sent).toBe(true);
    expect(await ssePromise).toBe(true);
  }, 15_000);

  // Review of 2026-11-06 (low 2): the agent, as the same user, could remove the
  // socket and bind its own at the same path; the probe only checked that a
  // file existed, so the listener kept receiving every activity line. The
  // probe now compares the socket with the one the daemon bound and binds
  // again when it differs.
  it('a socket swapped in at the path is replaced by the daemon', async ({ skip }) => {
    if (process.platform === 'win32') skip();
    if (!portWasFree) skip();
    const got: string[] = [];
    const squatter = net.createServer((c) => {
      let buf = '';
      c.on('data', (d) => (buf += d.toString()));
      c.on('end', () => {
        got.push(buf);
        c.end();
      });
    });
    try {
      fs.unlinkSync(ACTIVITY_SOCKET_PATH);
      await new Promise<void>((r) => squatter.listen(ACTIVITY_SOCKET_PATH, () => r()));
      const squatIno = fs.statSync(ACTIVITY_SOCKET_PATH).ino;
      // Within one or two probe ticks the daemon binds its own socket again.
      const deadline = Date.now() + 6000;
      while (Date.now() < deadline) {
        try {
          if (fs.statSync(ACTIVITY_SOCKET_PATH).ino !== squatIno) break;
        } catch {}
        await new Promise((r) => setTimeout(r, 100));
      }
      expect(fs.statSync(ACTIVITY_SOCKET_PATH).ino).not.toBe(squatIno);
      const id = `swap-${Date.now()}`;
      const ssePromise = waitForActivityEvent(authToken, id, 4000);
      await new Promise((r) => setTimeout(r, 200));
      expect(
        await sendOverSocket(
          JSON.stringify({
            id,
            ts: Date.now(),
            tool: 'Bash',
            args: {},
            status: 'pending',
            agent: 'T',
          })
        )
      ).toBe(true);
      expect(await ssePromise).toBe(true);
      expect(got.join('')).not.toContain(id);
    } finally {
      // Node's close() unlinks the file at the path, so the daemon rebinds
      // once more; wait for that here, not in the next test's quiet window.
      await new Promise<void>((r) => squatter.close(() => r()));
      await waitForFile(ACTIVITY_SOCKET_PATH, 6000);
      await new Promise((r) => setTimeout(r, 500));
    }
  }, 30_000);

  // Regression test for the rebind-loop bug: an earlier fs.watch-based
  // self-heal would observe the daemon's own unlink-then-listen sequence
  // and trigger another rebind, which fired another inotify event, etc.
  // The polling-only design eliminates this loop. This test would have
  // caught the bug: it spawns a daemon, leaves it idle through ~3 polling
  // cycles, then asserts hook-debug.log shows zero "rebinding" lines.
  it('does not rebind during quiet operation', async ({ skip }) => {
    if (process.platform === 'win32') skip();
    if (!portWasFree) skip();

    const debugLogPath = path.join(tmpHome, '.node9', 'hook-debug.log');
    // Snapshot any pre-existing rebind lines from earlier tests in this
    // suite (e.g., the unlink-then-rebind test runs before this one).
    const baselineRebinds = countRebindLines(debugLogPath);

    // Wait through ~3 polling cycles (probe runs every 2s).
    await new Promise((r) => setTimeout(r, 6500));

    const finalRebinds = countRebindLines(debugLogPath);
    expect(finalRebinds - baselineRebinds).toBe(0);
  }, 15_000);
});

function countRebindLines(logPath: string): number {
  if (!fs.existsSync(logPath)) return 0;
  const contents = fs.readFileSync(logPath, 'utf-8');
  return contents.split('\n').filter((line) => /\[activity-socket\] rebinding/.test(line)).length;
}
