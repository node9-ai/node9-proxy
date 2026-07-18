/**
 * A4b + A4c integration: a daemon that dies during startup must leave a trace.
 *
 * This is the load-bearing coverage for the 6-day silent-staleness incident. The
 * auto-start spawn used to be stdio:'ignore', so a daemon that crashed on the way
 * up vanished without a single byte anywhere. Two mechanisms replaced that:
 *   A4c — the daemon logs its own benign/fatal exit paths (structured line)
 *   A4b — the spawner redirects the child's STDERR into daemon-startup.log
 *
 * Only an integration test can prove A4b: it is an fd-inheritance property of a
 * detached spawn. No unit test can observe it (CLAUDE.md: unit tests with mocked
 * fs cannot catch filesystem or subprocess bugs).
 *
 * Requires `npm run build`.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync, spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import net from 'net';
import http from 'http';
import { DAEMON_PORT, DAEMON_HOST } from '../auth/daemon';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const REPO_ROOT = path.resolve(__dirname, '../..');
const itUnix = it.skipIf(process.platform === 'win32');

let home: string;
let blocker: net.Server | null = null;
// server.close() waits for OPEN CONNECTIONS to end. The daemon's /settings probe
// leaves one behind, so closing without destroying sockets hangs the afterEach
// until the runner's hook timeout — which reads as a product failure and is not.
const openSockets = new Set<net.Socket>();

function trackSockets(server: net.Server): void {
  server.on('connection', (sock: net.Socket) => {
    openSockets.add(sock);
    sock.on('close', () => openSockets.delete(sock));
  });
}

beforeAll(() => {
  expect(fs.existsSync(CLI), `${CLI} missing — run npm run build`).toBe(true);
});

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-startup-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
});
afterEach(async () => {
  // Reap any daemon this test actually managed to start. Without this, a spawn
  // that unexpectedly SUCCEEDS (e.g. the crash injection silently failed to take)
  // leaves a detached daemon squatting the real port, pointed at a HOME that is
  // about to be deleted — poisoning every later test and the developer's machine.
  try {
    const pidFile = path.join(home, '.node9', 'daemon.pid');
    if (fs.existsSync(pidFile)) {
      const { pid } = JSON.parse(fs.readFileSync(pidFile, 'utf-8'));
      // Never signal this process (the deterministic port-in-use case writes our
      // own pid into that file on purpose).
      if (typeof pid === 'number' && pid !== process.pid) {
        try {
          process.kill(pid, 'SIGTERM');
        } catch {
          /* already gone */
        }
      }
    }
  } catch {
    /* best-effort cleanup */
  }
  if (blocker) {
    for (const sock of openSockets) sock.destroy();
    openSockets.clear();
    await new Promise((r) => blocker!.close(r));
    blocker = null;
  }
  fs.rmSync(home, { recursive: true, force: true });
});

const startupLog = () => path.join(home, '.node9', 'daemon-startup.log');
const readLog = () => (fs.existsSync(startupLog()) ? fs.readFileSync(startupLog(), 'utf-8') : '');

/**
 * Make the daemon port unavailable, deterministically. If binding fails the port
 * is already held by a real daemon on this machine — equally valid for the test,
 * which only needs "the port is occupied", not "occupied by us".
 */
async function occupyDaemonPort(): Promise<void> {
  await new Promise<void>((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve()); // already in use — precondition satisfied
    s.listen(DAEMON_PORT, DAEMON_HOST, () => {
      blocker = s;
      trackSockets(s);
      resolve();
    });
  });
}

function runDaemon(cli = CLI, extraEnv: Record<string, string> = {}) {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  delete baseEnv.NODE9_NO_AUTO_DAEMON;
  delete baseEnv.NODE9_TESTING;
  return spawnSync(process.execPath, [cli, 'daemon'], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(),
    env: { ...baseEnv, HOME: home, USERPROFILE: home, NO_COLOR: '1', ...extraEnv },
  });
}

/**
 * ASYNC daemon runner. Required whenever this process hosts a server the child
 * must talk to: spawnSync blocks the event loop, so an in-process HTTP server can
 * never answer the child's request (documented in check.integration.test.ts). With
 * spawnSync the daemon's /settings probe times out, it retries the bind, and loops
 * until the 60s spawn timeout — a hang, not a result.
 */
function runDaemonAsync(
  extraEnv: Record<string, string> = {},
  timeoutMs = 20000
): Promise<{ code: number | null }> {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  // Never inherit the developer's ambient autostart/testing switches: this repo is
  // dogfooded, so the shell running the suite may itself have NODE9_NO_AUTO_DAEMON
  // set — which silently disables the very behaviour under test and makes the run
  // depend on who is typing.
  delete baseEnv.NODE9_NO_AUTO_DAEMON;
  delete baseEnv.NODE9_TESTING;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'daemon'], {
      env: { ...baseEnv, HOME: home, USERPROFILE: home, NO_COLOR: '1', ...extraEnv },
      cwd: os.tmpdir(),
      stdio: 'ignore',
    });
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`daemon did not exit within ${timeoutMs}ms`));
    }, timeoutMs);
    child.on('exit', (code) => {
      clearTimeout(timer);
      resolve({ code });
    });
    child.on('error', reject);
  });
}

/** A copy of dist/ whose CLI throws at module load when run as `daemon` — the
 *  ERR_REQUIRE_ESM incident shape. node_modules is symlinked because the bundle has
 *  external deps; without it the copy dies with MODULE_NOT_FOUND and any test using
 *  it passes for entirely the wrong reason. */
function crashPackage(condition = 'process.argv[2] === "daemon"'): string {
  const pkg = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-crashpkg-'));
  fs.cpSync(path.join(REPO_ROOT, 'dist'), path.join(pkg, 'dist'), { recursive: true });
  fs.copyFileSync(path.join(REPO_ROOT, 'package.json'), path.join(pkg, 'package.json'));
  fs.symlinkSync(path.join(REPO_ROOT, 'node_modules'), path.join(pkg, 'node_modules'), 'dir');
  // AFTER the shebang (line 2) — prepending to line 1 breaks it and the binary
  // fails to parse instead of crashing at import.
  const cliPath = path.join(pkg, 'dist', 'cli.js');
  const lines = fs.readFileSync(cliPath, 'utf-8').split('\n');
  lines.splice(1, 0, `if (${condition}) { throw new Error("SIMULATED import-time crash"); }`);
  fs.writeFileSync(cliPath, lines.join('\n'), 'utf-8');
  return pkg;
}

describe('A4c — the daemon logs its own startup outcome', () => {
  itUnix('records port-in-use and exits 0 when another daemon owns the port', async () => {
    await occupyDaemonPort();
    // A pid file naming a process that is definitely alive (this test runner) puts
    // the daemon on the "another daemon owns it" branch deterministically, instead
    // of depending on whatever happens to be running on the machine.
    fs.writeFileSync(
      path.join(home, '.node9', 'daemon.pid'),
      JSON.stringify({ pid: process.pid, port: DAEMON_PORT, internalToken: 'x' }),
      'utf-8'
    );

    const r = runDaemon();
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0); // losing a port race is benign, not a failure
    expect(readLog()).toMatch(/daemon-startup:port-in-use/);
  });
});

describe('A4c — an unidentifiable port holder is recorded as a FAILURE, not benign', () => {
  itUnix('records orphan-unidentified when the pid cannot be recovered', async (ctx) => {
    // The daemon answers /settings (so it is healthy) but neither `ss` nor `lsof`
    // can name its pid, so NO pid file is written — and every pid-file-based
    // command keeps reporting "not running" while each new start exits 0. Recording
    // that as benign (an earlier design did) hides an unbounded silent loop.
    await occupyDaemonPort();
    if (blocker) {
      // occupyDaemonPort's plain TCP socket cannot answer the daemon's
      // fetch(/settings) probe, and that probe GATES the branch under test — a raw
      // net.Server never emits 'request', so the daemon would retry forever. Swap
      // in a real HTTP server that answers 200.
      await new Promise<void>((r) => blocker!.close(() => r()));
      blocker = null;
    }
    const healthy = http.createServer((_req, res) => res.writeHead(200).end('{}'));
    const bound = await new Promise<boolean>((resolve) => {
      healthy.once('error', () => resolve(false)); // a real daemon owns the port
      healthy.listen(DAEMON_PORT, DAEMON_HOST, () => resolve(true));
    });
    if (!bound) {
      // SKIP loudly rather than `return`: a bare return reports a green tick for a
      // test that asserted nothing, which is worse than no test because it looks
      // like coverage.
      ctx.skip();
      return;
    }
    blocker = healthy as unknown as net.Server; // afterEach closes it
    trackSockets(blocker);

    // Hide both pid-recovery tools so identification must fail.
    const emptyBin = path.join(home, 'nobin');
    fs.mkdirSync(emptyBin, { recursive: true });
    const { code } = await runDaemonAsync({ PATH: emptyBin });

    expect(code).toBe(0); // still a clean exit — it is not a crash
    const state = JSON.parse(
      fs.readFileSync(path.join(home, '.node9', 'daemon-startup-state.json'), 'utf-8')
    );
    expect(state.outcome).toBe('failed');
    expect(state.kind).toBe('orphan-unidentified');
    // …and the advice must not tell the user to kill a daemon we just proved healthy.
    expect(state.detail).toMatch(/healthy daemon/);
    expect(state.detail).not.toMatch(/stop it/);
    expect(fs.existsSync(path.join(home, '.node9', 'daemon.pid'))).toBe(false);
  });
});

describe('F1 — `node9 daemon --background` is covered by the diagnostic', () => {
  itUnix('leaves a marker when the backgrounded daemon dies at module load', async () => {
    // This is the command doctor RECOMMENDS. Without the parent writing 'starting'
    // first, a child that dies at import records nothing at all — so the user runs
    // the suggested fix, it fails silently, and doctor still shows the previous
    // cause. Without F1 there is no state file here and this assertion fails.
    //
    // The crash must hit the spawned CHILD (`daemon`) and NOT the parent command
    // (`daemon --background`): with the default condition the parent dies at import
    // before it can record anything, and the test measures nothing at all.
    const pkg = crashPackage(
      'process.argv[2] === "daemon" && !process.argv.includes("--background")'
    );
    try {
      const r = spawnSync(
        process.execPath,
        [path.join(pkg, 'dist', 'cli.js'), 'daemon', '--background'],
        {
          encoding: 'utf-8',
          timeout: 30000,
          cwd: os.tmpdir(),
          env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: '1' },
        }
      );
      expect(r.error).toBeUndefined();

      const statePath = path.join(home, '.node9', 'daemon-startup-state.json');
      expect(fs.existsSync(statePath)).toBe(true);
      const state = JSON.parse(fs.readFileSync(statePath, 'utf-8'));
      // 'starting' (nothing resolved it — the child never ran our code) or a
      // conclusive 'failed' if the error listener won the race. Never absent.
      expect(['starting', 'failed']).toContain(state.outcome);
    } finally {
      fs.rmSync(pkg, { recursive: true, force: true });
    }
  });
});

describe('F2 — a port held by a NON-daemon must give up, not spin forever', () => {
  itUnix('records port-unavailable and exits instead of retrying endlessly', async (ctx) => {
    // Unbounded, this is a permanent ~1 Hz loop: EADDRINUSE → no pid file → probe
    // /settings → not a daemon → listen() → EADDRINUSE → … The daemon never serves,
    // never exits, and records nothing beyond 'starting'.
    // WITHOUT the fix this test does not fail — it HANGS until the runner's timeout,
    // which is precisely the defect.
    await occupyDaemonPort();
    if (!blocker) {
      ctx.skip(); // a real daemon owns the port; cannot stand in as a foreign holder
      return;
    }
    // occupyDaemonPort's raw TCP socket is exactly the case under test: it accepts
    // the connection but never answers HTTP, so the /settings probe cannot succeed.

    const { code } = await runDaemonAsync({}, 30000);

    expect(code).toBe(0); // benign, explained exit — NOT a crash, so systemd won't storm
    const state = JSON.parse(
      fs.readFileSync(path.join(home, '.node9', 'daemon-startup-state.json'), 'utf-8')
    );
    expect(state.outcome).toBe('failed');
    expect(state.kind).toBe('port-unavailable');
    expect(state.detail).toMatch(/not a node9 daemon/);
  });
});

describe('A4b — a crash during startup leaves a trace', () => {
  itUnix('captures an IMPORT-TIME crash from the auto-started child', () => {
    // The historical trigger was ERR_REQUIRE_ESM: a module-load failure. It happens
    // before any in-daemon try/catch exists, so the ONLY way it can be captured is
    // the spawner redirecting the child's stderr. If this test still passes after
    // reverting that redirect to stdio:'ignore', the test is wrong, not the code.
    const pkg = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-crashpkg-'));
    try {
      fs.cpSync(path.join(REPO_ROOT, 'dist'), path.join(pkg, 'dist'), { recursive: true });
      fs.copyFileSync(path.join(REPO_ROOT, 'package.json'), path.join(pkg, 'package.json'));
      // The bundle has external deps; without node_modules the copy dies with
      // MODULE_NOT_FOUND and this test would pass for entirely the wrong reason.
      fs.symlinkSync(path.join(REPO_ROOT, 'node_modules'), path.join(pkg, 'node_modules'), 'dir');

      // Inject the crash AFTER the shebang (line 2) — prepending to line 1 breaks
      // the shebang and the binary fails to parse instead of crashing at import.
      const cliPath = path.join(pkg, 'dist', 'cli.js');
      const lines = fs.readFileSync(cliPath, 'utf-8').split('\n');
      lines.splice(
        1,
        0,
        'if (process.argv[2] === "daemon") { throw new Error("SIMULATED import-time crash"); }'
      );
      fs.writeFileSync(cliPath, lines.join('\n'), 'utf-8');

      // `check` auto-starts the daemon. Run it from the COPY so the spawn's
      // packageDist guard resolves against the copy and permits the spawn.
      const r = spawnSync(
        process.execPath,
        [cliPath, 'check', JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } })],
        {
          encoding: 'utf-8',
          timeout: 60000,
          cwd: os.tmpdir(),
          env: {
            ...process.env,
            HOME: home,
            USERPROFILE: home,
            NO_COLOR: '1',
            // this test REQUIRES the auto-start it is measuring
            NODE9_NO_AUTO_DAEMON: '',
            NODE9_TESTING: '',
          },
        }
      );
      expect(r.error).toBeUndefined();

      // The child is detached; give it a moment to die and flush.
      const deadline = Date.now() + 15000;
      while (Date.now() < deadline && !/SIMULATED import-time crash/.test(readLog())) {
        spawnSync(process.execPath, ['-e', 'setTimeout(()=>{},250)']); // ~250ms sync sleep
      }

      const log = readLog();
      expect(log).toMatch(/SIMULATED import-time crash/);
      expect(log).toMatch(/at /); // a real stack, not just a one-line summary

      // …and the machine-readable half: the spawner's marker is still 'starting'
      // because the child died before it could record anything itself. That
      // stranded marker plus a down daemon IS the detection — it is what lets
      // doctor say "did not start" without parsing a line of the stack above.
      const state = JSON.parse(
        fs.readFileSync(path.join(home, '.node9', 'daemon-startup-state.json'), 'utf-8')
      );
      expect(state.outcome).toBe('starting');
    } finally {
      fs.rmSync(pkg, { recursive: true, force: true });
    }
  });
});
