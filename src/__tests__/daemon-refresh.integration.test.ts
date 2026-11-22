/**
 * Integration tests for "a hook on a newer build refreshes an older daemon"
 * (docs/roadmap/active/daemon-stale-refresh-design.md).
 *
 * After `npm install -g node9-ai` the daemon that is already running kept the
 * old code until the next login: a newer build takes the port over only when
 * a new daemon process starts, and a hook started one only when none ran.
 * Now `node9 check` on the newer build starts `node9 daemon refresh`.
 *
 * Every daemon here has a HOME and a port of its own (NODE9_DAEMON_PORT,
 * honoured under NODE9_TESTING=1), so a developer's live daemon is never
 * touched and the suite runs with :7391 held. NODE9_BUILD_ID_OVERRIDE gives a
 * daemon an older or newer build than the dist under test.
 *
 * Requires `npm run build`.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawn, spawnSync, type ChildProcess, type SpawnSyncReturns } from 'child_process';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import { keySafeEnv } from './helpers/env';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const VERSION = (
  JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../package.json'), 'utf-8')) as {
    version: string;
  }
).version;
const OLD_BUILD = '1.0.0+1';
const PAYLOAD = JSON.stringify({
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command: 'ls' },
  cwd: os.tmpdir(),
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      server.close(() => resolve(port));
    });
  });
}

async function waitFor(pred: () => Promise<boolean> | boolean, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await pred()) return true;
    await sleep(150);
  }
  return false;
}

interface Box {
  home: string;
  project: string;
  port: number;
  /** The daemon this test started (the one a refresh replaces). */
  first: ChildProcess;
  env(extra?: Record<string, string>): Record<string, string | undefined>;
  health(): Promise<Record<string, unknown> | null>;
  pidFile(): Record<string, unknown>;
  writePidFile(content: Record<string, unknown>): void;
  stamp(): { build: string; attempts: number; at: number; reason?: string } | null;
  log(name: string): string;
  check(extra?: Record<string, string>): SpawnSyncReturns<string>;
  refresh(): SpawnSyncReturns<string>;
  doctor(): SpawnSyncReturns<string>;
}

const boxes: Box[] = [];

/** A HOME, a port, and a daemon of `build` (null: the build under test). */
async function boot(build: string | null, settings: Record<string, unknown> = {}): Promise<Box> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-refresh-'));
  const dir = path.join(home, '.node9');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'config.json'),
    JSON.stringify({ settings: { mode: 'audit', autoStartDaemon: true, ...settings } })
  );
  const port = await freePort();
  // The tool call's directory: a project, not HOME. No node9.config.json in it.
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-refresh-proj-'));
  const env = (extra: Record<string, string> = {}) => {
    const base = keySafeEnv({
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_DAEMON_PORT: String(port),
      NO_COLOR: '1',
    });
    // The developer's shell must not decide what these rows test.
    delete base.NODE9_NO_AUTO_DAEMON;
    delete base.NODE9_BUILD_ID_OVERRIDE;
    delete base.NODE9_AUTO_STARTED;
    return { ...base, ...extra };
  };
  const first = spawn(process.execPath, [CLI, 'daemon'], {
    env: env(build ? { NODE9_BUILD_ID_OVERRIDE: build } : {}),
    cwd: home,
    stdio: 'ignore',
  });
  const read = (file: string): string => {
    try {
      return fs.readFileSync(path.join(dir, file), 'utf-8');
    } catch {
      return '';
    }
  };
  const run = (args: string[], extra: Record<string, string> = {}) => {
    const r = spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf-8',
      timeout: 60_000,
      cwd: project, // not the repo: its node9.config.json must not apply
      env: env(extra),
    });
    expect(r.error).toBeUndefined();
    expect(r.status).not.toBeNull();
    return r;
  };
  const box: Box = {
    home,
    project,
    port,
    first,
    env,
    async health() {
      // Twice: fetch keeps connections alive, and the first request after a
      // refresh can pick a socket of the daemon that has just left.
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const res = await fetch(`http://127.0.0.1:${port}/health`, {
            signal: AbortSignal.timeout(1000),
          });
          return res.ok ? ((await res.json()) as Record<string, unknown>) : null;
        } catch {
          /* try once more */
        }
      }
      return null;
    },
    pidFile: () => JSON.parse(read('daemon.pid') || '{}') as Record<string, unknown>,
    writePidFile: (content) =>
      fs.writeFileSync(path.join(dir, 'daemon.pid'), JSON.stringify(content), { mode: 0o600 }),
    stamp() {
      const raw = read('.daemon-refresh-stamp');
      return raw ? (JSON.parse(raw) as ReturnType<Box['stamp']>) : null;
    },
    log: read,
    check: (extra) => run(['check', PAYLOAD], extra),
    refresh: () => run(['daemon', 'refresh']),
    doctor: () => run(['doctor']),
  };
  boxes.push(box);
  const up = await waitFor(async () => (await box.health()) !== null, 15_000);
  if (!up) throw new Error(`daemon (${build ?? 'this build'}) did not serve /health in 15s`);
  return box;
}

const refreshLines = (b: Box): string[] =>
  b
    .log('daemon-startup.log')
    .split('\n')
    .filter((l) => l.includes('[refresh]'));

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`dist/cli.js not found — run "npm run build" first`);
});

afterEach(async () => {
  for (const b of boxes.splice(0)) {
    // The refreshed daemon is detached from this process: stop it by the pid
    // it answers with, and the first one by its handle.
    const pids = new Set<number>();
    const serving = (await b.health())?.pid;
    if (typeof serving === 'number') pids.add(serving);
    if (b.first.pid && b.first.exitCode === null) pids.add(b.first.pid);
    for (const pid of pids) {
      try {
        process.kill(pid, 'SIGTERM');
      } catch {
        /* gone */
      }
    }
    await waitFor(async () => (await b.health()) === null, 5000);
    for (const dir of [b.home, b.project]) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        /* Windows EBUSY */
      }
    }
  }
});

describe('a hook on a newer build refreshes an older daemon', () => {
  it('node9 check replaces a daemon of an older build, and its own output does not change', async () => {
    // What the hook prints with no drift: a daemon of this very build.
    const same = await boot(null);
    const quiet = same.check();
    expect(quiet.status).toBe(0);
    expect(same.stamp()).toBeNull(); // same build: no attempt, no helper

    const b = await boot(OLD_BUILD);
    expect((await b.health())?.buildId).toBe(OLD_BUILD);
    const oldPid = b.first.pid;
    // The daemons installed today write no `entry` into the pid file: an
    // older VERSION must be replaced without it.
    const { entry: _entry, ...asToday } = b.pidFile();
    expect(_entry).toBe(fs.realpathSync(CLI));
    b.writePidFile(asToday);

    const r = b.check();
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(quiet.stdout);
    expect(r.stderr).toBe(quiet.stderr);

    const refreshed = await waitFor(async () => (await b.health())?.version === VERSION, 25_000);
    expect(refreshed, b.log('daemon-startup.log')).toBe(true);
    const now = await b.health();
    expect(now?.buildId).not.toBe(OLD_BUILD);
    expect(now?.pid).not.toBe(oldPid);
    // The old process left through its own /shutdown: exit 0, not a signal.
    expect(await waitFor(() => b.first.exitCode !== null, 5000)).toBe(true);
    expect(b.first.exitCode).toBe(0);
    expect(b.pidFile().pid).toBe(now?.pid);
    // The new daemon runs from HOME, not from the project of the tool call
    // that found the old one stale: a daemon reads node9.config.json from its
    // own working directory.
    if (process.platform === 'linux') {
      expect(fs.readlinkSync(`/proc/${String(now?.pid)}/cwd`)).toBe(fs.realpathSync(b.home));
    }
    // One line for the person reading the log, and the throttle is cleared.
    expect(await waitFor(() => refreshLines(b).length > 0, 5000)).toBe(true);
    expect(refreshLines(b)).toHaveLength(1);
    expect(refreshLines(b)[0]).toContain(`ok ${OLD_BUILD} -> ${String(now?.buildId)}`);
    expect(await waitFor(() => b.stamp() === null, 5000)).toBe(true);
  }, 60_000);

  it('autoStartDaemon: false — the daemon stays, and the reason is recorded once', async () => {
    const b = await boot(OLD_BUILD, { autoStartDaemon: false });
    expect(b.check().status).toBe(0);
    expect(b.check().status).toBe(0);
    expect(b.stamp()).toBeNull(); // no attempt was counted, so no helper was started
    const lines = b
      .log('hook-debug.log')
      .split('\n')
      .filter((l) => l.includes('daemon-refresh-skip'));
    expect(lines).toHaveLength(1); // throttled: two calls, one line
    expect(lines[0]).toContain('autoStartDaemon=false');
    expect((await b.health())?.buildId).toBe(OLD_BUILD);
  }, 40_000);

  it('NODE9_NO_AUTO_DAEMON — the daemon stays', async () => {
    const b = await boot(OLD_BUILD);
    expect(b.check({ NODE9_NO_AUTO_DAEMON: '1' }).status).toBe(0);
    expect(b.stamp()).toBeNull();
    expect(b.log('hook-debug.log')).toContain('daemon-refresh-skip: NODE9_NO_AUTO_DAEMON');
    expect((await b.health())?.buildId).toBe(OLD_BUILD);
  }, 40_000);

  it('a daemon NEWER than the hook is never replaced (no downgrade)', async () => {
    const b = await boot('99.0.0+1');
    expect(b.check().status).toBe(0);
    expect(b.stamp()).toBeNull();
    expect((await b.health())?.buildId).toBe('99.0.0+1');
    expect(b.first.exitCode).toBeNull();
  }, 40_000);

  it('a rebuild of the same version refreshes the daemon of THIS install only', async () => {
    // Same version, older file: what `npm run build` in a linked checkout leaves.
    const rebuilt = `${VERSION}+1`;

    // A daemon that runs from another checkout: `check` from here must not
    // replace it with this checkout's code, however new this dist is.
    const other = await boot(rebuilt);
    other.writePidFile({ ...other.pidFile(), entry: '/somewhere/else/dist/cli.js' });
    expect(other.check().status).toBe(0);
    expect(other.stamp()).toBeNull();
    // A daemon from before the entry field: unknown install, left alone too.
    const noEntry = other.pidFile();
    delete noEntry.entry;
    other.writePidFile(noEntry);
    expect(other.check().status).toBe(0);
    expect(other.stamp()).toBeNull();
    expect((await other.health())?.buildId).toBe(rebuilt);

    // The daemon of this install: refreshed.
    const mine = await boot(rebuilt);
    expect(mine.pidFile().entry).toBe(fs.realpathSync(CLI));
    expect(mine.check().status).toBe(0);
    const refreshed = await waitFor(
      async () => ((await mine.health())?.buildId ?? rebuilt) !== rebuilt,
      25_000
    );
    expect(refreshed, mine.log('daemon-startup.log')).toBe(true);
    expect((await mine.health())?.version).toBe(VERSION);
  }, 60_000);

  it('a pid file that names an older build than the daemon on the port does not start a helper per call', async () => {
    // The daemon is this build; only its pid file says otherwise.
    const b = await boot(null);
    const current = (await b.health())?.buildId;
    b.writePidFile({ ...b.pidFile(), buildId: OLD_BUILD });

    expect(b.check().status).toBe(0);
    const armed = b.stamp();
    expect(armed?.attempts).toBe(1);
    // The helper finds the daemon current and does nothing. It must leave the
    // stamp: cleared, the next call would start another helper, and the next.
    const lock = path.join(b.home, '.node9', '.daemon-refresh.lock');
    await sleep(500);
    expect(await waitFor(() => !fs.existsSync(lock), 20_000)).toBe(true);
    expect(b.stamp()).toEqual(armed);
    expect(b.check().status).toBe(0);
    expect(b.stamp()).toEqual(armed); // inside the delay: not counted again
    expect((await b.health())?.buildId).toBe(current);
    expect(b.first.exitCode).toBeNull();
    expect(refreshLines(b)).toHaveLength(0);
  }, 60_000);

  it('a holder that cannot be authenticated: one attempt, then the backoff', async () => {
    const b = await boot(OLD_BUILD);
    // The pid file's token no longer opens /shutdown (the fabricated-token case).
    b.writePidFile({ ...b.pidFile(), internalToken: 'not-the-token' });

    expect(b.check().status).toBe(0);
    expect(b.stamp()?.attempts).toBe(1); // counted before the helper started
    expect(b.check().status).toBe(0); // inside the 1 min delay: nothing new
    expect(b.stamp()?.attempts).toBe(1);

    // The one helper gives up after its verify window and says why.
    const gaveUp = await waitFor(() => b.stamp()?.reason !== undefined, 30_000);
    expect(gaveUp, b.log('daemon-startup.log')).toBe(true);
    expect(b.stamp()?.reason).toContain(`still ${OLD_BUILD}`);
    expect(refreshLines(b)).toHaveLength(1);
    expect(refreshLines(b)[0]).toContain('not done');
    expect((await b.health())?.buildId).toBe(OLD_BUILD);
    expect(b.first.exitCode).toBeNull(); // never signalled

    // doctor names the cause next to the drift line, in place of the bare hint.
    const doctor = b.doctor().stdout;
    expect(doctor).toContain('it is enforcing a different build');
    expect(doctor).toContain(`Automatic refresh did not work: a new daemon was started`);
    expect(doctor).not.toContain('       Run: node9 daemon restart');

    // Still inside the delay. Once it has passed, the next call is attempt 2,
    // and the delay after it is longer.
    expect(b.check().status).toBe(0);
    expect(b.stamp()?.attempts).toBe(1);
    const stamp = b.stamp()!;
    fs.writeFileSync(
      path.join(b.home, '.node9', '.daemon-refresh-stamp'),
      JSON.stringify({ ...stamp, at: Date.now() - 61_000 })
    );
    expect(b.check().status).toBe(0);
    expect(b.stamp()?.attempts).toBe(2);
    expect(b.check().status).toBe(0);
    expect(b.stamp()?.attempts).toBe(2);
    // Let the second helper finish before the box is removed.
    await waitFor(() => refreshLines(b).length === 2, 30_000);
    expect((await b.health())?.buildId).toBe(OLD_BUILD);
  }, 120_000);
});

describe('node9 daemon refresh, by hand', () => {
  it('replaces an older daemon, and says "up to date" when there is nothing to do', async () => {
    const b = await boot(OLD_BUILD);
    const r = b.refresh();
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain(`Daemon refreshed: 1.0.0 -> ${VERSION}`);
    expect((await b.health())?.version).toBe(VERSION);
    expect(b.first.exitCode).toBe(0);

    const again = b.refresh();
    expect(again.status).toBe(0);
    expect(again.stdout).toContain('Daemon is up to date');
    expect(refreshLines(b)).toHaveLength(1); // the second run did nothing
  }, 60_000);

  it('one helper at a time: a second one leaves while the first holds the lock', async () => {
    const b = await boot(OLD_BUILD);
    const lock = path.join(b.home, '.node9', '.daemon-refresh.lock');
    fs.writeFileSync(lock, '12345');

    const second = b.refresh();
    expect(second.status).toBe(0);
    expect(second.stdout).toContain('Another daemon refresh is in progress');
    expect((await b.health())?.buildId).toBe(OLD_BUILD);
    expect(fs.existsSync(lock)).toBe(true); // not its lock to remove

    // A lock nobody can still hold (its helper was killed) is taken over.
    const longAgo = new Date(Date.now() - 5 * 60_000);
    fs.utimesSync(lock, longAgo, longAgo);
    const r = b.refresh();
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('Daemon refreshed');
    expect(fs.existsSync(lock)).toBe(false); // released
  }, 60_000);

  it('says so when no daemon is running', async () => {
    const b = await boot(OLD_BUILD);
    b.first.kill('SIGTERM');
    expect(await waitFor(async () => (await b.health()) === null, 5000)).toBe(true);
    const r = b.refresh();
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('not running');
  }, 40_000);

  it('waits for an open approval card, then refreshes once it is decided', async () => {
    const b = await boot(OLD_BUILD, {
      mode: 'standard',
      approvalTimeoutMs: 60_000,
      approvers: { native: false, browser: false, cloud: false, terminal: true },
    });
    const base = `http://127.0.0.1:${b.port}`;
    const opened = await fetch(`${base}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolName: 'bash',
        args: { command: 'echo held-for-a-person' },
        fromCLI: true,
        localSmartRuleMatched: true,
      }),
    });
    expect(opened.ok).toBe(true);
    const { id } = (await opened.json()) as { id: string };
    expect((await b.health())?.openCards).toBe(1);

    const held = b.refresh();
    expect(held.status).toBe(0);
    expect(held.stdout).toContain('1 approval card(s) are waiting');
    expect((await b.health())?.buildId).toBe(OLD_BUILD); // the card's daemon is untouched
    expect(b.stamp()).toMatchObject({ attempts: 1 }); // the hook waits 1 min, then asks again
    expect(refreshLines(b)[0]).toContain('put off');

    const decided = await fetch(`${base}/decision/${id}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Node9-Internal': String(b.pidFile().internalToken),
      },
      body: JSON.stringify({ decision: 'deny', source: 'terminal' }),
    });
    expect(decided.status).toBe(200);
    expect((await b.health())?.openCards).toBe(0);

    const r = b.refresh();
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('Daemon refreshed');
    expect((await b.health())?.version, b.log('daemon-startup.log')).toBe(VERSION);
    expect(b.stamp()).toBeNull();
  }, 60_000);
});
