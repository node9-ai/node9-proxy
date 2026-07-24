/**
 * Integration tests for task #18 commit (b): POST /shutdown + startup takeover
 * + the autostart reachability gate.
 *
 * Takeover rule (rogue-daemon-code-design.md §4): on EADDRINUSE with a live
 * pidfile holder, a STRICTLY newer build asks the holder to /shutdown and
 * takes the port; same-or-newer holder → yield (exit 0, ok-elsewhere). The
 * NODE9_BUILD_ID_OVERRIDE env fabricates builds.
 *
 * Port-guarded like daemon.integration.test.ts: suite SKIPS when :7391 is
 * already held (e.g. a real daemon on a dev box); runs in CI.
 */

import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import { autoStartDaemonAndWait } from '../cli/daemon-starter';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const PORT = 7391;
const HOST = '127.0.0.1';

function portFree(): Promise<boolean> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(PORT, HOST);
  });
}

function makeTempHome(): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-takeover-test-'));
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(tmpHome, '.node9', 'config.json'),
    JSON.stringify({ settings: { mode: 'audit', autoStartDaemon: false } })
  );
  return tmpHome;
}

function startDaemon(home: string, buildOverride: string): ChildProcess {
  return spawn(process.execPath, [CLI, 'daemon'], {
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_BUILD_ID_OVERRIDE: buildOverride,
    },
    stdio: 'ignore',
    detached: false,
  });
}

async function health(): Promise<Record<string, unknown> | null> {
  try {
    const res = await fetch(`http://${HOST}:${PORT}/health`, { signal: AbortSignal.timeout(1500) });
    if (!res.ok) return null;
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function waitFor(pred: () => Promise<boolean>, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await pred()) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

const kids: ChildProcess[] = [];
const homes: string[] = [];
let free = false;

beforeAll(async () => {
  if (!fs.existsSync(CLI)) throw new Error(`dist/cli.js not found — run "npm run build" first`);
  free = await portFree();
});

afterEach(async () => {
  for (const k of kids.splice(0)) {
    if (k.pid) {
      try {
        process.kill(k.pid, 'SIGTERM');
      } catch {
        /* gone */
      }
    }
  }
  await waitFor(portFree, 5000);
  for (const h of homes.splice(0)) {
    try {
      fs.rmSync(h, { recursive: true, force: true });
    } catch {
      /* Windows EBUSY */
    }
  }
});

async function boot(build: string): Promise<{ home: string; child: ChildProcess }> {
  const home = makeTempHome();
  homes.push(home);
  const child = startDaemon(home, build);
  kids.push(child);
  const up = await waitFor(async () => (await health()) !== null, 15000);
  if (!up) throw new Error(`daemon (${build}) did not serve /health in 15s`);
  return { home, child };
}

describe('startup takeover + /shutdown (task #18 commit b)', () => {
  it('a STRICTLY newer build takes over the port; the old daemon exits', async (ctx) => {
    if (!free) return ctx.skip();
    const a = await boot('1.63.0+1000');
    const oldPid = (await health())?.pid;
    expect(oldPid).toBe(a.child.pid);

    // Same HOME so the challenger can read the holder's pidfile token.
    const b = startDaemon(a.home, '1.63.0+2000');
    kids.push(b);
    const tookOver = await waitFor(async () => (await health())?.buildId === '1.63.0+2000', 15000);
    expect(tookOver).toBe(true);
    expect((await health())?.pid).toBe(b.pid);
    // Pidfile now names the new daemon.
    const pidfile = JSON.parse(
      fs.readFileSync(path.join(a.home, '.node9', 'daemon.pid'), 'utf-8')
    ) as Record<string, unknown>;
    expect(pidfile.pid).toBe(b.pid);
  }, 40000);

  it('an OLDER (or equal) challenger yields — never a downgrade, never churn', async (ctx) => {
    if (!free) return ctx.skip();
    const a = await boot('1.63.0+2000');
    for (const build of ['1.63.0+1000', '1.63.0+2000']) {
      const b = startDaemon(a.home, build);
      kids.push(b);
      const exited = await waitFor(async () => b.exitCode !== null, 15000);
      expect(exited).toBe(true);
      expect(b.exitCode).toBe(0); // stable condition — exit 0, no restart storm
      expect((await health())?.pid).toBe(a.child.pid); // A still serves
    }
  }, 40000);

  it('POST /shutdown: 401 without the token; exits gracefully with it', async (ctx) => {
    if (!free) return ctx.skip();
    const a = await boot('1.63.0+1000');
    const noToken = await fetch(`http://${HOST}:${PORT}/shutdown`, { method: 'POST' });
    expect(noToken.status).toBe(401);
    expect((await health())?.pid).toBe(a.child.pid); // still up

    const token = (
      JSON.parse(fs.readFileSync(path.join(a.home, '.node9', 'daemon.pid'), 'utf-8')) as Record<
        string,
        unknown
      >
    ).internalToken as string;
    const ok = await fetch(`http://${HOST}:${PORT}/shutdown`, {
      method: 'POST',
      headers: { 'x-node9-internal': token },
    });
    expect(ok.status).toBe(200);
    expect(await waitFor(async () => a.child.exitCode !== null, 10000)).toBe(true);
  }, 40000);
});

describe('autostart reachability gate (task #18 commit b)', () => {
  it('does not spawn a competing daemon when one is already serving', async (ctx) => {
    // Must own a CONTROLLED /settings→200 stub on :7391. Relying on an
    // uncontrolled occupant (a sibling test file's daemon, mid-setup/teardown)
    // was flaky in CI — parallel workers contend for the one hardcoded port.
    // Bind our own; if a sibling holds it, SKIP (the file's port-guard rule).
    const http = await import('http');
    const stub = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
    const bound = await new Promise<boolean>((resolve) => {
      stub.once('error', () => resolve(false)); // EADDRINUSE — a sibling owns it
      stub.listen(PORT, HOST, () => resolve(true));
    });
    if (!bound) return ctx.skip();

    // Observable-effects assertion (ESM namespaces can't be spied): with an
    // isolated HOME, the gate must (1) return true, (2) log the skip, and
    // (3) NEVER record a 'starting' attempt — 'starting' is written strictly
    // before any spawn, so its absence proves no competitor was launched.
    const home = makeTempHome();
    const prev = { t: process.env.NODE9_TESTING, h: process.env.HOME, u: process.env.USERPROFILE };
    delete process.env.NODE9_TESTING; // the gate must fire before the testing guard
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    try {
      const result = await autoStartDaemonAndWait();
      expect(result).toBe(true); // our stub IS serving → gate returns true
      const dbg = path.join(home, '.node9', 'hook-debug.log');
      expect(fs.existsSync(dbg) && fs.readFileSync(dbg, 'utf-8')).toContain('already-serving');
      expect(fs.existsSync(path.join(home, '.node9', 'daemon-startup-state.json'))).toBe(false);
    } finally {
      if (prev.t !== undefined) process.env.NODE9_TESTING = prev.t;
      if (prev.h !== undefined) process.env.HOME = prev.h;
      if (prev.u !== undefined) process.env.USERPROFILE = prev.u;
      else delete process.env.USERPROFILE;
      fs.rmSync(home, { recursive: true, force: true });
      await new Promise((r) => stub.close(r));
    }
  }, 15000);
});
