/**
 * Integration tests for GET /health + the versioned pidfile (task #18, commit a).
 *
 * The daemon must report WHICH build it is running — and report the build it
 * LOADED, not the file currently on disk (the capture-at-start invariant, G3:
 * a rebuild after daemon start must NOT change the served buildId, otherwise
 * a same-version takeover can never fire).
 *
 * Requirements (same harness rules as daemon.integration.test.ts):
 *   - `npm run build` before running — asserts dist/cli.js exists
 *   - Port 7391 must be free — suite SKIPS when another daemon is serving
 *   - Isolated HOME
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'child_process';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const DAEMON_PORT = 7391;
const HOST = '127.0.0.1';

function portFree(): Promise<boolean> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.once('listening', () => srv.close(() => resolve(true)));
    srv.listen(DAEMON_PORT, HOST);
  });
}

function makeTempHome(): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-health-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(
    path.join(node9Dir, 'config.json'),
    JSON.stringify({ settings: { mode: 'audit', autoStartDaemon: false } })
  );
  return tmpHome;
}

async function waitFor(pred: () => Promise<boolean>, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await pred()) return true;
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

async function getJson(pathname: string): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`http://${HOST}:${DAEMON_PORT}${pathname}`, {
    signal: AbortSignal.timeout(2000),
  });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON */
  }
  return { status: res.status, body };
}

let free = false;
let child: ChildProcess | null = null;
let home = '';

beforeAll(async () => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found — run "npm run build" first. Expected: ${CLI}`);
  }
  free = await portFree();
  if (!free) return; // suite skips below
  home = makeTempHome();
  child = spawn(process.execPath, [CLI, 'daemon'], {
    env: { ...process.env, HOME: home, USERPROFILE: home, NODE9_TESTING: '1' },
    stdio: 'ignore',
    detached: false,
  });
  const up = await waitFor(async () => {
    try {
      return (await getJson('/settings')).status === 200;
    } catch {
      return false;
    }
  }, 15000);
  if (!up) throw new Error('daemon did not come up on :7391 within 15s');
}, 20000);

afterAll(async () => {
  if (child?.pid) {
    try {
      process.kill(child.pid, 'SIGTERM');
    } catch {
      /* already gone */
    }
  }
  if (home) {
    try {
      fs.rmSync(home, { recursive: true, force: true });
    } catch {
      /* Windows EBUSY — leaked temp dir is harmless */
    }
  }
});

describe('GET /health + versioned pidfile (task #18 commit a)', () => {
  it('serves {version, buildId, pid, startedAt, autoStarted}', async (ctx) => {
    if (!free) return ctx.skip();
    const { status, body } = await getJson('/health');
    expect(status).toBe(200);
    const h = body as Record<string, unknown>;
    const pkg = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, '../../package.json'), 'utf-8')
    ) as { version: string };
    expect(h.version).toBe(pkg.version);
    expect(typeof h.buildId).toBe('string');
    expect(h.buildId).toMatch(/^\d+\.\d+\.\d+.*\+\d+$/);
    expect(h.pid).toBe(child?.pid);
    expect(typeof h.startedAt).toBe('string');
    expect(Number.isNaN(Date.parse(h.startedAt as string))).toBe(false);
    expect(h.autoStarted).toBe(false);
  });

  it('pidfile carries version/buildId/startedAt alongside the existing fields', async (ctx) => {
    if (!free) return ctx.skip();
    const pidfile = JSON.parse(
      fs.readFileSync(path.join(home, '.node9', 'daemon.pid'), 'utf-8')
    ) as Record<string, unknown>;
    expect(pidfile.pid).toBe(child?.pid);
    expect(typeof pidfile.internalToken).toBe('string'); // existing fields intact
    expect(typeof pidfile.version).toBe('string');
    expect(typeof pidfile.buildId).toBe('string');
    expect(typeof pidfile.startedAt).toBe('string');
    const health = (await getJson('/health')).body as Record<string, unknown>;
    expect(pidfile.buildId).toBe(health.buildId); // one identity, two surfaces
  });

  it('G3: rebuilding dist AFTER daemon start does not change the served buildId', async (ctx) => {
    if (!free) return ctx.skip();
    const before = ((await getJson('/health')).body as Record<string, unknown>).buildId;
    const orig = fs.statSync(CLI);
    // Simulate a rebuild: bump the entry file's mtime under the running daemon.
    fs.utimesSync(CLI, orig.atime, new Date());
    try {
      const after = ((await getJson('/health')).body as Record<string, unknown>).buildId;
      expect(after).toBe(before); // captured at start, never re-stat'd
    } finally {
      fs.utimesSync(CLI, orig.atime, orig.mtime); // restore the real mtime
    }
  });
});
