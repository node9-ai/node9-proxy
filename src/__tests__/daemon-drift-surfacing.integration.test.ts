/**
 * Task #18 (G-A) — `node9 status` / `node9 doctor` must SURFACE build drift.
 *
 * The takeover logic (server.ts decideAgainstHolder) only reconciles builds at
 * daemon STARTUP. A daemon that started before an in-place upgrade and is never
 * restarted keeps enforcing OLD code — and `systemctl restart` silently no-ops
 * because the port is held. The only thing that tells the user is the drift line
 * in status/doctor. `describeBuildDrift` (the pure fn) is unit-tested; this
 * proves the WIRING — that the commands actually render it against a live,
 * drifted daemon — which no test covered (a regression could delete the line
 * silently).
 *
 * Port-guarded (skips when :7391 is already held) like the takeover suite; a
 * real daemon is spawned on the port with a fabricated OLD build via
 * NODE9_BUILD_ID_OVERRIDE, and the CLI is run with a NEWER override so its
 * CURRENT_BUILD deterministically differs from the daemon's — no dependence on
 * the real dist mtime.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
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
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-drift-test-'));
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

/** Run a CLI command with its OWN build identity (so its CURRENT_BUILD is the
 *  "installed" side of the comparison), against the daemon in `home`. */
function runCli(cmd: string, home: string, installedBuild: string): string {
  const r = spawnSync(process.execPath, [CLI, cmd], {
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      NODE9_BUILD_ID_OVERRIDE: installedBuild,
    },
    encoding: 'utf-8',
    timeout: 15000,
  });
  expect(r.error).toBeUndefined();
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
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
  if (!fs.existsSync(CLI)) throw new Error('dist/cli.js not found — run "npm run build" first');
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

async function bootDaemon(home: string, build: string): Promise<void> {
  const child = startDaemon(home, build);
  kids.push(child);
  const up = await waitFor(async () => (await health())?.buildId === build, 15000);
  if (!up) throw new Error(`daemon (${build}) did not serve /health in 15s`);
}

describe('task #18 G-A — status/doctor surface build drift (real daemon)', () => {
  it('status warns when the running daemon is a DIFFERENT build than installed', async (ctx) => {
    if (!free) return ctx.skip();
    const home = makeTempHome();
    homes.push(home);
    await bootDaemon(home, '1.0.0+1'); // an OLD daemon holds the port
    const out = runCli('status', home, '9.9.9+9'); // CLI thinks the installed build is newer
    // The daemon section must flag the mismatch — assert on structure/intent,
    // not the exact sentence (copy-change resilient).
    expect(out.toLowerCase()).toMatch(/different build|older|enforcing/);
    expect(out).toContain('1.0.0'); // names the running build
  });

  it('doctor warns on the same drift', async (ctx) => {
    if (!free) return ctx.skip();
    const home = makeTempHome();
    homes.push(home);
    await bootDaemon(home, '1.0.0+1');
    const out = runCli('doctor', home, '9.9.9+9');
    expect(out.toLowerCase()).toMatch(/different build|older|enforcing/);
  });

  it('status does NOT warn when the running build matches installed', async (ctx) => {
    if (!free) return ctx.skip();
    const home = makeTempHome();
    homes.push(home);
    await bootDaemon(home, '5.5.5+5');
    const out = runCli('status', home, '5.5.5+5'); // same build → no drift
    expect(out.toLowerCase()).not.toMatch(/different build|enforcing (?:a )?different|older than/);
  });
});
