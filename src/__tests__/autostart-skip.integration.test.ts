/**
 * A4a integration: when the enforcement hot path finds the daemon down and does
 * NOT auto-start it, it must leave a throttled breadcrumb saying WHY. Before this,
 * "why didn't the daemon come up?" was unanswerable — the root cause of a 6-day
 * silent policy staleness incident.
 *
 * Must be an integration test, not a unit test: the breadcrumb is written by a
 * spawned `dist/cli.js` to a HOME-derived path, and CLAUDE.md requires integration
 * coverage for subprocess commands, file writes, and HOME-dependent behavior. A
 * mocked-fs unit test cannot catch the very bug this file's last case guards.
 *
 * NOTE: these tests deliberately do NOT set NODE9_TESTING=1 (the convention in
 * check.integration.test.ts) — isTestingMode() short-circuits the exact branch
 * under test, so a test that set it would pass while asserting nothing.
 *
 * Requires `npm run build`.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const PAYLOAD = JSON.stringify({
  tool_name: 'Bash',
  tool_input: { command: 'ls' },
  cwd: '/tmp',
});

let home: string;

beforeAll(() => {
  expect(fs.existsSync(CLI), `${CLI} missing — run npm run build`).toBe(true);
});

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-skip-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

/** Run `node9 check` against the isolated HOME. NODE9_TESTING is intentionally absent. */
function runCheck(env: Record<string, string> = {}) {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  delete baseEnv.NODE9_TESTING; // would short-circuit the branch under test
  const r = spawnSync(process.execPath, [CLI, 'check', PAYLOAD], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(), // don't pick up the repo's own node9.config.json
    env: { ...baseEnv, HOME: home, USERPROFILE: home, NO_COLOR: '1', ...env },
  });
  expect(r.error).toBeUndefined();
  expect(r.status).not.toBeNull();
  return r;
}

const hookDebug = () => path.join(home, '.node9', 'hook-debug.log');
const stamp = () => path.join(home, '.node9', '.autostart-skip-stamp');

function breadcrumbs(): string[] {
  if (!fs.existsSync(hookDebug())) return [];
  return fs
    .readFileSync(hookDebug(), 'utf-8')
    .split('\n')
    .filter((l) => l.includes('daemon-autostart-skip'));
}

const withNode9Dir = () => fs.mkdirSync(path.join(home, '.node9'), { recursive: true });

describe('A4a — the hot path records WHY a down daemon was not started', () => {
  it('records NODE9_NO_AUTO_DAEMON as the reason', () => {
    withNode9Dir();
    runCheck({ NODE9_NO_AUTO_DAEMON: '1' });
    expect(breadcrumbs()[0]).toMatch(/daemon-autostart-skip: NODE9_NO_AUTO_DAEMON/);
  });

  it('records autoStartDaemon=false as the reason', () => {
    withNode9Dir();
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { autoStartDaemon: false } }),
      'utf-8'
    );
    runCheck();
    expect(breadcrumbs()[0]).toMatch(/daemon-autostart-skip: autoStartDaemon=false/);
  });

  it('throttles: a second immediate call does not duplicate the breadcrumb', () => {
    withNode9Dir();
    runCheck({ NODE9_NO_AUTO_DAEMON: '1' });
    runCheck({ NODE9_NO_AUTO_DAEMON: '1' });
    // This runs on the enforcement hot path — one line per tool call would bury
    // hook-debug.log.
    expect(breadcrumbs()).toHaveLength(1);
    expect(fs.existsSync(stamp())).toBe(true);
  });

  it('logs again once the throttle window has passed', () => {
    withNode9Dir();
    runCheck({ NODE9_NO_AUTO_DAEMON: '1' });
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000); // window is 1h
    fs.utimesSync(stamp(), old, old);
    runCheck({ NODE9_NO_AUTO_DAEMON: '1' });
    expect(breadcrumbs()).toHaveLength(2);
  });

  it('arms the throttle even when the breadcrumb cannot be written', () => {
    // This runs once per tool call on the enforcement hot path, so the throttle
    // must be armed before anything that can fail. If a persistent append failure
    // left it unarmed, every subsequent tool call would retry filesystem work
    // forever. Losing up to an hour of breadcrumbs on a machine that is already
    // refusing writes is the cheaper failure.
    withNode9Dir();
    fs.mkdirSync(hookDebug()); // a directory → appendFileSync throws EISDIR
    runCheck({ NODE9_NO_AUTO_DAEMON: '1' });
    expect(fs.existsSync(stamp())).toBe(true);
  });

  it('records the breadcrumb on a FRESH machine, where ~/.node9 does not exist yet', () => {
    // Regression guard (C2). The autostart block runs BEFORE the writes that
    // happen to create ~/.node9, so without an explicit mkdir the append throws
    // ENOENT into a best-effort `catch {}` and the very first breadcrumb — on the
    // machine most likely to have a broken daemon — vanishes silently. A silent
    // diagnostic is the exact failure this whole feature exists to eliminate.
    expect(fs.existsSync(path.join(home, '.node9'))).toBe(false);
    runCheck({ NODE9_NO_AUTO_DAEMON: '1' });
    expect(breadcrumbs()[0]).toMatch(/daemon-autostart-skip: NODE9_NO_AUTO_DAEMON/);
  });
});
