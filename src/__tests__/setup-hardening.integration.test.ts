import { afterEach, describe, expect, it } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';

// Review round for the first-run wizard: automation must never get a login
// service, and every problem a user can fix is one line, never a stack trace.
const cli = path.resolve(__dirname, '../../dist/cli.js');
const homes: string[] = [];
function fixture(files: Record<string, string> = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-setup-hardening-'));
  homes.push(home);
  for (const [name, body] of Object.entries(files)) {
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(path.join(home, '.node9', name), body);
  }
  return home;
}
function run(home: string, args: string[]) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: home,
    env: {
      PATH: path.join(home, 'empty-bin'),
      HOME: home,
      USERPROFILE: home,
      CI: 'true',
      // Testing mode turns a service install into a reported no-op, so a
      // planned service change is visible in the output without touching
      // the host's systemd, launchd or startup folder.
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
    },
    encoding: 'utf8',
    timeout: 15000,
  });
}
function expectOneLineError(r: ReturnType<typeof run>, message: string) {
  expect(r.error).toBeUndefined();
  expect(r.status).toBe(1);
  expect(r.stderr).toContain(message);
  expect(r.stderr).not.toContain('Unhandled error');
  expect(r.stderr).not.toMatch(/^\s+at /m);
}
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});

describe('automation never gets a login service', () => {
  it('a fresh init in CI plans no service change and says how to add one', () => {
    const home = fixture();
    const r = run(home, ['init']);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).not.toContain('Service operation skipped (testing mode)');
    expect(r.stdout).toContain('node9 daemon install');
  });
  it('--recommended in CI plans no service change either', () => {
    const home = fixture();
    const r = run(home, ['init', '--recommended']);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).not.toContain('Service operation skipped (testing mode)');
  });
});

describe('problems the user can fix are one line', () => {
  it('a malformed config.json names the fix and is left untouched', () => {
    const home = fixture({ 'config.json': '{broken' });
    const r = run(home, ['init', '--skip-setup']);
    expectOneLineError(r, 'node9 init --force');
    expect(fs.readFileSync(path.join(home, '.node9/config.json'), 'utf8')).toBe('{broken');
  });
  it('an unknown --mode lists the valid modes', () => {
    const r = run(fixture(), ['init', '--skip-setup', '--mode', 'foo']);
    expectOneLineError(r, 'Mode must be standard, strict, audit, or observe.');
  });
});

describe('logout with an unreadable credentials file', () => {
  it('moves the file aside, disconnects locally and points at the dashboard', () => {
    const home = fixture({ 'credentials.json': 'not json' });
    const r = run(home, ['logout']);
    expect(r.error).toBeUndefined();
    expect(r.status, r.stderr).toBe(0);
    const dir = fs.readdirSync(path.join(home, '.node9'));
    expect(dir).not.toContain('credentials.json');
    const moved = dir.filter((f) => f.startsWith('credentials.json.corrupt-'));
    expect(moved).toHaveLength(1);
    expect(fs.readFileSync(path.join(home, '.node9', moved[0]), 'utf8')).toBe('not json');
    const out = r.stdout + r.stderr;
    expect(out).toContain('could not be read');
    expect(out).toContain('Enforcement › Devices › Disconnect');
    expect(out).not.toContain('Unhandled error');
  });
  it('a missing credentials file is still "not logged in"', () => {
    const r = run(fixture(), ['logout']);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain('Not logged in');
  });
});
