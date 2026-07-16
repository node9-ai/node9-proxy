/**
 * A4c: logDaemonStartup writes a structured, greppable line to
 * ~/.node9/daemon-startup.log and never throws. Real fs against a temp HOME.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { logDaemonStartup, DAEMON_STARTUP_LOG, openStartupLogFd } from '../daemon/startup-log';

let tmp: string;
let homeSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-startuplog-'));
  homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmp);
});
afterEach(() => {
  homeSpy.mockRestore();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('logDaemonStartup', () => {
  it('appends a structured line, creating .node9 if absent', () => {
    logDaemonStartup('port-in-use', 'another daemon owns :7391');
    const contents = fs.readFileSync(DAEMON_STARTUP_LOG(), 'utf-8');
    expect(contents).toMatch(/daemon-startup:port-in-use another daemon owns :7391/);
    expect(contents).toMatch(/^\[\d{4}-\d\d-\d\dT/); // ISO timestamp prefix
  });

  it('appends (does not overwrite) across calls', () => {
    logDaemonStartup('startup-throw', 'ERR_REQUIRE_ESM');
    logDaemonStartup('bind-failed', 'EACCES');
    const lines = fs.readFileSync(DAEMON_STARTUP_LOG(), 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(/startup-throw/);
    expect(lines[1]).toMatch(/bind-failed/);
  });

  it('openStartupLogFd creates .node9, returns a usable fd, and caps a large file', () => {
    // fresh machine: .node9 absent — must be created, fd returned + writable.
    const fd = openStartupLogFd();
    expect(typeof fd).toBe('number');
    fs.writeSync(fd!, 'child stderr line\n');
    fs.closeSync(fd!);
    expect(fs.readFileSync(DAEMON_STARTUP_LOG(), 'utf-8')).toMatch(/child stderr line/);

    // Grow it past the cap (256KB) → next open truncates so a crash loop can't
    // grow it without bound.
    fs.writeFileSync(DAEMON_STARTUP_LOG(), 'x'.repeat(300 * 1024));
    const fd2 = openStartupLogFd();
    fs.closeSync(fd2!);
    expect(fs.statSync(DAEMON_STARTUP_LOG()).size).toBe(0);
  });

  it('never throws when the log path is unwritable', () => {
    // Make the target a DIRECTORY so appendFileSync fails (EISDIR) — keeps HOME
    // valid (mocking homedir to an unwritable path breaks vitest's own internals).
    fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
    fs.mkdirSync(DAEMON_STARTUP_LOG());
    expect(() => logDaemonStartup('startup-throw')).not.toThrow();
  });
});
