/**
 * A4a: logAutostartSkipThrottled records WHY the check hot path didn't auto-start
 * a down daemon, throttled to once/hour so it can't spam hook-debug.log on every
 * tool call. Real fs against a temp HOME.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { logAutostartSkipThrottled } from '../cli/daemon-starter';

let tmp: string;
let homeSpy: ReturnType<typeof vi.spyOn>;
const hookLog = () => path.join(tmp, '.node9', 'hook-debug.log');

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-skip-'));
  fs.mkdirSync(path.join(tmp, '.node9'), { recursive: true });
  homeSpy = vi.spyOn(os, 'homedir').mockReturnValue(tmp);
});
afterEach(() => {
  homeSpy.mockRestore();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('logAutostartSkipThrottled', () => {
  it('writes a skip line with the reason on first call', () => {
    logAutostartSkipThrottled('autoStartDaemon=false');
    expect(fs.readFileSync(hookLog(), 'utf-8')).toMatch(
      /daemon-autostart-skip: autoStartDaemon=false/
    );
  });

  it('throttles a second immediate call (no duplicate within the window)', () => {
    logAutostartSkipThrottled('NODE9_NO_AUTO_DAEMON');
    logAutostartSkipThrottled('NODE9_NO_AUTO_DAEMON');
    const lines = fs
      .readFileSync(hookLog(), 'utf-8')
      .trim()
      .split('\n')
      .filter((l) => l.includes('daemon-autostart-skip'));
    expect(lines).toHaveLength(1);
  });

  it('logs again once the throttle stamp is older than the window', () => {
    logAutostartSkipThrottled('autoStartDaemon=false');
    // Age the stamp beyond the 1h window.
    const stamp = path.join(tmp, '.node9', '.autostart-skip-stamp');
    const old = Date.now() - 2 * 60 * 60 * 1000;
    fs.utimesSync(stamp, new Date(old), new Date(old));
    logAutostartSkipThrottled('autoStartDaemon=false');
    const lines = fs
      .readFileSync(hookLog(), 'utf-8')
      .trim()
      .split('\n')
      .filter((l) => l.includes('daemon-autostart-skip'));
    expect(lines).toHaveLength(2);
  });

  it('never throws when the stamp path is unwritable', () => {
    // Make the throttle stamp a DIRECTORY so writeFileSync fails — keeps HOME valid
    // (mocking homedir to an unwritable path breaks vitest's own internals).
    fs.mkdirSync(path.join(tmp, '.node9', '.autostart-skip-stamp'));
    expect(() => logAutostartSkipThrottled('unknown')).not.toThrow();
  });
});
