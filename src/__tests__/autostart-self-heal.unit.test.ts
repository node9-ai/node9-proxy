// fw#409: the running daemon keeps its autostart unit enabled, and `daemon
// restart` goes through the service manager when a unit is enabled. Every
// systemctl / launchctl call is mocked: no test touches the real service.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const calls = vi.hoisted(() => ({ list: [] as string[][], isEnabled: 'enabled', status: 0 }));

vi.mock('child_process', async (orig) => {
  const real = await orig<typeof import('child_process')>();
  return {
    ...real,
    spawnSync: (cmd: string, args: string[]) => {
      calls.list.push([cmd, ...args]);
      if (args.includes('is-enabled'))
        return {
          status: calls.isEnabled === 'enabled' ? 0 : 1,
          stdout: calls.isEnabled + '\n',
          stderr: '',
        };
      return { status: calls.status, stdout: '', stderr: '' };
    },
  };
});

import fs from 'fs';
import {
  restartDaemonService,
  scheduleAutostartSelfHeal,
  type HealResult,
} from '../daemon/service';
import { DAEMON_STARTUP_LOG } from '../daemon/startup-log';

const origPlatform = Object.getOwnPropertyDescriptor(process, 'platform')!;
const setPlatform = (p: NodeJS.Platform) =>
  Object.defineProperty(process, 'platform', { value: p, configurable: true });

beforeEach(() => {
  calls.list = [];
  calls.isEnabled = 'enabled';
  calls.status = 0;
});
afterEach(() => {
  Object.defineProperty(process, 'platform', origPlatform);
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

describe('restartDaemonService', () => {
  it('linux, unit enabled: restarts through systemctl', () => {
    setPlatform('linux');
    expect(restartDaemonService()).toBe(true);
    expect(calls.list).toContainEqual(['systemctl', '--user', 'restart', 'node9-daemon']);
  });

  it('linux, unit disabled: does nothing, the caller spawns as before', () => {
    setPlatform('linux');
    calls.isEnabled = 'disabled';
    expect(restartDaemonService()).toBe(false);
    expect(calls.list.some((c) => c.includes('restart'))).toBe(false);
  });

  it('a failed systemctl restart falls back to the spawn', () => {
    setPlatform('linux');
    calls.status = 1;
    expect(restartDaemonService()).toBe(false);
  });
});

describe('scheduleAutostartSelfHeal', () => {
  it('never runs under test', () => {
    vi.useFakeTimers();
    vi.stubEnv('NODE9_TESTING', '1');
    scheduleAutostartSelfHeal(() => true);
    vi.advanceTimersByTime(25 * 60 * 60 * 1000);
    expect(calls.list).toEqual([]);
  });

  it('checks after a minute and then once a day', () => {
    vi.useFakeTimers();
    vi.stubEnv('NODE9_TESTING', '');
    setPlatform('linux');
    scheduleAutostartSelfHeal(() => true);
    expect(calls.list).toEqual([]);
    vi.advanceTimersByTime(61_000);
    const first = calls.list.filter((c) => c.includes('is-enabled')).length;
    expect(first).toBe(1);
    vi.advanceTimersByTime(24 * 60 * 60 * 1000);
    expect(calls.list.filter((c) => c.includes('is-enabled')).length).toBe(2);
  });

  // fw#421 item 10: one failed `enable` used to wait a day for its retry, and
  // left no trace. Now: every 10 minutes until it heals, then daily, logged.
  it('retries soon after a failed repair, then once a day after it heals', () => {
    vi.useFakeTimers();
    vi.stubEnv('NODE9_TESTING', '');
    const results: HealResult[] = ['failed', 'failed', 'repaired', 'ok', 'ok'];
    const seen: number[] = [];
    const heal = () => {
      seen.push(Date.now());
      return results.shift() ?? 'ok';
    };
    const t0 = Date.now();
    scheduleAutostartSelfHeal(() => true, heal);
    vi.advanceTimersByTime(60_000);
    expect(seen).toEqual([t0 + 60_000]);
    vi.advanceTimersByTime(10 * 60_000); // first retry
    vi.advanceTimersByTime(60 * 60_000); // second retry: repaired
    expect(seen.length).toBe(3);
    vi.advanceTimersByTime(60 * 60_000);
    expect(seen.length).toBe(3); // healthy: back to the daily check
    vi.advanceTimersByTime(24 * 60 * 60_000);
    expect(seen.length).toBe(4);
  });

  it('backs off when the repair keeps failing: 10 min, 1 h, then daily', () => {
    // Review finding 3: a unit that can never be enabled (masked, static)
    // must not cost a blocking systemctl call every 10 minutes forever.
    vi.useFakeTimers();
    vi.stubEnv('NODE9_TESTING', '');
    const seen: number[] = [];
    scheduleAutostartSelfHeal(
      () => true,
      () => {
        seen.push(Date.now());
        return 'failed';
      }
    );
    const t0 = Date.now();
    vi.advanceTimersByTime(60_000 + 10 * 60_000 + 60 * 60_000 + 24 * 60 * 60_000);
    expect(seen.map((t) => t - t0)).toEqual([
      60_000,
      60_000 + 10 * 60_000,
      60_000 + 70 * 60_000,
      60_000 + 70 * 60_000 + 24 * 60 * 60_000,
    ]);
  });

  it('writes repaired and failed outcomes to daemon-startup.log, ok writes nothing', () => {
    vi.useFakeTimers();
    vi.stubEnv('NODE9_TESTING', '');
    fs.rmSync(DAEMON_STARTUP_LOG(), { force: true }); // the case above wrote its own lines
    const results: HealResult[] = ['failed', 'repaired', 'ok'];
    scheduleAutostartSelfHeal(
      () => true,
      () => results.shift() ?? 'ok'
    );
    vi.advanceTimersByTime(60_000 + 10 * 60_000 + 24 * 60 * 60_000);
    const log = fs.readFileSync(DAEMON_STARTUP_LOG(), 'utf8');
    const lines = log.split('\n').filter((l) => l.includes('[autostart-heal]'));
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('failed');
    expect(lines[1]).toContain('repaired');
  });
});
