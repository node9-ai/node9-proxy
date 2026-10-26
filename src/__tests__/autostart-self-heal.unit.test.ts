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

import { restartDaemonService, scheduleAutostartSelfHeal } from '../daemon/service';

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
});
