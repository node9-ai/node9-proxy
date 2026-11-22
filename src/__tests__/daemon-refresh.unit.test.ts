/**
 * Unit tests for the pure halves of "a hook on a newer build refreshes an
 * older daemon": the stale decision, the attempt spacing and its stamp, the
 * restart plan, and the reader that says whether the login service starts
 * this install. The subprocess behaviour is in
 * daemon-refresh.integration.test.ts.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parseBuildId } from '../daemon/build-id';
import { isUnverifiedHolder } from '../daemon/daemon-key';
import {
  REFRESH_BACKOFF_MAX_MS,
  REFRESH_STAMP,
  armRefreshStamp,
  clearRefreshStamp,
  deferRefresh,
  isDaemonStale,
  noteRefreshFailure,
  readPidBuild,
  readRefreshStamp,
  refreshDelayMs,
  refreshDue,
} from '../daemon/refresh-stamp';
import { describeRefresh, refreshPlan } from '../daemon/refresh';
import {
  launchdPlist,
  restartDaemonService,
  serviceUnitNamesBinary,
  systemdUnit,
} from '../daemon/service';
import { refreshStaleDaemon } from '../cli/daemon-starter';

const MINE = { version: '2.67.0', mtimeMs: 5000 };

describe('isDaemonStale', () => {
  const HERE = '/opt/node9/dist/cli.js';
  const ELSEWHERE = '/home/u/checkout/dist/cli.js';
  const here = () => HERE;

  it.each([
    // An older VERSION is replaced whichever install the daemon runs from:
    // today's daemons write no entry at all.
    ['an older version, same install', '2.66.3+9000', HERE, true],
    ['an older version, another install', '2.66.3+9000', ELSEWHERE, true],
    ['an older version, no entry in the pid file', '2.66.3+9000', null, true],
    // The same version and an older file is a rebuild: only of this install.
    ['the same version, older file, same install', '2.67.0+4999', HERE, true],
    ['the same version, older file, another install', '2.67.0+4999', ELSEWHERE, false],
    ['the same version, older file, no entry', '2.67.0+4999', null, false],
    ['the same build', '2.67.0+5000', HERE, false],
    ['the same version, newer file', '2.67.0+5001', HERE, false],
    ['a newer version', '2.68.0+1', HERE, false],
    ['no build in the pid file', null, HERE, false],
    ['a build that does not parse', 'banana', HERE, false],
  ])('%s -> %s', (_name, buildId, entry, stale) => {
    expect(isDaemonStale({ buildId, entry }, MINE, here)).toBe(stale);
  });

  it('a rebuild is not stale when this process has no launcher of its own', () => {
    expect(isDaemonStale({ buildId: '2.67.0+4999', entry: HERE }, MINE, () => null)).toBe(false);
  });

  it('asks for the own launcher only to judge a same-version rebuild', () => {
    let asked = 0;
    const counting = () => {
      asked++;
      return HERE;
    };
    isDaemonStale({ buildId: '2.66.3+9000', entry: null }, MINE, counting);
    isDaemonStale({ buildId: '2.67.0+5000', entry: HERE }, MINE, counting);
    isDaemonStale({ buildId: null, entry: HERE }, MINE, counting);
    expect(asked).toBe(0);
    isDaemonStale({ buildId: '2.67.0+4999', entry: HERE }, MINE, counting);
    expect(asked).toBe(1);
  });
});

describe('refreshDelayMs / refreshDue', () => {
  it('spaces attempts 1 min, 10 min, 1 h, then a day', () => {
    expect([0, 1, 2, 3, 4, 9].map(refreshDelayMs)).toEqual([
      0,
      60_000,
      600_000,
      3_600_000,
      REFRESH_BACKOFF_MAX_MS,
      REFRESH_BACKOFF_MAX_MS,
    ]);
  });

  it('is due with no stamp, and for a stamp of another build', () => {
    expect(refreshDue(null, 'a+1', 1000)).toBe(true);
    expect(refreshDue({ build: 'b+1', attempts: 9, at: 1000 }, 'a+1', 1000)).toBe(true);
  });

  it('waits out the delay of the attempt count', () => {
    const stamp = { build: 'a+1', attempts: 2, at: 1_000_000 };
    expect(refreshDue(stamp, 'a+1', 1_000_000 + 599_999)).toBe(false);
    expect(refreshDue(stamp, 'a+1', 1_000_000 + 600_000)).toBe(true);
  });

  it('a stamp dated in the future does not block for longer than its delay', () => {
    const stamp = { build: 'a+1', attempts: 1, at: 10_000_000 };
    expect(refreshDue(stamp, 'a+1', 10_000_000 - 30_000)).toBe(false);
    expect(refreshDue(stamp, 'a+1', 10_000_000 - 60_000)).toBe(true);
  });
});

describe('the refresh stamp on disk', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-refresh-stamp-'));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('counts attempts per installed build and starts again for a new build', () => {
    armRefreshStamp('a+1', 100, home); // creates ~/.node9 too
    armRefreshStamp('a+1', 200, home);
    expect(readRefreshStamp(home)).toEqual({ build: 'a+1', attempts: 2, at: 200 });
    armRefreshStamp('b+1', 300, home);
    expect(readRefreshStamp(home)).toEqual({ build: 'b+1', attempts: 1, at: 300 });
  });

  it('a failure keeps the count and the time, and records the reason', () => {
    armRefreshStamp('a+1', 100, home);
    armRefreshStamp('a+1', 200, home);
    noteRefreshFailure('a+1', 'the holder refused', 999, home);
    expect(readRefreshStamp(home)).toEqual({
      build: 'a+1',
      attempts: 2,
      at: 200,
      reason: 'the holder refused',
    });
    // The reason stays while the next attempt is under way.
    armRefreshStamp('a+1', 300, home);
    expect(readRefreshStamp(home)?.reason).toBe('the holder refused');
  });

  it('a deferral gives the attempt back but never drops below one', () => {
    armRefreshStamp('a+1', 100, home);
    deferRefresh('a+1', 150, home);
    expect(readRefreshStamp(home)).toEqual({ build: 'a+1', attempts: 1, at: 150 });
    armRefreshStamp('a+1', 200, home);
    armRefreshStamp('a+1', 300, home);
    deferRefresh('a+1', 350, home);
    expect(readRefreshStamp(home)).toEqual({ build: 'a+1', attempts: 2, at: 350 });
  });

  it('reads a damaged or foreign stamp as no stamp', () => {
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    for (const text of ['', '{', '[]', '{"build":1,"attempts":1,"at":1}', '{"build":"a+1"}']) {
      fs.writeFileSync(REFRESH_STAMP(home), text);
      expect(readRefreshStamp(home), text).toBeNull();
    }
    clearRefreshStamp(home);
    clearRefreshStamp(home); // absent: no throw
    expect(fs.existsSync(REFRESH_STAMP(home))).toBe(false);
  });

  it('arming throws when the stamp cannot be written, so nothing is spawned', () => {
    // ~/.node9 is a FILE: the stamp cannot be created under it.
    fs.writeFileSync(path.join(home, '.node9'), '');
    expect(() => armRefreshStamp('a+1', 100, home)).toThrow();
  });

  it('readPidBuild reads what the daemon wrote about itself, or nothing', () => {
    const nothing = { buildId: null, entry: null };
    expect(readPidBuild(home)).toEqual(nothing);
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    const pid = path.join(home, '.node9', 'daemon.pid');
    fs.writeFileSync(
      pid,
      JSON.stringify({ pid: 1, port: 7391, buildId: '2.66.3+12', entry: '/opt/n9/dist/cli.js' })
    );
    expect(readPidBuild(home)).toEqual({ buildId: '2.66.3+12', entry: '/opt/n9/dist/cli.js' });
    // A daemon from before the entry field.
    fs.writeFileSync(pid, JSON.stringify({ pid: 1, port: 7391, buildId: '2.66.3+12' }));
    expect(readPidBuild(home)).toEqual({ buildId: '2.66.3+12', entry: null });
    fs.writeFileSync(pid, JSON.stringify({ pid: 1, port: 7391, buildId: 7, entry: 7 }));
    expect(readPidBuild(home)).toEqual(nothing);
    fs.writeFileSync(pid, 'not json');
    expect(readPidBuild(home)).toEqual(nothing);
  });
});

describe('refreshPlan', () => {
  it.each([
    ['linux', true, true, 'service'],
    ['linux', true, false, 'spawn'],
    ['linux', false, true, 'spawn'],
    ['linux', false, false, 'spawn'],
    ['darwin', true, true, 'service'],
    // launchd restarts its own job every 10 s against a daemon it did not start.
    ['darwin', true, false, 'leave'],
    ['darwin', false, true, 'spawn'],
    ['darwin', false, false, 'spawn'],
    // The Windows startup entry cannot be restarted through a service manager.
    ['win32', true, true, 'spawn'],
    ['freebsd', true, true, 'spawn'],
  ] as const)('%s enabled=%s unit-names-this-install=%s -> %s', (platform, on, names, plan) => {
    expect(refreshPlan({ platform, serviceEnabled: on, unitNamesThisInstall: names })).toBe(plan);
  });
});

describe('serviceUnitNamesBinary', () => {
  let dir: string;
  let files: { systemd: string; launchd: string };
  const BIN = '/home/u/.nvm/versions/node/v25.9.0/lib/node_modules/node9-ai/dist/cli.js';
  const OTHER = '/home/u/.nvm/versions/node/v18.19.1/lib/node_modules/node9-ai/dist/cli.js';
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-refresh-unit-'));
    files = { systemd: path.join(dir, 'unit.service'), launchd: path.join(dir, 'unit.plist') };
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  // The units are written by the real writers, so the reader cannot drift
  // from them.
  it('linux: true for the unit of this install, false for another install', () => {
    fs.writeFileSync(files.systemd, systemdUnit(BIN));
    expect(serviceUnitNamesBinary(BIN, 'linux', files)).toBe(true);
    expect(serviceUnitNamesBinary(OTHER, 'linux', files)).toBe(false);
    // A path that only starts the same is another file.
    expect(serviceUnitNamesBinary(BIN.replace(/\.js$/, ''), 'linux', files)).toBe(false);
  });

  it('darwin: true for the plist of this install, also with characters XML escapes', () => {
    const odd = '/Users/a&b/lib/node_modules/node9-ai/dist/cli.js';
    fs.writeFileSync(files.launchd, launchdPlist(odd));
    expect(serviceUnitNamesBinary(odd, 'darwin', files)).toBe(true);
    expect(serviceUnitNamesBinary(OTHER, 'darwin', files)).toBe(false);
  });

  it('false with no unit, and on a platform with no service manager restart', () => {
    expect(serviceUnitNamesBinary(BIN, 'linux', files)).toBe(false);
    expect(serviceUnitNamesBinary(BIN, 'darwin', files)).toBe(false);
    fs.writeFileSync(files.systemd, systemdUnit(BIN));
    expect(serviceUnitNamesBinary(BIN, 'win32', files)).toBe(false);
  });
});

// Moved out of server.ts so the refresh helper applies the same rule as a
// starting daemon; the table pins the rule as it was.
describe('isUnverifiedHolder', () => {
  const mine = { version: '2.67.0', mtimeMs: 5000 };
  const build = (s: string) => parseBuildId(s);
  it.each([
    ['no key of our own: nothing can be checked', false, true, 'absent', '2.67.0+5000', false],
    ['nothing answered', true, false, 'absent', null, false],
    ['a valid proof', true, true, 'valid', '2.67.0+5000', false],
    ['an invalid proof', true, true, 'invalid', '2.0.0+1', true],
    ['no proof from an older build (before the key)', true, true, 'absent', '2.66.3+1', false],
    ['no proof from this build', true, true, 'absent', '2.67.0+5000', true],
    ['no proof from a newer build', true, true, 'absent', '2.68.0+1', true],
    ['no proof and no build', true, true, 'absent', null, true],
  ] as const)('%s', (_name, hasKey, answered, proof, holderBuild, unverified) => {
    expect(
      isUnverifiedHolder(hasKey, { answered, proof }, holderBuild ? build(holderBuild) : null, mine)
    ).toBe(unverified);
  });
});

describe("refreshStaleDaemon outside node9's own launcher", () => {
  // This file runs under vitest: argv[1] is the test runner, not dist/cli.js.
  // A test that imports `check` must never start a helper, and must not leave
  // a stamp or a log line in ~/.node9 either.
  let home: string;
  let realHome: string | undefined;
  let realProfile: string | undefined;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-refresh-hook-'));
    fs.mkdirSync(path.join(home, '.node9'));
    fs.writeFileSync(
      path.join(home, '.node9', 'daemon.pid'),
      JSON.stringify({ pid: process.pid, port: 7391, buildId: '0.0.1+1' })
    );
    realHome = process.env.HOME;
    realProfile = process.env.USERPROFILE;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
  });
  afterEach(() => {
    if (realHome === undefined) delete process.env.HOME;
    else process.env.HOME = realHome;
    if (realProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = realProfile;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it.each([null, 'autoStartDaemon=false'])('skipReason %s: writes nothing', (skipReason) => {
    expect(os.homedir()).toBe(home);
    refreshStaleDaemon(skipReason);
    expect(fs.readdirSync(path.join(home, '.node9'))).toEqual(['daemon.pid']);
  });
});

describe('restartDaemonService', () => {
  it('does nothing and reports false when the caller knows the service is not enabled', () => {
    expect(restartDaemonService(false)).toBe(false);
  });
});

describe('describeRefresh', () => {
  it('names versions when they differ and full builds when they do not', () => {
    expect(
      describeRefresh({ outcome: 'refreshed', from: '2.66.3+1', to: '2.67.0+2', via: 'spawn' }).text
    ).toBe('Daemon refreshed: 2.66.3 -> 2.67.0');
    expect(
      describeRefresh({ outcome: 'refreshed', from: '2.67.0+1', to: '2.67.0+2', via: 'service' })
        .text
    ).toBe('Daemon refreshed: 2.67.0+1 -> 2.67.0+2 (restarted by the background service)');
  });

  it('only a failure is not ok', () => {
    expect(describeRefresh({ outcome: 'failed', reason: 'x' }).ok).toBe(false);
    for (const r of [
      { outcome: 'not-running' },
      { outcome: 'unknown-build' },
      { outcome: 'current', running: '2.67.0+1' },
      { outcome: 'busy' },
      { outcome: 'deferred', openCards: 2 },
    ] as const) {
      expect(describeRefresh(r).ok).toBe(true);
    }
  });
});
