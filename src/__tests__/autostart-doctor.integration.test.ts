/**
 * A2 + B1 integration: `node9 doctor` must surface the two states behind the
 * 6-day silent policy-staleness incident —
 *   A2: autostart INSTALLED but DISABLED (a unit file on disk that never runs), and
 *   B1: WHY the daemon is down, from daemon-startup.log.
 *
 * Integration, not unit (CLAUDE.md): doctor is a subprocess whose output and exit
 * code are the contract, and both probes resolve paths through HOME.
 *
 * Faking systemd: a stub `systemctl` earlier on PATH. The runner's real systemd is
 * never touched — `is-enabled` on CI would be nondeterministic, and enabling or
 * disabling a real unit from a test is not acceptable. This works because the two
 * probes are independent: isDaemonServiceInstalled() is fs.existsSync(unit file)
 * (service.ts:190), while isDaemonServiceEnabled() shells out to systemctl.
 *
 * Requires `npm run build`.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
// Linux only, not merely "not Windows": the fixtures below fake systemd
// specifically (a stub `systemctl` plus a unit file under ~/.config/systemd/user).
// On darwin the probes go to launchd instead, so the stub is never consulted and
// these assertions could not hold.
const itUnix = it.skipIf(process.platform !== 'linux');
// B1's cause line has nothing to do with systemd — it only needs the daemon-down
// branch and a seeded log — so it runs anywhere but Windows.
const itPosix = it.skipIf(process.platform === 'win32');

let home: string;
let stubBin: string;

beforeAll(() => {
  expect(fs.existsSync(CLI), `${CLI} missing — run npm run build`).toBe(true);
});

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-doctor-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  stubBin = path.join(home, 'bin');
  fs.mkdirSync(stubBin, { recursive: true });
  // Stub by default so NO test consults the developer's real systemd. Tests that
  // care about autostart state re-stub explicitly; the rest simply must not vary
  // by machine.
  stubSystemctlDisabled();
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

/** Report the unit as DISABLED without going near the real systemd. */
function stubSystemctlDisabled() {
  const p = path.join(stubBin, 'systemctl');
  fs.writeFileSync(
    p,
    '#!/bin/bash\nif [ "$2" = "is-enabled" ]; then echo disabled; exit 1; fi\nexit 1\n',
    'utf-8'
  );
  fs.chmodSync(p, 0o755);
}

/** A unit file on disk → isDaemonServiceInstalled() reports installed. */
function installUnitFile() {
  const dir = path.join(home, '.config', 'systemd', 'user');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'node9-daemon.service'), '[Unit]\nDescription=node9\n', 'utf-8');
}

function cloudEnabled(enabled = true) {
  fs.writeFileSync(
    path.join(home, '.node9', 'credentials.json'),
    JSON.stringify({ default: { apiKey: 'fake' } }),
    'utf-8'
  );
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ settings: { approvers: { cloud: enabled } } }),
    'utf-8'
  );
}

/** Seed the machine-readable startup STATE (not the human log — nothing parses that). */
const seedStartupState = (state: object, msAgo = 60_000) =>
  fs.writeFileSync(
    path.join(home, '.node9', 'daemon-startup-state.json'),
    JSON.stringify({ at: new Date(Date.now() - msAgo).toISOString(), ...state }),
    'utf-8'
  );

function runDoctor() {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, 'doctor'], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(),
    env: {
      ...baseEnv,
      HOME: home,
      USERPROFILE: home,
      PATH: `${stubBin}${path.delimiter}${process.env.PATH}`,
      NO_COLOR: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
    },
  });
  expect(r.error).toBeUndefined();
  expect(r.status).not.toBeNull();
  return r;
}

describe('A2 — doctor surfaces autostart health', () => {
  itUnix('warns when autostart is INSTALLED but DISABLED', () => {
    cloudEnabled();
    installUnitFile();
    stubSystemctlDisabled();
    const r = runDoctor();
    expect(r.stdout).toMatch(/INSTALLED but DISABLED/);
    expect(r.stdout).toMatch(/will NOT survive a reboot/);
    // The exit-code contract: this is a LATENT risk on a machine that still
    // enforces cached policy. Flipping doctor red here would break every CI
    // health-check that greps its exit code.
    expect(r.status).toBe(0);
  });

  itUnix('warns when no autostart unit is installed at all', () => {
    cloudEnabled();
    stubSystemctlDisabled();
    const r = runDoctor();
    expect(r.stdout).toMatch(/No daemon autostart installed/);
    expect(r.status).toBe(0);
  });

  itUnix('says nothing about autostart in privacy mode (cloud disabled)', () => {
    cloudEnabled(false);
    installUnitFile();
    stubSystemctlDisabled();
    // A privacy-mode user never syncs cloud policy, so autostart health is not
    // their problem — nagging them would be a false alarm.
    expect(runDoctor().stdout).not.toMatch(/autostart/i);
  });
});

describe('B1 — doctor reports WHY the daemon is down', () => {
  itPosix('surfaces a recorded startup failure', () => {
    cloudEnabled();
    seedStartupState({ outcome: 'failed', kind: 'startup-throw', detail: 'boom' });
    const r = runDoctor();
    expect(r.stdout).toMatch(/last start attempt .+ ago: startup-throw — boom/);
    expect(r.status).toBe(0); // a detail line on an existing warning, not a failure
  });

  itPosix('says NOTHING once the daemon has started successfully since', () => {
    cloudEnabled();
    // The state is overwritten by each attempt, so a success erases the earlier
    // failure outright — no chance of blaming a crash that was fixed weeks ago.
    seedStartupState({ outcome: 'ok' });
    expect(runDoctor().stdout).not.toMatch(/last start attempt/);
  });

  itPosix('never presents a port conflict as the reason a daemon is not running', () => {
    cloudEnabled();
    // "another daemon owns the port" asserts a daemon IS up — printed beneath
    // "Daemon not running" it contradicts the very warning it explains.
    seedStartupState({ outcome: 'ok-elsewhere' });
    expect(runDoctor().stdout).not.toMatch(/last start attempt/);
  });

  itPosix('reports a spawn that never reported back (the import-time crash)', () => {
    cloudEnabled();
    seedStartupState({ outcome: 'starting' }, 10 * 60 * 1000);
    const r = runDoctor();
    // A stranded 'starting' keeps the FIRST attempt's timestamp so the grace window
    // can expire, so it must NOT be labelled as the last attempt — the age printed
    // would be off by the length of the streak.
    expect(r.stdout).toMatch(/start attempts failing since .+ ago: did-not-start/);
    expect(r.stdout).not.toMatch(/last start attempt.*did-not-start/);
    expect(r.stdout).toMatch(/daemon-startup\.log/); // points at the human artifact
  });

  itPosix('stays silent about a cause older than the recency window', () => {
    cloudEnabled();
    seedStartupState({ outcome: 'failed', kind: 'startup-throw' }, 48 * 60 * 60 * 1000);
    expect(runDoctor().stdout).not.toMatch(/last start attempt/);
  });

  itPosix('says nothing when there is no startup state at all', () => {
    cloudEnabled();
    expect(runDoctor().stdout).not.toMatch(/last start attempt/);
  });
});
