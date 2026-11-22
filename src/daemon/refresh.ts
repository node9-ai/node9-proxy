// src/daemon/refresh.ts
// `node9 daemon refresh`: replace a running daemon of an OLDER build with this
// install's build, and do nothing otherwise. The hook starts it detached when
// the pid file names an older build (cli/daemon-starter.ts refreshStaleDaemon);
// a person can run it too. Design: docs/roadmap/active/daemon-stale-refresh-design.md.
//
// It never posts /shutdown and never signals a pid. A takeover stays in one
// place (decideAgainstHolder in server.ts, run by the daemon it starts), and
// the only signal is the service manager's to its own unit.
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { DAEMON_HOST, DAEMON_PORT } from '../auth/daemon';
import { CURRENT_BUILD, buildIdString, compareBuild, parseBuildId } from './build-id';
import { isUnverifiedHolder, loadDaemonKey, probePortHolder } from './daemon-key';
import { clearRefreshStamp, deferRefresh, noteRefreshFailure } from './refresh-stamp';
import {
  isDaemonServiceEnabled,
  resolveNode9Binary,
  restartDaemonService,
  serviceUnitNamesBinary,
} from './service';
import { DAEMON_STARTUP_LOG, openStartupLogFd, recordStartupState } from './startup-log';

/** How the daemon is replaced.
 *  service: the login service restarts its own unit (the new daemon is the one
 *           systemd / launchd supervises).
 *  spawn:   a plain new daemon, which takes the port over through /shutdown.
 *  leave:   nothing safe to do. */
export type RefreshPlan = 'service' | 'spawn' | 'leave';

/**
 * Pure. An enabled service whose unit starts THIS install restarts through
 * the service manager. When the unit starts another install (a global node9
 * under another Node after an nvm switch) a service restart would bring the
 * same old code back: on Linux a plain daemon takes over instead (the unit
 * goes inactive until the next login). On macOS the plist has KeepAlive, so
 * launchd would start its own job every 10 s against a daemon it did not
 * start: there the daemon is left alone and the user is told.
 */
export function refreshPlan(opts: {
  platform: NodeJS.Platform;
  serviceEnabled: boolean;
  unitNamesThisInstall: boolean;
}): RefreshPlan {
  if (opts.platform !== 'linux' && opts.platform !== 'darwin') return 'spawn';
  if (!opts.serviceEnabled) return 'spawn';
  if (opts.unitNamesThisInstall) return 'service';
  return opts.platform === 'darwin' ? 'leave' : 'spawn';
}

export type RefreshResult =
  | { outcome: 'not-running' }
  | { outcome: 'unknown-build' }
  | { outcome: 'current'; running: string }
  | { outcome: 'busy' }
  | { outcome: 'deferred'; openCards: number }
  | { outcome: 'refreshed'; from: string; to: string; via: 'service' | 'spawn' }
  | { outcome: 'failed'; reason: string };

/** How long the new daemon has to answer with this build: a takeover waits up
 *  to 2 s for the old process to free the port before it binds. */
const VERIFY_MS = 10_000;

/** One line in daemon-startup.log, the file `doctor` points at. Never throws. */
function logRefresh(text: string): void {
  try {
    const file = DAEMON_STARTUP_LOG();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, `[${new Date().toISOString()}] [refresh] ${text}\n`, 'utf-8');
  } catch {
    /* the log is best effort */
  }
}

/** Start a plain daemon of this build, detached. It finds the port held and
 *  decides against the holder itself. False when no process was started. */
function spawnDaemon(autoStarted: boolean): boolean {
  const script = process.argv[1];
  if (typeof script !== 'string' || !path.isAbsolute(script)) return false;
  const fd = openStartupLogFd();
  try {
    recordStartupState('starting');
    const env = { ...process.env };
    // The new daemon keeps how the old one was started (it decides whether an
    // idle exit removes the pid file).
    if (autoStarted) env.NODE9_AUTO_STARTED = '1';
    else delete env.NODE9_AUTO_STARTED;
    const child = spawn(process.execPath, [script, 'daemon'], {
      detached: true,
      stdio: ['ignore', 'ignore', fd ?? 'ignore'],
      env,
      // HOME, never the directory this helper was started in: that is the
      // project of whichever tool call found the daemon stale, and a daemon
      // reads `node9.config.json` from its own working directory.
      cwd: os.homedir(),
    });
    // An 'error' event with no listener is an uncaught exception.
    child.on('error', (err: Error) => recordStartupState('failed', 'spawn-failed', err.message));
    child.unref();
    return child.pid !== undefined;
  } catch (err) {
    recordStartupState('failed', 'spawn-failed', err instanceof Error ? err.message : String(err));
    return false;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        /* non-fatal */
      }
    }
  }
}

/** Longer than one helper can run (probe, service restart, two verify
 *  windows): a lock older than this was left by a helper that was killed. */
const LOCK_STALE_MS = 90_000;

/**
 * One helper at a time per HOME. Parallel tool calls can each find the stamp
 * unarmed and each start a helper; two helpers would each start a daemon, and
 * two daemons racing for the port of a holder that is leaving can end with
 * the winner adopted as an orphan (a pid file with no token). Returns the
 * release function, or null when another helper holds the lock.
 */
function takeRefreshLock(home: string): (() => void) | null {
  const dir = path.join(home, '.node9');
  const file = path.join(dir, '.daemon-refresh.lock');
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(file, String(process.pid), { flag: 'wx' });
      return () => {
        try {
          fs.unlinkSync(file);
        } catch {
          /* already gone */
        }
      };
    } catch {
      try {
        if (Math.abs(Date.now() - fs.statSync(file).mtimeMs) < LOCK_STALE_MS) return null;
        fs.unlinkSync(file); // a killed helper's leftover: take it over
      } catch {
        return null; // cannot be created or judged: do not run unlocked
      }
    }
  }
  return null;
}

export async function runDaemonRefresh(): Promise<RefreshResult> {
  const release = takeRefreshLock(os.homedir());
  if (!release) return { outcome: 'busy' };
  try {
    return await refreshUnderLock();
  } finally {
    release();
  }
}

async function refreshUnderLock(): Promise<RefreshResult> {
  const home = os.homedir();
  const mine = buildIdString(CURRENT_BUILD);
  const key = loadDaemonKey(home, { create: false });

  const fail = (reason: string): RefreshResult => {
    noteRefreshFailure(mine, reason, Date.now(), home);
    logRefresh(`not done: ${reason}`);
    return { outcome: 'failed', reason };
  };

  const holder = await probePortHolder(key, DAEMON_HOST, DAEMON_PORT);
  // Nothing answers: a daemon that is down is the auto-start's job.
  if (!holder.answered) return { outcome: 'not-running' };
  const holderBuild = parseBuildId(holder.buildId);
  if (isUnverifiedHolder(key !== null, holder, holderBuild, CURRENT_BUILD)) {
    return fail(
      `the process on :${DAEMON_PORT} could not prove it is this user's node9 daemon; it was left running`
    );
  }
  if (!holderBuild || holder.buildId === null) return { outcome: 'unknown-build' };
  if (compareBuild(CURRENT_BUILD, holderBuild) <= 0) {
    // Someone else already refreshed it (another helper, a manual restart).
    // The stamp is left as it is: when the pid file keeps naming an older
    // build than the process on the port, the hook keeps seeing a stale
    // daemon, and a cleared stamp would start this helper on every tool call.
    return { outcome: 'current', running: holder.buildId };
  }
  const from = holder.buildId;

  // A person is looking at an approval card: replacing the daemon would drop
  // it and fail that tool call. Daemons before `openCards` do not say.
  if (holder.openCards !== null && holder.openCards > 0) {
    deferRefresh(mine, Date.now(), home);
    logRefresh(`put off: ${holder.openCards} approval card(s) open on ${from}`);
    return { outcome: 'deferred', openCards: holder.openCards };
  }

  // Never through a real service manager under test: HOME is a temp dir there,
  // but systemctl and launchctl answer for the real user.
  const useService = process.env.NODE9_TESTING !== '1';
  const binary = resolveNode9Binary();
  const unitNamesThisInstall = useService && binary !== null && serviceUnitNamesBinary(binary);
  // `systemctl is-enabled` blocks for up to 3 s: asked once, and not at all
  // where the answer cannot change the plan (Linux with a unit of another
  // install, Windows).
  const serviceEnabled =
    useService &&
    (process.platform === 'darwin' || (process.platform === 'linux' && unitNamesThisInstall)) &&
    isDaemonServiceEnabled();
  const plan = refreshPlan({ platform: process.platform, serviceEnabled, unitNamesThisInstall });
  if (plan === 'leave') {
    return fail(
      'the login service starts another node9 install, so it cannot bring up this build; run: node9 daemon install'
    );
  }
  const autoStarted = holder.autoStarted !== false;
  let via: 'service' | 'spawn' = 'spawn';
  if (plan === 'service') {
    if (restartDaemonService(serviceEnabled)) via = 'service';
    else if (process.platform === 'darwin') {
      // No plain daemon next to a launchd job that restarts itself.
      return fail('launchctl could not restart the login service; run: node9 daemon restart');
    }
  }
  if (via === 'spawn' && !spawnDaemon(autoStarted)) {
    return fail('could not start a new daemon process; run: node9 daemon restart');
  }

  /** The build now on the port, once it is this one or newer; else whether
   *  anything answered at the end of the window. */
  const verify = async (): Promise<{ build: string | null; answered: boolean }> => {
    const deadline = Date.now() + VERIFY_MS;
    let answered = false;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 250));
      const now = await probePortHolder(key, DAEMON_HOST, DAEMON_PORT, 500);
      const nowBuild = parseBuildId(now.buildId);
      answered = now.answered;
      if (
        now.answered &&
        now.buildId !== null &&
        nowBuild !== null &&
        compareBuild(nowBuild, CURRENT_BUILD) >= 0 &&
        !isUnverifiedHolder(key !== null, now, nowBuild, CURRENT_BUILD)
      ) {
        return { build: now.buildId, answered };
      }
    }
    return { build: null, answered };
  };

  let seen = await verify();
  if (seen.build === null && via === 'service' && !seen.answered && process.platform === 'linux') {
    // systemctl reported success, stopped its daemon and brought nothing up
    // (an ExecStart whose Node moved). `node9 daemon restart` starts one
    // directly in this case, and so does this: never leave no daemon behind.
    logRefresh('the login service brought no daemon up; starting one directly');
    if (spawnDaemon(autoStarted)) {
      via = 'spawn';
      seen = await verify();
    }
  }
  if (seen.build !== null) {
    clearRefreshStamp(home);
    logRefresh(`ok ${from} -> ${seen.build} (${via})`);
    return { outcome: 'refreshed', from, to: seen.build, via };
  }
  return fail(
    via === 'service'
      ? `the login service restarted, but the daemon on :${DAEMON_PORT} is not build ${mine}; run: node9 daemon restart`
      : `a new daemon was started, but the daemon on :${DAEMON_PORT} is still ${from}; run: node9 daemon restart`
  );
}

/** `2.66.3 -> 2.67.0`, or the full build ids for two builds of one version. */
function versions(from: string, to: string): string {
  const a = parseBuildId(from)?.version ?? from;
  const b = parseBuildId(to)?.version ?? to;
  return a === b ? `${from} -> ${to}` : `${a} -> ${b}`;
}

/** What `node9 daemon refresh` prints, and whether it is a failure. */
export function describeRefresh(r: RefreshResult): { ok: boolean; text: string } {
  switch (r.outcome) {
    case 'not-running':
      return {
        ok: true,
        text: 'Daemon is not running, nothing to refresh. Start it with: node9 daemon --background',
      };
    case 'unknown-build':
      return {
        ok: true,
        text: 'The running daemon does not report its build. Restart it with: node9 daemon restart',
      };
    case 'current':
      return { ok: true, text: `Daemon is up to date (build ${r.running})` };
    case 'busy':
      return { ok: true, text: 'Another daemon refresh is in progress; nothing was done' };
    case 'deferred':
      return {
        ok: true,
        text: `${r.openCards} approval card(s) are waiting for a decision, so the daemon was not restarted. Decide them and run this again, or restart now with: node9 daemon restart`,
      };
    case 'refreshed':
      return {
        ok: true,
        text: `Daemon refreshed: ${versions(r.from, r.to)}${r.via === 'service' ? ' (restarted by the background service)' : ''}`,
      };
    case 'failed':
      return { ok: false, text: `Daemon not refreshed: ${r.reason}` };
  }
}
