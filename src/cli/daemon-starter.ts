// src/cli/daemon-starter.ts
// Shared helpers for auto-starting the approval daemon from CLI commands.
//
// Note: as of the v3 browser-removal sprint this module no longer
// opens a browser. The local browser dashboard is being retired in
// favour of terminal (`node9 tail`) + native popup + SaaS approval
// channels. The daemon still spawns headlessly so `node9 tail` and
// the MCP gateway can subscribe to its SSE stream.
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { isDaemonRunning, isDaemonReachable } from '../auth/daemon';
import { openStartupLogFd, recordStartupState, readStartupState } from '../daemon/startup-log';

export function isTestingMode(): boolean {
  return /^(1|true|yes)$/i.test(process.env.NODE9_TESTING ?? '');
}

const SKIP_STAMP = () => path.join(os.homedir(), '.node9', '.autostart-skip-stamp');
const SKIP_THROTTLE_MS = 60 * 60 * 1000; // once per hour — this is the enforcement hot path

/**
 * A4a: record WHY the check hot path did not auto-start a down daemon
 * (`autoStartDaemon=false` / `NODE9_NO_AUTO_DAEMON`), throttled to once/hour so it
 * never spams hook-debug.log on every tool call. Answers the "why didn't the daemon
 * come up?" question that was previously unknowable. Best-effort, never throws.
 */
export function logAutostartSkipThrottled(reason: string): void {
  try {
    const stamp = SKIP_STAMP();
    try {
      if (Date.now() - fs.statSync(stamp).mtimeMs < SKIP_THROTTLE_MS) return; // throttled
    } catch {
      /* no stamp yet → not throttled */
    }
    // On a fresh machine ~/.node9 may not exist yet: this runs BEFORE the writes
    // that would otherwise create it, so without this the stamp write throws
    // ENOENT into the catch below and the very FIRST breadcrumb is lost — on the
    // machine most likely to have a broken daemon. Mirrors startup-log.ts.
    const dir = path.join(os.homedir(), '.node9');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    // Stamp FIRST, unconditionally. The throttle must be armed before anything
    // that can fail, because this runs on the enforcement hot path — once per tool
    // call. Every alternative is worse:
    //   append-first        → an unwritable stamp removes throttling entirely and
    //                         we append on EVERY tool call, forever.
    //   stamp-then-unlink   → a persistently failing append becomes an unbounded
    //                         write+unlink cycle on that same hot path.
    // The cost of this ordering is bounded and small: if the append fails, up to
    // one hour of breadcrumbs is lost. These are diagnostics — losing an hour of
    // them on a machine whose disk is already refusing writes is a far better
    // outcome than doing unbounded filesystem work per tool call.
    fs.writeFileSync(stamp, '', 'utf-8');
    fs.appendFileSync(
      path.join(dir, 'hook-debug.log'),
      `[${new Date().toISOString()}] daemon-autostart-skip: ${reason}\n`,
      'utf-8'
    );
  } catch {
    /* best-effort diagnostics — never break the hook */
  }
}

export async function autoStartDaemonAndWait(): Promise<boolean> {
  // Task #18: if ANY daemon is already serving the port — whatever build,
  // whether or not the pidfile knows it — never spawn a competitor. The hook
  // autostart is a fallback for "nothing is running", not a reconciler; racing
  // spawns are exactly how rogue daemons were born. Version reconciliation
  // belongs to explicit starts (systemd, `node9 daemon restart`).
  let alreadyServing = false;
  try {
    alreadyServing = await isDaemonReachable();
  } catch {
    /* a throwing probe must never break the hook — treat as not serving */
  }
  if (alreadyServing) {
    logAutostartSkipThrottled('already-serving');
    return true;
  }
  if (isTestingMode()) return false;
  if (!path.isAbsolute(process.argv[1])) return false;
  let resolvedArgv1: string;
  try {
    resolvedArgv1 = fs.realpathSync(process.argv[1]);
  } catch {
    return false;
  }
  if (!resolvedArgv1.endsWith('.js')) return false;
  // A4b: capture the child's stderr to daemon-startup.log (capped) so a startup
  // crash (e.g. an import-time ERR_REQUIRE_ESM) leaves a trace instead of vanishing.
  const startupFd = openStartupLogFd();
  // See check.ts: mark the attempt before spawning, so a child that dies at module
  // load (before it can run any of our code) still leaves evidence.
  recordStartupState('starting');
  let spawned = false;
  try {
    const child = spawn(process.execPath, [resolvedArgv1, 'daemon'], {
      detached: true,
      stdio: ['ignore', 'ignore', startupFd ?? 'ignore'],
      env: {
        ...process.env,
        NODE9_AUTO_STARTED: '1',
      },
    });
    // spawn() reports an exec failure on THIS EVENT, never by throwing — a
    // try/catch around spawn() cannot see ENOENT/EACCES/EMFILE. Without a listener
    // the attempt would also be left marked 'starting' forever and later reported
    // as an import-time crash that never happened. We out-live the event because of
    // the poll below, which is why this works here and not in the check hot path.
    child.on('error', (err: Error) => {
      // Only blame the attempt if nothing conclusive has landed since. This fires
      // asynchronously, so a racer's daemon may already have recorded 'ok' — and a
      // losing racer's exec failure must not overwrite a healthy daemon's state.
      if (readStartupState()?.outcome !== 'starting') return;
      recordStartupState('failed', 'spawn-failed', err.message);
    });
    child.unref();
    spawned = true; // past here a child exists and OWNS the outcome
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 250));
      if (!isDaemonRunning()) continue;
      // isDaemonRunning() is the cheap sync check (PID file + process.kill);
      // confirm the HTTP server is actually accepting connections before
      // returning true so callers don't get ECONNREFUSED on their first
      // request. The process may be alive but still mid-listen().
      if (await isDaemonReachable()) return true;
    }
  } catch (err) {
    // This catch also wraps the POLL loop, so it must not blame the attempt once a
    // child exists: by then the child has recorded (or will record) its own outcome,
    // and a poll-time throw here would overwrite a legitimate 'ok' with 'failed'
    // for a daemon that is actually up. Only a spawn that produced no child at all
    // may claim the attempt failed — and note exec failures do NOT arrive here at
    // all (they land on the 'error' listener above); this is for synchronous throws.
    if (!spawned)
      recordStartupState(
        'failed',
        'spawn-failed',
        err instanceof Error ? err.message : String(err)
      );
  } finally {
    // The child inherited its own fd copy at spawn(); close ours whether we
    // returned true, fell through, or threw — no leak across the poll loop.
    if (startupFd !== undefined) {
      try {
        fs.closeSync(startupFd);
      } catch {
        /* non-fatal */
      }
    }
  }
  return false;
}
