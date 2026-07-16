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
import { openStartupLogFd } from '../daemon/startup-log';

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
    fs.writeFileSync(stamp, '', 'utf-8'); // touch the throttle stamp
    fs.appendFileSync(
      path.join(os.homedir(), '.node9', 'hook-debug.log'),
      `[${new Date().toISOString()}] daemon-autostart-skip: ${reason}\n`,
      'utf-8'
    );
  } catch {
    /* best-effort diagnostics — never break the hook */
  }
}

export async function autoStartDaemonAndWait(): Promise<boolean> {
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
  try {
    const child = spawn(process.execPath, [resolvedArgv1, 'daemon'], {
      detached: true,
      stdio: ['ignore', 'ignore', startupFd ?? 'ignore'],
      env: {
        ...process.env,
        NODE9_AUTO_STARTED: '1',
      },
    });
    child.unref();
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 250));
      if (!isDaemonRunning()) continue;
      // isDaemonRunning() is the cheap sync check (PID file + process.kill);
      // confirm the HTTP server is actually accepting connections before
      // returning true so callers don't get ECONNREFUSED on their first
      // request. The process may be alive but still mid-listen().
      if (await isDaemonReachable()) return true;
    }
  } catch {
    /* spawn/poll failure → not started */
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
