// src/daemon/startup-log.ts
// A4c (policy-sync-commit2-liveness): a tiny structured log for daemon STARTUP
// outcomes, written to ~/.node9/daemon-startup.log. The daemon's startup deaths
// (a sync-init throw, a fatal bind error) and benign port-in-use exits used to be
// silent under stdio:'ignore'; this makes them diagnosable, and `doctor` tails the
// last line when it reports the daemon down. Best-effort — never throws.
import fs from 'fs';
import path from 'path';
import os from 'os';

export const DAEMON_STARTUP_LOG = () => path.join(os.homedir(), '.node9', 'daemon-startup.log');

// A daemon that crash-loops (the exact incident: ERR_REQUIRE_ESM at import) gets
// re-spawned on many tool calls, each appending its startup stderr here. Cap the
// file so that loop can't grow it without bound (old code discarded stderr entirely).
const MAX_STARTUP_LOG_BYTES = 256 * 1024;

/**
 * Open daemon-startup.log (append) for a spawned daemon's stderr — creating ~/.node9
 * if absent and truncating first if the file grew past the cap. Returns an fd the
 * CALLER MUST close (in a finally), or undefined to fall back to discarding stderr.
 * Never throws.
 */
export function openStartupLogFd(): number | undefined {
  try {
    const file = DAEMON_STARTUP_LOG();
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    try {
      if (fs.statSync(file).size > MAX_STARTUP_LOG_BYTES) fs.truncateSync(file);
    } catch {
      /* absent → nothing to truncate */
    }
    return fs.openSync(file, 'a');
  } catch {
    return undefined;
  }
}

/** Append one structured line: `[ISO] daemon-startup:<kind> <detail>`. Never throws. */
export function logDaemonStartup(kind: string, detail?: string): void {
  try {
    const file = DAEMON_STARTUP_LOG();
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const line = `[${new Date().toISOString()}] daemon-startup:${kind}${detail ? ` ${detail}` : ''}\n`;
    fs.appendFileSync(file, line, 'utf-8');
  } catch {
    /* diagnostics are best-effort — never let logging break daemon startup/exit */
  }
}
