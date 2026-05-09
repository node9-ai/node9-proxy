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
import { isDaemonRunning, isDaemonReachable } from '../auth/daemon';

export function isTestingMode(): boolean {
  return /^(1|true|yes)$/i.test(process.env.NODE9_TESTING ?? '');
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
  try {
    const child = spawn(process.execPath, [resolvedArgv1, 'daemon'], {
      detached: true,
      stdio: 'ignore',
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
  } catch {}
  return false;
}
