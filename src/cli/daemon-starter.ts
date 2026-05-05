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
import { isDaemonRunning, DAEMON_PORT, DAEMON_HOST } from '../auth/daemon';

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
      // Verify the HTTP server is actually accepting connections, not just that
      // the process is alive. isDaemonRunning() only checks the PID file, which
      // could be stale (OS PID reuse) or written before the socket is fully ready.
      try {
        const res = await fetch(`http://${DAEMON_HOST}:${DAEMON_PORT}/settings`, {
          signal: AbortSignal.timeout(500),
        });
        if (res.ok) return true;
      } catch {
        // HTTP not ready yet — keep polling
      }
    }
  } catch {}
  return false;
}
