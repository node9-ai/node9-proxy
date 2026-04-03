// src/cli/daemon-starter.ts
// Shared helpers for auto-starting the approval daemon from CLI commands.
import { spawn, execSync } from 'child_process';
import { isDaemonRunning, DAEMON_PORT, DAEMON_HOST } from '../auth/daemon';

export function openBrowserLocal() {
  const url = `http://${DAEMON_HOST}:${DAEMON_PORT}/`;
  try {
    const opts = { stdio: 'ignore' as const };
    if (process.platform === 'darwin') execSync(`open "${url}"`, opts);
    else if (process.platform === 'win32') execSync(`cmd /c start "" "${url}"`, opts);
    else execSync(`xdg-open "${url}"`, opts);
  } catch {}
}

export async function autoStartDaemonAndWait(): Promise<boolean> {
  if (process.env.NODE9_TESTING === '1') return false;
  try {
    const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
      detached: true,
      stdio: 'ignore',
      // NODE9_BROWSER_OPENED=1 tells the daemon we will open the browser ourselves
      // (openBrowserLocal below), so it must not open a duplicate tab on first approval.
      env: { ...process.env, NODE9_AUTO_STARTED: '1', NODE9_BROWSER_OPENED: '1' },
    });
    child.unref();
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 250));
      if (!isDaemonRunning()) continue;
      // Verify the HTTP server is actually accepting connections, not just that
      // the process is alive. isDaemonRunning() only checks the PID file, which
      // could be stale (OS PID reuse) or written before the socket is fully ready.
      try {
        const res = await fetch('http://127.0.0.1:7391/settings', {
          signal: AbortSignal.timeout(500),
        });
        if (res.ok) {
          // Open the browser NOW — before the approval request is registered —
          // so the browser has time to connect SSE. If we wait until POST /check,
          // broadcast('add') fires with sseClients.size === 0 and the request
          // depends on the async openBrowser() inside the daemon, which can lose
          // the race with the browser's own page-load timing.
          openBrowserLocal();
          return true;
        }
      } catch {
        // HTTP not ready yet — keep polling
      }
    }
  } catch {}
  return false;
}
