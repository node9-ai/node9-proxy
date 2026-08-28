import { spawn } from 'child_process';

/**
 * Best-effort browser open — must never fail or block. On headless machines
 * (SSH, no display) the caller's printed URL is the fallback, so this returns
 * false and stays silent. Shared by `node9 signup` and the device-login flow.
 */
export function openBrowser(url: string): boolean {
  // Headless heuristics: no display server on Linux, or an SSH session
  // anywhere — opening would either fail or open on the wrong machine.
  if (process.env.SSH_CONNECTION || process.env.SSH_TTY) return false;
  if (process.platform === 'linux' && !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) {
    return false;
  }
  const opener =
    process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  try {
    const child = spawn(opener, [url], {
      stdio: 'ignore',
      detached: true,
      shell: process.platform === 'win32',
    });
    child.on('error', () => {
      /* no browser available — the printed URL is the fallback */
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}
