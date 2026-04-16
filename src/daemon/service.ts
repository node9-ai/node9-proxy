// src/daemon/service.ts
// Install / uninstall the node9 daemon as a login service.
// macOS  → launchd user agent   ~/Library/LaunchAgents/ai.node9.daemon.plist
// Linux  → systemd user unit    ~/.config/systemd/user/node9-daemon.service
// Other  → unsupported (no-op with warning)
import fs from 'fs';
import path from 'path';
import os from 'os';
import { spawnSync, execFileSync } from 'child_process';

// ── Paths ──────────────────────────────────────────────────────────────────

const LAUNCHD_LABEL = 'ai.node9.daemon';
const LAUNCHD_PLIST = path.join(os.homedir(), 'Library', 'LaunchAgents', `${LAUNCHD_LABEL}.plist`);
const SYSTEMD_UNIT_DIR = path.join(os.homedir(), '.config', 'systemd', 'user');
const SYSTEMD_UNIT = path.join(SYSTEMD_UNIT_DIR, 'node9-daemon.service');

// ── Binary resolution ──────────────────────────────────────────────────────

/**
 * Resolve the absolute path to the node9 CLI binary.
 * Tries (in order): process.argv[1], PATH lookup via `which`/`where`.
 */
export function resolveNode9Binary(): string | null {
  // argv[1] is the currently running script — most reliable
  try {
    const script = process.argv[1];
    if (typeof script === 'string' && path.isAbsolute(script) && fs.existsSync(script)) {
      return fs.realpathSync(script);
    }
  } catch {
    /* fall through */
  }

  // Fall back to PATH lookup
  try {
    const cmd = process.platform === 'win32' ? 'where' : 'which';
    const r = spawnSync(cmd, ['node9'], { encoding: 'utf8', timeout: 3000 });
    if (r.status === 0 && r.stdout.trim()) {
      return r.stdout.trim().split('\n')[0].trim();
    }
  } catch {
    /* fall through */
  }

  return null;
}

// ── macOS launchd ──────────────────────────────────────────────────────────

/** Escape characters that are special in XML string content. */
function xmlEscape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function launchdPlist(binaryPath: string): string {
  const logDir = path.join(os.homedir(), '.node9');
  // Use the Node.js runtime + script path form so the plist works correctly
  // when node9 is installed via nvm, volta, or any version manager that doesn't
  // put the binary on a system-wide PATH available to launchd at boot.
  const nodePath = xmlEscape(process.execPath);
  const scriptPath = xmlEscape(binaryPath);
  const outLog = xmlEscape(path.join(logDir, 'daemon.log'));
  const errLog = xmlEscape(path.join(logDir, 'daemon-error.log'));
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${nodePath}</string>
        <string>${scriptPath}</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>${outLog}</string>
    <key>StandardErrorPath</key>
    <string>${errLog}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>NODE9_AUTO_STARTED</key>
        <string>1</string>
        <key>NODE9_BROWSER_OPENED</key>
        <string>1</string>
    </dict>
</dict>
</plist>
`;
}

function installLaunchd(binaryPath: string): void {
  const dir = path.dirname(LAUNCHD_PLIST);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(LAUNCHD_PLIST, launchdPlist(binaryPath), 'utf-8');
  // Unload any old version first — ignore errors (may not be loaded)
  spawnSync('launchctl', ['unload', LAUNCHD_PLIST], { encoding: 'utf8' });
  const r = spawnSync('launchctl', ['load', '-w', LAUNCHD_PLIST], {
    encoding: 'utf8',
    timeout: 5000,
  });
  if (r.status !== 0) {
    throw new Error(`launchctl load failed: ${r.stderr || r.stdout || 'unknown error'}`);
  }
}

function uninstallLaunchd(): void {
  if (fs.existsSync(LAUNCHD_PLIST)) {
    spawnSync('launchctl', ['unload', '-w', LAUNCHD_PLIST], { encoding: 'utf8', timeout: 5000 });
    fs.unlinkSync(LAUNCHD_PLIST);
  }
}

function isLaunchdInstalled(): boolean {
  return fs.existsSync(LAUNCHD_PLIST);
}

// ── Linux systemd ──────────────────────────────────────────────────────────

function systemdUnit(binaryPath: string): string {
  // Use the Node.js runtime + script path explicitly so the unit works correctly
  // when node9 is installed via nvm, volta, or any version manager whose shims
  // are not available in the systemd user session PATH.
  return `[Unit]
Description=node9 approval daemon
After=network.target

[Service]
Type=simple
ExecStart=${process.execPath} ${binaryPath} daemon
Restart=on-failure
RestartSec=10s
Environment=NODE9_AUTO_STARTED=1
Environment=NODE9_BROWSER_OPENED=1

[Install]
WantedBy=default.target
`;
}

function installSystemd(binaryPath: string): void {
  if (!fs.existsSync(SYSTEMD_UNIT_DIR)) {
    fs.mkdirSync(SYSTEMD_UNIT_DIR, { recursive: true });
  }
  fs.writeFileSync(SYSTEMD_UNIT, systemdUnit(binaryPath), 'utf-8');
  // Enable lingering so the service starts without a full login (useful in CI/servers)
  try {
    execFileSync('loginctl', ['enable-linger', os.userInfo().username], { timeout: 3000 });
  } catch {
    /* non-fatal — linger not available in all envs */
  }
  const reload = spawnSync('systemctl', ['--user', 'daemon-reload'], {
    encoding: 'utf8',
    timeout: 5000,
  });
  if (reload.status !== 0) {
    throw new Error(`systemctl daemon-reload failed: ${reload.stderr}`);
  }
  // Stop any manually-started daemon so the service becomes the sole owner.
  // If this fails (e.g. not running), that's fine — ignore the error.
  spawnSync('systemctl', ['--user', 'stop', 'node9-daemon'], { encoding: 'utf8', timeout: 3000 });
  const enable = spawnSync('systemctl', ['--user', 'enable', '--now', 'node9-daemon'], {
    encoding: 'utf8',
    timeout: 5000,
  });
  if (enable.status !== 0) {
    throw new Error(`systemctl enable failed: ${enable.stderr}`);
  }
}

function uninstallSystemd(): void {
  if (fs.existsSync(SYSTEMD_UNIT)) {
    spawnSync('systemctl', ['--user', 'disable', '--now', 'node9-daemon'], {
      encoding: 'utf8',
      timeout: 5000,
    });
    spawnSync('systemctl', ['--user', 'daemon-reload'], { encoding: 'utf8', timeout: 5000 });
    fs.unlinkSync(SYSTEMD_UNIT);
  }
}

function isSystemdInstalled(): boolean {
  return fs.existsSync(SYSTEMD_UNIT);
}

// ── Public API ─────────────────────────────────────────────────────────────

export type ServiceInstallResult =
  | { ok: true; platform: 'launchd' | 'systemd'; alreadyInstalled: boolean }
  | { ok: false; reason: string };

/**
 * Stop any manually-started daemon process so the service becomes the sole owner.
 * Reads the PID file and sends SIGTERM if the process is alive.
 */
function stopRunningDaemon(): void {
  const pidFile = path.join(os.homedir(), '.node9', 'daemon.pid');
  if (!fs.existsSync(pidFile)) return;
  try {
    const data = JSON.parse(fs.readFileSync(pidFile, 'utf-8')) as Record<string, unknown>;
    const pid = data.pid;
    const MAX_PID = 4_194_304;
    if (typeof pid === 'number' && Number.isInteger(pid) && pid > 0 && pid <= MAX_PID) {
      try {
        process.kill(pid, 'SIGTERM');
        // Give it a moment to shut down cleanly
        const deadline = Date.now() + 3000;
        const pollStop = spawnSync(
          'sh',
          ['-c', `while kill -0 ${pid} 2>/dev/null; do sleep 0.1; done`],
          {
            timeout: 3100,
          }
        );
        void pollStop; // result unused — we just wait
        void deadline;
      } catch {
        /* already dead */
      }
    }
    try {
      fs.unlinkSync(pidFile);
    } catch {
      /* non-fatal */
    }
  } catch {
    /* parse error — ignore */
  }
}

/**
 * Install the daemon as a login service for the current user.
 * Idempotent — safe to call again if already installed (reinstalls to pick up new binary path).
 */
export function installDaemonService(): ServiceInstallResult {
  const binary = resolveNode9Binary();
  if (!binary) {
    return { ok: false, reason: 'Could not locate the node9 binary. Is it in your PATH?' };
  }

  // Stop any manually-started daemon so the service becomes the sole authority.
  stopRunningDaemon();

  try {
    if (process.platform === 'darwin') {
      const alreadyInstalled = isLaunchdInstalled();
      installLaunchd(binary);
      return { ok: true, platform: 'launchd', alreadyInstalled };
    }

    if (process.platform === 'linux') {
      // Check systemd is available
      const check = spawnSync('systemctl', ['--user', '--version'], {
        encoding: 'utf8',
        timeout: 2000,
      });
      if (check.status !== 0) {
        return {
          ok: false,
          reason: 'systemd not available. Start the daemon manually with: node9 daemon start',
        };
      }
      const alreadyInstalled = isSystemdInstalled();
      installSystemd(binary);
      return { ok: true, platform: 'systemd', alreadyInstalled };
    }

    return {
      ok: false,
      reason: `Automatic service install is not supported on ${process.platform}. Start the daemon manually with: node9 daemon start`,
    };
  } catch (err) {
    return {
      ok: false,
      reason: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Remove the daemon login service. Does not stop the currently running daemon process.
 */
export function uninstallDaemonService(): ServiceInstallResult {
  try {
    if (process.platform === 'darwin') {
      uninstallLaunchd();
      return { ok: true, platform: 'launchd', alreadyInstalled: false };
    }
    if (process.platform === 'linux') {
      uninstallSystemd();
      return { ok: true, platform: 'systemd', alreadyInstalled: false };
    }
    return {
      ok: false,
      reason: `Service management not supported on ${process.platform}.`,
    };
  } catch (err) {
    return {
      ok: false,
      reason: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Returns whether the daemon login service is currently installed.
 */
export function isDaemonServiceInstalled(): boolean {
  if (process.platform === 'darwin') return isLaunchdInstalled();
  if (process.platform === 'linux') return isSystemdInstalled();
  return false;
}
