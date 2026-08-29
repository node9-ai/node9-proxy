// src/daemon/service.ts
// Install / uninstall the node9 daemon as a login service.
// macOS   → launchd user agent    ~/Library/LaunchAgents/ai.node9.daemon.plist
// Linux   → systemd user unit     ~/.config/systemd/user/node9-daemon.service
// Windows → Task Scheduler task   "Node9Daemon" (ONLOGON, via a hidden-window
//           VBS launcher at ~/.node9/daemon-launcher.vbs)
// Other   → unsupported (no-op with warning)
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

// DO NOT add `StandardError=append:%h/.node9/daemon-startup.log` to the unit below.
// It looks like the systemd equivalent of the auto-start path's stderr capture, but
// systemd opens that file ITSELF and does not create parent directories: with
// ~/.node9 absent (e.g. after the documented `rm -rf ~/.node9` reset) the unit fails
// with status=222/STDERR *before exec*, and Restart=on-failure then crash-loops it to
// the start limit and leaves it permanently dead. That is precisely the
// silent-stale-policy incident this diagnostic exists to prevent — caused by the
// diagnostic. Verified on systemd 255, 2026-07-18. A module-load crash under systemd
// goes to the journal instead: `journalctl --user -u node9-daemon`.
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

// ── Windows logon startup ──────────────────────────────────────────────────
// The per-user Startup folder, NOT Task Scheduler.
//
// schtasks was the first attempt and it is the wrong tool: `schtasks /Create`
// writes to the root task folder, which requires elevation. On a normal user
// account every install failed with `ERROR: Access is denied.` — reproduced
// on a founder machine with a bare `/TR notepad.exe`, so it was the mechanism,
// not our arguments (2026-08-29). Asking a developer to run an elevated shell
// to make logging work is not an onboarding step we are willing to ship.
//
// The Startup folder needs no privileges at all and is the true analogue of a
// launchd USER agent / `systemd --user` unit: per-user, at interactive logon.
// The trade is no restart-on-failure — acceptable, because the agent hooks
// already respawn a dead daemon on the next tool call.
//
// A .vbs there (rather than a .cmd or a shortcut to node) is what keeps the
// daemon INVISIBLE: a console app launched at logon parks a console window in
// the taskbar for the whole session. `Wscript.Shell.Run … , 0` starts it hidden.

const STARTUP_FILE = 'node9-daemon.vbs';

/**
 * Turn a failed spawnSync into a sentence a user can act on.
 *
 * The first Windows install reported `schtasks /Create failed: unknown error`
 * because the message only read stderr/stdout — but a command that never RAN
 * (missing binary, blocked, timed out) leaves both empty and reports itself in
 * `.error` / `.status: null`. A diagnostic that can print "unknown error" is
 * not a diagnostic. Exported for tests.
 */
export function describeSpawnFailure(
  what: string,
  r: {
    status: number | null;
    signal?: NodeJS.Signals | null;
    stdout?: string;
    stderr?: string;
    error?: Error;
  }
): string {
  const parts: string[] = [];
  const out = `${r.stderr ?? ''}${r.stdout ?? ''}`.trim();
  if (out) parts.push(out);
  if (r.error) {
    const code = (r.error as NodeJS.ErrnoException).code;
    parts.push(
      code === 'ENOENT' ? `${what.split(' ')[0]} not found on this machine` : r.error.message
    );
  }
  if (r.signal) parts.push(`killed by ${r.signal}`);
  if (!parts.length) {
    parts.push(
      r.status === null
        ? 'the command did not run (timed out or was blocked)'
        : `exit code ${r.status}`
    );
  }
  return `${what} failed: ${parts.join(' — ')}`;
}

/** The per-user Startup folder. Honours APPDATA (roaming/redirected profiles)
 *  before falling back to the conventional location. */
export function windowsStartupDir(homeDir: string = os.homedir()): string {
  // `||`, not `??` (repo rule): an APPDATA set to "" passes a ?? guard and
  // yields a RELATIVE path — the Startup entry would land somewhere random
  // and autostart would silently never happen. Caught by the unit test below.
  const appData = process.env.APPDATA || path.join(homeDir, 'AppData', 'Roaming');
  return path.join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
}

const WIN_LAUNCHER = () => path.join(windowsStartupDir(), STARTUP_FILE);

/**
 * The hidden-window launcher.
 *
 * ASCII ONLY. Windows Script Host reads a .vbs as ANSI unless it carries a
 * UTF-16 BOM, so a UTF-8 em dash in the first version rendered as `â€"` on the
 * founder's machine. It was only a comment that time; in a path it would have
 * broken the launch outright.
 *
 * VBS escapes a quote by doubling it. Windows paths cannot legally contain `"`,
 * so embedding them is safe — the guard is for a corrupted argv reaching us.
 * NODE9_AUTO_STARTED rides the launcher's process environment, matching what
 * the plist and the systemd unit set.
 */
export function windowsLauncherVbs(nodePath: string, scriptPath: string): string {
  for (const p of [nodePath, scriptPath]) {
    if (p.includes('"')) throw new Error(`Illegal quote in path: ${p}`);
  }
  return [
    "' Auto-generated by node9 - starts the approval daemon with no console window.",
    "' Recreated by `node9 daemon install`; removed by `node9 daemon uninstall`.",
    'Set sh = CreateObject("Wscript.Shell")',
    'sh.Environment("PROCESS")("NODE9_AUTO_STARTED") = "1"',
    `sh.Run """${nodePath}"" ""${scriptPath}"" daemon", 0, False`,
    '',
  ].join('\r\n');
}

function installWindowsStartup(binaryPath: string): void {
  const target = WIN_LAUNCHER();
  const dir = path.dirname(target);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(target, windowsLauncherVbs(process.execPath, binaryPath), 'utf-8');
  // Start it now — parity with systemd's `enable --now` and launchd's `load`.
  // Best-effort: the logon entry is installed either way.
  spawnSync('wscript.exe', ['//B', target], { encoding: 'utf8', timeout: 10_000 });
}

function uninstallWindowsStartup(): void {
  const target = WIN_LAUNCHER();
  if (fs.existsSync(target)) fs.unlinkSync(target);
}

/** Installed and enabled are the same thing here: the file is in Startup or it
 *  is not. There is no disabled-but-present state to detect, unlike a systemd
 *  unit or a scheduled task. */
function isWindowsStartupInstalled(): boolean {
  return fs.existsSync(WIN_LAUNCHER());
}

// ── Public API ─────────────────────────────────────────────────────────────

export type ServiceInstallResult =
  | { ok: true; platform: 'launchd' | 'systemd' | 'startup-folder'; alreadyInstalled: boolean }
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
        // Give it a moment to shut down cleanly. Portable wait: the previous
        // `sh -c 'while kill -0 …'` poll assumed a POSIX shell and silently
        // did nothing on Windows. process.kill(pid, 0) probes liveness
        // everywhere; Atomics.wait is a sleep that needs no shell at all.
        const deadline = Date.now() + 3000;
        const sleeper = new Int32Array(new SharedArrayBuffer(4));
        while (Date.now() < deadline) {
          try {
            process.kill(pid, 0);
          } catch {
            break; // gone
          }
          Atomics.wait(sleeper, 0, 0, 100);
        }
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

    if (process.platform === 'win32') {
      const alreadyInstalled = isWindowsStartupInstalled();
      installWindowsStartup(binary);
      return { ok: true, platform: 'startup-folder', alreadyInstalled };
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
    if (process.platform === 'win32') {
      uninstallWindowsStartup();
      return { ok: true, platform: 'startup-folder', alreadyInstalled: false };
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
  if (process.platform === 'win32') return isWindowsStartupInstalled();
  return false;
}

/** Pure decision for the self-heal. `repair` = re-enable an already-installed but
 *  DISABLED unit (the incident state) — deliberately NOT when the unit is absent:
 *  we never silently INSTALL a new service from login/init (that surprised users),
 *  we only re-enable one the user already had. No I/O — testable. */
export function autostartRepairDecision(opts: {
  installed: boolean;
  enabled: boolean;
  autoStartDaemon: boolean;
}): 'ok' | 'repair' | 'skip' | 'unsupported' {
  if (!opts.autoStartDaemon) return 'skip'; // user opted out — never touch the service
  if (
    process.platform !== 'linux' &&
    process.platform !== 'darwin' &&
    process.platform !== 'win32'
  ) {
    return 'unsupported';
  }
  if (!opts.installed) return 'skip'; // no unit → advise (doctor), don't auto-install
  return opts.enabled ? 'ok' : 'repair'; // installed-but-disabled → re-enable
}

/**
 * Re-enable an already-installed autostart unit for next boot, WITHOUT stopping or
 * restarting the currently-running daemon. Unlike `installDaemonService()` (which
 * stops + `enable --now`), this is non-disruptive — safe to call from `login`.
 * Linux: `systemctl --user enable node9-daemon` (no `--now`). Darwin: launchd units
 * installed via `load -w` are already persistent, so a no-op. Never throws.
 */
function enableDaemonServiceQuiet(): boolean {
  try {
    if (process.platform === 'linux') {
      const r = spawnSync('systemctl', ['--user', 'enable', 'node9-daemon'], {
        encoding: 'utf8',
        timeout: 3000,
      });
      return r.status === 0;
    }
    if (process.platform === 'win32') {
      // Nothing to re-enable: the Startup entry is present or absent, and
      // installing a missing one is deliberately not this function's job
      // (see autostartRepairDecision — we never silently install).
      return isWindowsStartupInstalled();
    }
    // darwin: `load -w` (done at install) already sets RunAtLoad persistently.
    return process.platform === 'darwin';
  } catch {
    return false;
  }
}

/**
 * Best-effort, NON-DISRUPTIVE self-heal called from `init`/`login`: if autostart is
 * wanted and the service is installed-but-DISABLED (the state that silently staled
 * policy for 6 days), re-enable it for next boot without restarting the running
 * daemon. Does NOT install a missing unit and does NOT stop a live daemon. Respects
 * the `autoStartDaemon` opt-out. Never throws. Returns what happened.
 */
export function ensureAutostartHealthy(
  autoStartDaemon: boolean
): 'ok' | 'repaired' | 'skipped' | 'unsupported' {
  const decision = autostartRepairDecision({
    installed: isDaemonServiceInstalled(),
    enabled: isDaemonServiceEnabled(),
    autoStartDaemon,
  });
  if (decision === 'repair') return enableDaemonServiceQuiet() ? 'repaired' : 'skipped';
  return decision === 'ok' ? 'ok' : decision === 'unsupported' ? 'unsupported' : 'skipped';
}

/** Advice line for the daemon-autostart health, rendered by `doctor` and `status`.
 *  Pure (no I/O) so it's testable without the host's real systemd state. */
export type AutostartAdvice = { level: 'warn'; message: string; hint: string } | null;

/**
 * Decide what to surface about daemon autostart. This advice is entirely about
 * CLOUD-POLICY freshness, so it only applies when cloud policy is enforced
 * (`cloudEnabled`) and autostart is actually installable on this platform —
 * a privacy-mode user never syncs, so they should not be nagged. Returns null
 * (say nothing) otherwise.
 */
/** The per-platform way to make the daemon survive reboots. ONE definition —
 *  doctor's stale-policy hint used to hardcode systemctl and sent a Windows
 *  founder a Linux command (QA 2026-08-28). */
export function autostartInstallHint(): string {
  return process.platform === 'linux'
    ? 'Run: systemctl --user enable --now node9-daemon   (or: node9 daemon install)'
    : 'Run: node9 daemon install';
}

export function autostartAdvice(opts: {
  installed: boolean;
  enabled: boolean;
  cloudEnabled: boolean;
}): AutostartAdvice {
  const installable =
    process.platform === 'linux' || process.platform === 'darwin' || process.platform === 'win32';
  if (!opts.cloudEnabled || !installable) return null;
  const installHint = autostartInstallHint();
  if (opts.installed && !opts.enabled) {
    return {
      level: 'warn',
      message:
        'Daemon autostart is INSTALLED but DISABLED — it will NOT survive a reboot, so cloud policy can silently go stale.',
      hint: installHint,
    };
  }
  if (!opts.installed) {
    return {
      level: 'warn',
      message:
        'No daemon autostart installed — the daemon only runs when an agent happens to spawn it; cloud policy may lag.',
      hint: installHint,
    };
  }
  return null;
}

/**
 * Is the autostart service ENABLED (will start on boot/login)? The state that
 * silently staled policy for 6 days is INSTALLED but not enabled — a unit file on
 * disk that never runs. `isDaemonServiceInstalled()` alone can't see it.
 *
 * Linux: `systemctl --user is-enabled node9-daemon` prints "enabled" / exits 0 only
 * when DURABLY enabled. Deliberately strict — "enabled-runtime" exits 0 too but does
 * NOT survive a reboot (the exact failure mode), and "static"/"indirect" aren't
 * durable either, so we require the literal "enabled".
 * Darwin: `launchctl list <label>` exits 0 iff the agent is loaded.
 * Never throws.
 */
export function isDaemonServiceEnabled(): boolean {
  try {
    if (process.platform === 'linux') {
      const r = spawnSync('systemctl', ['--user', 'is-enabled', 'node9-daemon'], {
        encoding: 'utf8',
        timeout: 3000,
      });
      return r.status === 0 && (r.stdout ?? '').trim() === 'enabled';
    }
    if (process.platform === 'darwin') {
      const r = spawnSync('launchctl', ['list', LAUNCHD_LABEL], {
        encoding: 'utf8',
        timeout: 3000,
      });
      return r.status === 0;
    }
    if (process.platform === 'win32') {
      return isWindowsStartupInstalled();
    }
  } catch {
    /* probe failure → treat as not-enabled; never throw */
  }
  return false;
}
