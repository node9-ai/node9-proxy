/**
 * Windows Task Scheduler backend — the pure parts (login-v2, Windows daemon).
 * The exec wrappers are two-line spawnSync calls; everything that can be wrong
 * (VBS escaping, schtasks argv, hidden-window flag) is built by pure functions
 * so it is testable on any platform. The Windows CI runners exercise the same
 * code paths through the existing doctor/status integration tests.
 */
import { describe, it, expect } from 'vitest';
import { windowsLauncherVbs, schtasksCreateArgs } from '../daemon/service';

describe('windowsLauncherVbs', () => {
  const NODE = 'C:\\Program Files\\nodejs\\node.exe';
  const CLI = 'C:\\Users\\nadav\\AppData\\Roaming\\npm\\node_modules\\node9-ai\\dist\\cli.js';

  it('runs node + cli + daemon with a HIDDEN window (style 0)', () => {
    const vbs = windowsLauncherVbs(NODE, CLI);
    // VBS doubles quotes inside strings — each path must arrive doubly-quoted
    // so paths with spaces ("Program Files") survive.
    expect(vbs).toContain(`""${NODE}"" ""${CLI}"" daemon`);
    // Window style 0 + no-wait: the whole reason the launcher exists. A task
    // that ran node.exe directly would park a console window in the taskbar
    // for the entire session.
    expect(vbs).toMatch(/, 0, False/);
  });

  it('marks the daemon as auto-started via the process environment', () => {
    // Task Scheduler cannot set per-task env vars — the launcher's process
    // env is how NODE9_AUTO_STARTED reaches the daemon, like the plist/unit do.
    const vbs = windowsLauncherVbs(NODE, CLI);
    expect(vbs).toContain('sh.Environment("PROCESS")("NODE9_AUTO_STARTED") = "1"');
  });

  it('uses CRLF — notepad-openable, and VBS is a Windows-native format', () => {
    expect(windowsLauncherVbs(NODE, CLI)).toContain('\r\n');
  });

  it('refuses a path containing a quote instead of producing broken VBS', () => {
    expect(() => windowsLauncherVbs('C:\\evil"quote\\node.exe', CLI)).toThrow(/Illegal quote/);
  });
});

describe('schtasksCreateArgs', () => {
  it('creates an ONLOGON task for the current user, idempotently', () => {
    const args = schtasksCreateArgs('C:\\Users\\nadav\\.node9\\daemon-launcher.vbs');
    expect(args).toEqual([
      '/Create',
      '/TN',
      'Node9Daemon',
      '/TR',
      'wscript.exe //B "C:\\Users\\nadav\\.node9\\daemon-launcher.vbs"',
      '/SC',
      'ONLOGON',
      '/F',
    ]);
  });

  it('quotes the launcher path inside /TR (home dirs contain spaces)', () => {
    const args = schtasksCreateArgs('C:\\Users\\Nadav Cohen\\.node9\\daemon-launcher.vbs');
    const tr = args[args.indexOf('/TR') + 1];
    expect(tr).toBe('wscript.exe //B "C:\\Users\\Nadav Cohen\\.node9\\daemon-launcher.vbs"');
  });

  it('never asks for elevation — no /RU, runs as the logged-on user', () => {
    // /RU would demand credentials or admin rights; the whole design is a
    // user-level agent, matching launchd user agents and systemd --user.
    expect(schtasksCreateArgs('x.vbs')).not.toContain('/RU');
  });
});
