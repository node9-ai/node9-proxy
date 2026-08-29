/**
 * Windows logon-startup backend — the pure parts (login-v2, Windows daemon).
 *
 * History worth keeping: this started as a Task Scheduler backend and every
 * install failed with `ERROR: Access is denied.` on a normal account, because
 * `schtasks /Create` writes to the root task folder and that needs elevation.
 * A bare `/TR notepad.exe` failed identically, which proved it was the
 * mechanism rather than our arguments. The Startup folder needs no privileges.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import path from 'path';
import { windowsLauncherVbs, windowsStartupDir, describeSpawnFailure } from '../daemon/service';

describe('windowsLauncherVbs', () => {
  const NODE = 'C:\\Program Files\\nodejs\\node.exe';
  const CLI = 'C:\\Users\\nadav\\AppData\\Roaming\\npm\\node_modules\\node9-ai\\dist\\cli.js';

  it('runs node + cli + daemon with a HIDDEN window (style 0)', () => {
    const vbs = windowsLauncherVbs(NODE, CLI);
    // VBS doubles quotes inside strings — each path must arrive doubly-quoted
    // so paths with spaces ("Program Files") survive.
    expect(vbs).toContain(`""${NODE}"" ""${CLI}"" daemon`);
    // Window style 0 + no-wait: the whole reason a .vbs is used instead of a
    // .cmd. A console app at logon parks a window in the taskbar all session.
    expect(vbs).toMatch(/, 0, False/);
  });

  it('is ASCII-only — WSH reads .vbs as ANSI without a BOM', () => {
    // The first version used a UTF-8 em dash in a comment and rendered as
    // `â€"` on the founder's machine. Harmless in a comment; in a path it
    // would have broken the launch.
    const vbs = windowsLauncherVbs(NODE, CLI);
    // eslint-disable-next-line no-control-regex
    expect(vbs).toMatch(/^[\x00-\x7F]*$/);
  });

  it('marks the daemon as auto-started via the process environment', () => {
    expect(windowsLauncherVbs(NODE, CLI)).toContain(
      'sh.Environment("PROCESS")("NODE9_AUTO_STARTED") = "1"'
    );
  });

  it('uses CRLF — a Windows-native format read by a legacy host', () => {
    expect(windowsLauncherVbs(NODE, CLI)).toContain('\r\n');
  });

  it('refuses a path containing a quote instead of emitting broken VBS', () => {
    expect(() => windowsLauncherVbs('C:\\evil"quote\\node.exe', CLI)).toThrow(/Illegal quote/);
  });
});

describe('windowsStartupDir', () => {
  afterEach(() => vi.unstubAllEnvs());

  // path.join uses the HOST separator, so these assert structure rather than a
  // literal string — otherwise they would only be true on a Windows runner.
  it('honours APPDATA (roaming / redirected profiles)', () => {
    vi.stubEnv('APPDATA', 'D:\\Roaming');
    expect(windowsStartupDir('C:\\Users\\nadav')).toBe(
      path.join('D:\\Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    );
  });

  it('an EMPTY APPDATA falls back instead of producing a relative path', () => {
    // `??` would let "" through and the Startup entry would land somewhere
    // relative — autostart would silently never happen. This is the repo's
    // documented `|| undefined` rule; the test found the violation.
    vi.stubEnv('APPDATA', '');
    const p = windowsStartupDir('C:\\Users\\nadav');
    expect(p).toContain('AppData');
    expect(p.startsWith('Microsoft')).toBe(false);
  });
});

describe('describeSpawnFailure', () => {
  // The first Windows install printed `schtasks /Create failed: unknown error`
  // — a diagnostic that can say "unknown error" is not a diagnostic.
  it('never says "unknown error" when the command did not run', () => {
    const msg = describeSpawnFailure('wscript.exe', { status: null });
    expect(msg).not.toMatch(/unknown error/);
    expect(msg).toMatch(/did not run/);
  });

  it('names a missing binary from the spawn error, not the empty streams', () => {
    const err = Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' });
    const msg = describeSpawnFailure('wscript.exe //B x', { status: null, error: err });
    expect(msg).toMatch(/wscript\.exe not found/);
  });

  it('prefers the command output when there is any', () => {
    const msg = describeSpawnFailure('cmd', { status: 1, stderr: 'ERROR: Access is denied.' });
    expect(msg).toContain('Access is denied');
  });

  it('falls back to the exit code when a failure produced no output at all', () => {
    expect(describeSpawnFailure('cmd', { status: 5 })).toMatch(/exit code 5/);
  });
});
