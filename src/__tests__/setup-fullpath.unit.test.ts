/**
 * Unit tests for fullPathCommand / isStaleHookCommand / isNode9Hook.
 *
 * Regression suite for issue #185: on Windows + Git Bash (which Claude Code
 * uses to run hooks), the previously-generated hook command was the
 * unquoted form `C:\Program Files\nodejs\node.exe C:\Users\...\cli.js
 * check`. Bash split that on whitespace, ran the backslash-unescape on
 * the first token, and ended up trying to exec `C:Program: command not
 * found`. The fix quotes both paths and normalises backslashes to forward
 * slashes — both forms work on Windows, cmd, PowerShell, and POSIX.
 *
 * The existing setup.test.ts suite runs with NODE9_TESTING=1, which makes
 * fullPathCommand short-circuit to the bare `node9 <subcommand>` form and
 * therefore never exercises the production string-builder. This file
 * clears NODE9_TESTING per-test (via vi.stubEnv) and stubs process.execPath
 * + process.argv[1] to exercise the real path.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import { fullPathCommand, isStaleHookCommand, isNode9Hook } from '../setup.js';

// process.execPath is technically settable but not writable on all
// platforms (we run on Linux for CI, so it is). Helper to stub safely
// and restore.
function stubProcess(execPath: string, argv1: string): () => void {
  const origExec = process.execPath;
  const origArgv = process.argv[1];
  Object.defineProperty(process, 'execPath', { value: execPath, configurable: true });
  process.argv[1] = argv1;
  return () => {
    Object.defineProperty(process, 'execPath', { value: origExec, configurable: true });
    process.argv[1] = origArgv;
  };
}

describe('fullPathCommand', () => {
  let restoreProcess: () => void = () => {};

  beforeEach(() => {
    // Clear NODE9_TESTING so the production string-builder runs.
    // vi.stubEnv auto-restores on test teardown.
    vi.stubEnv('NODE9_TESTING', '');
  });

  afterEach(() => {
    restoreProcess();
    vi.unstubAllEnvs();
  });

  it('quotes + forward-slashes a Windows path with spaces (issue #185 regression)', () => {
    restoreProcess = stubProcess(
      'C:\\Program Files\\nodejs\\node.exe',
      'C:\\Users\\nadav\\AppData\\Roaming\\npm\\node_modules\\node9-ai\\node_modules\\@node9\\proxy\\dist\\cli.js'
    );
    // Both paths quoted, all backslashes converted to forward slashes.
    // Git Bash, cmd, and PowerShell all accept this form; the old
    // `C:\Program Files\...` form broke Git Bash on whitespace + escape.
    expect(fullPathCommand('check')).toBe(
      '"C:/Program Files/nodejs/node.exe" ' +
        '"C:/Users/nadav/AppData/Roaming/npm/node_modules/node9-ai/node_modules/@node9/proxy/dist/cli.js" ' +
        'check'
    );
  });

  it('quotes a POSIX path with spaces (e.g. /Users/Some User/...)', () => {
    // macOS users with spaces in their full name end up with a $HOME like
    // "/Users/Some User". The old unquoted form would have broken them
    // too — covered by the same fix.
    restoreProcess = stubProcess(
      '/Users/Some User/.nvm/versions/node/v22.0.0/bin/node',
      '/Users/Some User/.npm-global/lib/node_modules/node9-ai/dist/cli.js'
    );
    expect(fullPathCommand('log')).toBe(
      '"/Users/Some User/.nvm/versions/node/v22.0.0/bin/node" ' +
        '"/Users/Some User/.npm-global/lib/node_modules/node9-ai/dist/cli.js" ' +
        'log'
    );
  });

  it('quotes the bare-binary global-install form (no .js suffix)', () => {
    // When the binary itself is a self-contained executable (npm link
    // or some global installs), we skip the `node ${cliScript}` prefix
    // but still need to quote the binary path for the same reason.
    restoreProcess = stubProcess(
      '/usr/local/bin/node', // ignored on this branch
      '/usr/local/bin/node9' // ends without .js
    );
    expect(fullPathCommand('check')).toBe('"/usr/local/bin/node9" check');
  });

  it('still emits the bare "node9 <sub>" form under NODE9_TESTING=1', () => {
    // Restore the env short-circuit and confirm we haven't changed test-mode behavior.
    vi.stubEnv('NODE9_TESTING', '1');
    expect(fullPathCommand('check')).toBe('node9 check');
    expect(fullPathCommand('log')).toBe('node9 log');
  });
});

describe('isStaleHookCommand', () => {
  let restoreFs: () => void = () => {};

  beforeEach(() => {
    const spy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    restoreFs = () => spy.mockRestore();
  });

  afterEach(() => {
    restoreFs();
  });

  it('treats a quoted POSIX path that does not exist as stale', () => {
    // New quoted form must still get detected as stale when its files
    // are gone — the whole reason we have this helper is to repair
    // hooks left behind by an `npm uninstall`.
    expect(isStaleHookCommand('"/usr/bin/node" "/lib/node_modules/.../dist/cli.js" check')).toBe(
      true
    );
  });

  it('treats a quoted Windows-style path (C:/...) that does not exist as stale', () => {
    // Pre-fix `isStaleHookCommand` only treated `/`-prefixed tokens as
    // absolute, so on Windows the stale-detector never fired — a real
    // bug for any Windows user who uninstalled-then-reinstalled.
    expect(
      isStaleHookCommand('"C:/Program Files/nodejs/node.exe" "C:/Users/u/.../cli.js" check')
    ).toBe(true);
  });

  it('returns false for a bare "node9 check" command (resolved via PATH)', () => {
    expect(isStaleHookCommand('node9 check')).toBe(false);
  });

  it('returns false when every quoted path exists on disk', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    expect(isStaleHookCommand('"/usr/bin/node" "/lib/node_modules/.../dist/cli.js" check')).toBe(
      false
    );
  });
});

describe('isNode9Hook', () => {
  it('recognises the new quoted "cli.js check" form', () => {
    // The character immediately before `cli.js` is now `/` (forward
    // slash), so the existing `[\s/\\]` boundary class still matches —
    // but we want to be explicit and also tolerate a `"` boundary in
    // case the path itself doesn't contain a `/` separator before the
    // filename (e.g. a Windows root install at `C:/cli.js`).
    expect(isNode9Hook('"C:/Users/u/cli.js" check')).toBe(true);
    expect(isNode9Hook('"/usr/local/bin/cli.js" log')).toBe(true);
  });

  it('still recognises the legacy unquoted form (backward compat)', () => {
    // Hooks already on disk in the old unquoted form must keep being
    // recognised as node9 hooks until the next self-heal rewrites them.
    expect(isNode9Hook('/usr/bin/node /path/cli.js check')).toBe(true);
    expect(isNode9Hook('node9 check')).toBe(true);
    expect(isNode9Hook('node9 log')).toBe(true);
  });

  it('does not match unrelated commands', () => {
    expect(isNode9Hook('echo hi')).toBe(false);
    expect(isNode9Hook('mynode9 check')).toBe(false); // word-boundary
    expect(isNode9Hook(undefined)).toBe(false);
  });
});
