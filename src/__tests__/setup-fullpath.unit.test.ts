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
import { spawnSync } from 'child_process';
import fs from 'fs';
import {
  fullPathCommand,
  isStaleHookCommand,
  isNode9Hook,
  isLegacyHookFormat,
  needsRewrite,
  isWindowsQuoteBrokenHook,
  isChurnProneHookForm,
  isPathNodeHookForm,
  pinsNode,
  pinnedNode,
  rewrittenHookCommand,
  isNode9StatusLine,
  hookShimPath,
  hookShimBody,
  ensureHookShim,
} from '../setup.js';
import {
  shimPath,
  shimBody,
  ensureShims,
  isShimTargetStale,
  mcpLauncherArgv,
  readyLauncherArgv,
} from '../node9-shim.js';
import os from 'os';
import path from 'path';

// A throwaway HOME for the shim rows, so fullPathCommand's POSIX branch never
// touches the real ~/.node9.
let shimHome = '';
function freshShimHome(): string {
  shimHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-shim-'));
  return shimHome;
}

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

  it('emits an unquoted leading `node` on Windows (cmd quote-stripping)', () => {
    restoreProcess = stubProcess(
      'C:\\Program Files\\nodejs\\node.exe',
      'C:\\Users\\nadav\\AppData\\Roaming\\npm\\node_modules\\node9-ai\\node_modules\\@node9\\proxy\\dist\\cli.js'
    );
    // The #185 form quoted BOTH paths, which made the string start with a
    // quote and carry four of them. cmd preserves quotes only when there
    // are exactly two, so it stripped the outer pair and split on the space
    // in `Program Files`, tried to exec `C:/Program`, and exited 1. Codex
    // Desktop drops a failing hook silently: no enforcement, no audit row.
    // Dropping the absolute node path removes the leading quote and fixes
    // every shell form, while the still-quoted cli.js keeps #185's
    // space-safety under Git Bash.
    expect(fullPathCommand('check', 'win32')).toBe(
      'node ' +
        '"C:/Users/nadav/AppData/Roaming/npm/node_modules/node9-ai/node_modules/@node9/proxy/dist/cli.js" ' +
        'check'
    );
  });

  it('falls back to the PATH-resolved name for a Windows global binary', () => {
    // The bare-binary branch cannot be quoted (leading quote) and cannot be
    // left bare (a space in the path would split it), so on Windows it
    // resolves via PATH. This is the form verified end-to-end against Codex
    // Desktop on 2026-09-22.
    restoreProcess = stubProcess(
      'C:\\Program Files\\nodejs\\node.exe',
      'C:\\Users\\nadav\\AppData\\Roaming\\npm\\node9'
    );
    expect(fullPathCommand('check', 'win32')).toBe('node9 check');
  });

  it('never begins a Windows hook command with a quote (the cmd invariant)', () => {
    // One assertion standing for the whole class of regressions: whatever
    // shape this function grows on Windows, a leading quote reintroduces
    // the silent-failure bug for every user.
    for (const argv1 of [
      'C:\\Users\\Some User\\AppData\\Roaming\\npm\\node_modules\\node9-ai\\dist\\cli.js',
      'C:\\Users\\Some User\\AppData\\Roaming\\npm\\node9',
    ]) {
      restoreProcess();
      restoreProcess = stubProcess('C:\\Program Files\\nodejs\\node.exe', argv1);
      for (const sub of ['check', 'log', 'check --agent antigravity']) {
        expect(fullPathCommand(sub, 'win32').startsWith('"')).toBe(false);
      }
    }
  });

  it('leaves the POSIX form untouched (issue #185 regression)', () => {
    // #185 quoted both paths so a $HOME with a space survives Git Bash and
    // POSIX shells alike. Windows no longer takes this branch; POSIX still
    // must, and has no cmd quote-stripping rule to trip over.
    restoreProcess = stubProcess(
      '/usr/bin/node',
      '/home/u/.npm-global/lib/node_modules/node9-ai/dist/cli.js'
    );
    const home = freshShimHome();
    // The command in the agent's config is the shim's fixed path, quoted.
    // node + cli.js live INSIDE the shim, where changing them changes nothing
    // an agent has trusted.
    expect(fullPathCommand('check', 'linux', home)).toBe(
      `"${hookShimPath(home).replace(/\\/g, '/')}" check`
    );
    expect(fs.readFileSync(path.join(home, '.node9', 'bin', 'hook'), 'utf-8')).toBe(
      hookShimBody('/usr/bin/node', '/home/u/.npm-global/lib/node_modules/node9-ai/dist/cli.js')
    );
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('quotes a POSIX path with spaces (e.g. /Users/Some User/...)', () => {
    // macOS users with spaces in their full name end up with a $HOME like
    // "/Users/Some User". The old unquoted form would have broken them
    // too — covered by the same fix.
    restoreProcess = stubProcess(
      '/Users/Some User/.nvm/versions/node/v22.0.0/bin/node',
      '/Users/Some User/.npm-global/lib/node_modules/node9-ai/dist/cli.js'
    );
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9 shim space '));
    // The shim path itself is quoted, so a $HOME with a space still survives.
    expect(fullPathCommand('log', 'linux', home)).toBe(
      `"${hookShimPath(home).replace(/\\/g, '/')}" log`
    );
    // And the space-bearing node path is quoted INSIDE the shim.
    expect(fs.readFileSync(path.join(home, '.node9', 'bin', 'hook'), 'utf-8')).toContain(
      'node="/Users/Some User/.nvm/versions/node/v22.0.0/bin/node"\n[ -x "$node" ] || node=node\nexec "$node" "/Users/Some User/.npm-global/lib/node_modules/node9-ai/dist/cli.js" "$@"'
    );
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('does not rewrite the shim when its body is already current (trust-safe re-runs)', () => {
    restoreProcess = stubProcess('/usr/bin/node', '/opt/node9/dist/cli.js');
    const home = freshShimHome();
    expect(ensureHookShim(home, '/usr/bin/node', '/opt/node9/dist/cli.js')).toBe(true);
    const shim = hookShimPath(home);
    const before = fs.statSync(shim).mtimeMs;
    expect(ensureHookShim(home, '/usr/bin/node', '/opt/node9/dist/cli.js')).toBe(false);
    expect(fs.statSync(shim).mtimeMs).toBe(before);
    // A node upgrade changes only the body — the path agents trusted is intact.
    expect(ensureHookShim(home, '/usr/bin/node-v23', '/opt/node9/dist/cli.js')).toBe(true);
    expect(fs.readFileSync(shim, 'utf-8')).toContain('"/usr/bin/node-v23"');
    // POSIX only: Windows has no executable bit, and the shim is a POSIX-branch
    // artifact anyway. Asserting it there measured the host, not the code.
    if (process.platform !== 'win32') {
      expect(fs.statSync(shim).mode & 0o111).not.toBe(0);
    }
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('quotes the bare-binary global-install form (no .js suffix)', () => {
    // When the binary itself is a self-contained executable (npm link
    // or some global installs), we skip the `node ${cliScript}` prefix
    // but still need to quote the binary path for the same reason.
    restoreProcess = stubProcess(
      '/usr/local/bin/node', // ignored on this branch
      '/usr/local/bin/node9' // ends without .js
    );
    expect(fullPathCommand('check', 'linux')).toBe('"/usr/local/bin/node9" check');
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

  it('recognises the quoted bare-binary form (global install, post-#185)', () => {
    // Regression: fullPathCommand quotes the binary path for global installs
    // (`"/path/node9" check`), but isNode9Hook only matched the quoted cli.js
    // form — so freshly wired agy/copilot read back as "not wired" and setup
    // appended duplicate hooks on every re-run. The closing quote sits between
    // `node9` and the subcommand, which the old `node9 ` pattern missed.
    expect(
      isNode9Hook('"/home/u/.nvm/versions/node/v25.9.0/bin/node9" check --agent antigravity')
    ).toBe(true);
    expect(isNode9Hook('"/usr/local/bin/node9" log --agent copilot')).toBe(true);
    expect(isNode9Hook('"C:/Users/u/node9" check')).toBe(true);
  });

  it('still recognises the legacy unquoted form (backward compat)', () => {
    // Hooks already on disk in the old unquoted form must keep being
    // recognised as node9 hooks until the next self-heal rewrites them.
    expect(isNode9Hook('/usr/bin/node /path/cli.js check')).toBe(true);
    expect(isNode9Hook('/usr/local/bin/node9 check')).toBe(true); // unquoted bare
    expect(isNode9Hook('node9 check')).toBe(true);
    expect(isNode9Hook('node9 log')).toBe(true);
  });

  it('does not match unrelated commands', () => {
    expect(isNode9Hook('echo hi')).toBe(false);
    expect(isNode9Hook('echo node9 is cool')).toBe(false); // node9 not followed by check/log
    expect(isNode9Hook('mynode9 check')).toBe(false); // word-boundary
    expect(isNode9Hook('"/usr/bin/mynode9checker" check')).toBe(false); // substring guard
    expect(isNode9Hook(undefined)).toBe(false);
  });
});

describe('isLegacyHookFormat (#185 follow-up)', () => {
  it('flags any command containing a backslash', () => {
    // Pre-#185 unquoted Windows hook — the exact form reported in the bug.
    expect(
      isLegacyHookFormat('C:\\Program Files\\nodejs\\node.exe C:\\Users\\u\\...\\cli.js check')
    ).toBe(true);
    // Also a quoted-but-still-backslash form (some hand-edited configs).
    expect(isLegacyHookFormat('"C:\\path\\node.exe" "C:\\path\\cli.js" check')).toBe(true);
  });

  it('returns false for the new quoted forward-slash form (idempotence)', () => {
    // Once self-heal rewrites a hook, running init again must not retrigger
    // the rewrite or we'd churn settings.json on every invocation.
    expect(
      isLegacyHookFormat('"C:/Program Files/nodejs/node.exe" "C:/Users/u/.../cli.js" check')
    ).toBe(false);
  });

  it('returns false for the legacy unquoted POSIX form (no churn on working hooks)', () => {
    // POSIX users with pre-#185 hooks are still working — no backslashes
    // means no Git Bash break. We deliberately don't rewrite cosmetic
    // differences; only actual breakage.
    expect(isLegacyHookFormat('/usr/bin/node /lib/node_modules/.../cli.js check')).toBe(false);
    expect(isLegacyHookFormat('/usr/local/bin/node9 check')).toBe(false);
  });

  it('returns false for the bare "node9 check" form and empty input', () => {
    expect(isLegacyHookFormat('node9 check')).toBe(false);
    expect(isLegacyHookFormat('')).toBe(false);
  });
});

describe('needsRewrite (#185 follow-up)', () => {
  // needsRewrite ORs the two detection helpers. Spot-check that both
  // branches feed into the result; exhaustive coverage of the
  // underlying conditions lives in the isStaleHookCommand /
  // isLegacyHookFormat blocks above.
  it('returns true when the path is stale', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    expect(needsRewrite('"/missing/node" "/missing/cli.js" check')).toBe(true);
  });

  it('returns true when the shape is legacy (backslashes)', () => {
    // existsSync left at the test-file default; even if it returns true
    // for every path, the backslash branch should still fire.
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    expect(needsRewrite('C:\\path\\node C:\\path\\cli.js check')).toBe(true);
  });

  it('returns false for a well-formed hook whose paths exist', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    // "Well-formed" on POSIX now means the shim form. The two-quoted-path form
    // this row used to hold up as correct is exactly the one that expires
    // Codex trust on every nvm switch, and it is migrated on purpose — see
    // the isChurnProneHookForm block.
    // A global bin that is not JavaScript (pnpm's shell wrapper) stays as it is.
    // realpath is pinned so the row does not depend on what this host has
    // installed at /usr/local/bin.
    vi.spyOn(fs, 'realpathSync').mockReturnValue('/usr/local/bin/node9');
    expect(needsRewrite('"/home/u/.node9/bin/hook" check', 'linux')).toBe(false);
    expect(needsRewrite('"/usr/local/bin/node9" check', 'linux')).toBe(false);
  });
});

describe('isWindowsQuoteBrokenHook (cmd quote-stripping self-heal)', () => {
  // The shape every Windows install carries after running #185-era code.
  const BROKEN =
    '"C:/Program Files/nodejs/node.exe" "C:/Users/u/AppData/Roaming/npm/.../cli.js" check';

  it('flags the #185-era Windows form even when every path still exists', () => {
    // This is the case the other two predicates miss, and the reason those
    // users stayed silently unenforced across upgrades: the files are all
    // present, and the forward-slash normalisation left no backslashes.
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    expect(isStaleHookCommand(BROKEN)).toBe(false);
    expect(isLegacyHookFormat(BROKEN)).toBe(false);
    expect(isWindowsQuoteBrokenHook(BROKEN, 'win32')).toBe(true);
    expect(needsRewrite(BROKEN, 'win32')).toBe(true);
  });

  it('leaves POSIX alone — a leading quote is correct there', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    const posix = '"/usr/bin/node" "/usr/lib/node_modules/node9-ai/dist/cli.js" check';
    expect(isWindowsQuoteBrokenHook(posix, 'linux')).toBe(false);
    // needsRewrite is still true for this string on linux — but via
    // isChurnProneHookForm (migration to the shim), not via the Windows
    // predicate. The two reasons are kept distinct so a failure names its cause.
    expect(isChurnProneHookForm(posix, 'linux')).toBe(true);
    expect(needsRewrite(posix, 'linux')).toBe(true);
    // Same string, Windows: still broken, because the rule is about cmd's
    // parser and not about the path it happens to contain.
    expect(isWindowsQuoteBrokenHook(posix, 'win32')).toBe(true);
  });

  it('does not flag the shapes fullPathCommand now emits on Windows', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    for (const cmd of ['node "C:/Users/u/dist/cli.js" check', 'node9 log']) {
      expect(isWindowsQuoteBrokenHook(cmd, 'win32')).toBe(false);
      expect(needsRewrite(cmd, 'win32')).toBe(false);
    }
  });

  it('handles leading whitespace and empty input', () => {
    expect(isWindowsQuoteBrokenHook('   "C:/x/node.exe" "C:/y/cli.js" check', 'win32')).toBe(true);
    expect(isWindowsQuoteBrokenHook('', 'win32')).toBe(false);
  });
});

describe('isNode9Hook recognises the post-fix Windows shapes', () => {
  // Wiring pin, not a helper test. If isNode9Hook stops matching what
  // fullPathCommand emits, setup reads a freshly wired install as "not
  // wired" and appends duplicate hooks on every re-run.
  it('matches the unquoted-node Windows form', () => {
    expect(isNode9Hook('node "C:/Users/u/dist/cli.js" check')).toBe(true);
    expect(isNode9Hook('node "C:/Users/u/dist/cli.js" log')).toBe(true);
    expect(isNode9Hook('node9 check --agent antigravity')).toBe(true);
  });
});

describe('Codex PreToolUse — a foreign hook must not be mistaken for coverage', () => {
  // Dogfound on Windows 2026-09-22: a leftover probe script owned the ^Bash$
  // matcher. `node9 agents remove codex` left it (correctly — it is not ours),
  // and `add` then skipped the matcher because an ENTRY existed, so Bash stayed
  // ungated while setup printed "hooks added" and doctor read the file as
  // wired. The predicate has to be "is node9 present", not "does a matcher
  // entry exist" — the same shape as the UserPromptSubmit/PostToolUse checks
  // a few lines below it in setup.ts.
  it('does not treat a non-node9 command as a node9 hook', () => {
    expect(isNode9Hook('C:\\Users\\u\\.codex\\probes\\probe-flat.cmd')).toBe(false);
    expect(isNode9Hook('some-other-tool --check')).toBe(false);
    expect(isNode9Hook(undefined)).toBe(false);
  });
});

describe('isNode9Hook recognises the shim form', () => {
  // Wiring pin. If this stops matching what fullPathCommand emits on POSIX,
  // setup reads a freshly wired install as "not wired" and appends duplicate
  // hooks on every re-run.
  it('matches the quoted shim path with check, log and flags', () => {
    expect(isNode9Hook('"/home/u/.node9/bin/hook" check')).toBe(true);
    expect(isNode9Hook('"/home/u/.node9/bin/hook" log')).toBe(true);
    expect(isNode9Hook('"/Users/Some User/.node9/bin/hook" check --agent antigravity')).toBe(true);
  });
  it('does not match a look-alike outside ~/.node9/bin', () => {
    expect(isNode9Hook('"/home/u/bin/hook" check')).toBe(false);
  });
  it('the HUD statusLine matcher still owns the shim form (never clobbers a user statusLine)', () => {
    expect(isNode9StatusLine('"/home/u/.node9/bin/hook" hud')).toBe(true);
    expect(isNode9StatusLine('ccstatusline')).toBe(false);
  });
});

describe('isChurnProneHookForm — migrating the pre-shim POSIX form', () => {
  const OLD_POSIX =
    '"/home/u/.nvm/versions/node/v22.0.0/bin/node" "/home/u/.npm-global/lib/node_modules/node9-ai/dist/cli.js" check';

  it('flags the two-quoted-path POSIX form so self-heal moves it onto the shim', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true); // paths exist — not "stale"
    expect(isStaleHookCommand(OLD_POSIX)).toBe(false);
    expect(isChurnProneHookForm(OLD_POSIX, 'linux')).toBe(true);
    expect(needsRewrite(OLD_POSIX, 'linux')).toBe(true);
  });

  it('never fires on Windows — that shape is the D1 bug there and handled by its own predicate', () => {
    const win = '"C:/Program Files/nodejs/node.exe" "C:/Users/u/dist/cli.js" check';
    expect(isChurnProneHookForm(win, 'win32')).toBe(false);
    // (needsRewrite still says true on win32, via isWindowsQuoteBrokenHook.)
  });

  it('does not flag the shim form, the bare form, or the global-binary form', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    // Not JavaScript behind the bin (see isPathNodeHookForm for the JS case).
    vi.spyOn(fs, 'realpathSync').mockReturnValue('/usr/local/bin/node9');
    for (const cmd of [
      '"/home/u/.node9/bin/hook" check',
      'node9 check',
      '"/usr/local/bin/node9" check',
    ]) {
      expect(isChurnProneHookForm(cmd, 'linux'), cmd).toBe(false);
      expect(needsRewrite(cmd, 'linux'), cmd).toBe(false);
    }
  });
});

// The global-install hook ran through `#!/usr/bin/env node`, so the AGENT's PATH
// picked the Node. A desktop agent whose PATH starts with an older system Node
// (18 here) crashed every hook on load (ERR_REQUIRE_ESM from commander 15) and
// the agent ran each tool call unchecked. The node that runs `node9 init` /
// `agents add` is one that runs node9, so the hook now pins it in the shim.
describe.skipIf(process.platform === 'win32')(
  'global install: the hook pins the Node that wired it',
  () => {
    let root = '';
    let restoreProcess: () => void = () => {};
    let binLink = '';
    let shWrapper = '';

    beforeEach(() => {
      // Earlier blocks leave fs spies in place; these rows need the real fs.
      vi.restoreAllMocks();
      vi.stubEnv('NODE9_TESTING', '');
      root = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-global-'));
      // npm / bun global layout: <prefix>/bin/node9 -> ../lib/node_modules/node9-ai/dist/cli.js
      const cli = path.join(root, 'lib', 'node_modules', 'node9-ai', 'dist', 'cli.js');
      fs.mkdirSync(path.dirname(cli), { recursive: true });
      fs.writeFileSync(cli, '#!/usr/bin/env node\n');
      fs.mkdirSync(path.join(root, 'bin'));
      binLink = path.join(root, 'bin', 'node9');
      fs.symlinkSync(cli, binLink);
      // pnpm-style global bin: a shell script, not JavaScript. node cannot run it.
      shWrapper = path.join(root, 'bin', 'node9-sh');
      fs.writeFileSync(shWrapper, '#!/bin/sh\nexec node "$basedir/cli.js" "$@"\n', { mode: 0o755 });
    });

    afterEach(() => {
      restoreProcess();
      vi.unstubAllEnvs();
      vi.restoreAllMocks();
      fs.rmSync(root, { recursive: true, force: true });
    });

    it('writes the shim with the running node for a bin that links to cli.js', () => {
      restoreProcess = stubProcess('/opt/node-v25/bin/node', binLink);
      const home = path.join(root, 'home');
      expect(fullPathCommand('check', 'linux', home)).toBe(`"${hookShimPath(home)}" check`);
      expect(fs.readFileSync(hookShimPath(home), 'utf-8')).toBe(
        hookShimBody('/opt/node-v25/bin/node', binLink)
      );
    });

    it('keeps the quoted bin for a wrapper that is not JavaScript (pnpm)', () => {
      restoreProcess = stubProcess('/opt/node-v25/bin/node', shWrapper);
      const home = path.join(root, 'home');
      expect(fullPathCommand('check', 'linux', home)).toBe(`"${shWrapper}" check`);
      expect(fs.existsSync(hookShimPath(home))).toBe(false);
    });

    it('pins node, never another runtime that happens to run setup', () => {
      expect(pinsNode('/opt/node-v25/bin/node', binLink)).toBe(true);
      expect(pinsNode('/usr/bin/nodejs', binLink)).toBe(true);
      expect(pinsNode('/home/u/.bun/bin/bun', binLink)).toBe(false);
      expect(pinsNode('/opt/node-v25/bin/node', shWrapper)).toBe(false);
      // A .js path was always run with the current binary; that is unchanged.
      expect(pinsNode('/home/u/.bun/bin/bun', '/opt/node9/dist/cli.js')).toBe(true);
      restoreProcess = stubProcess('/home/u/.bun/bin/bun', binLink);
      expect(fullPathCommand('check', 'linux', path.join(root, 'home'))).toBe(`"${binLink}" check`);
    });

    it('pins the node link beside the bin, which survives a package-manager upgrade', () => {
      // Homebrew: <prefix>/bin/node -> Cellar/node/<ver>/bin/node, and
      // process.execPath is the Cellar path that `brew upgrade` deletes.
      const realNode = fs.realpathSync(process.execPath);
      fs.symlinkSync(realNode, path.join(root, 'bin', 'node'));
      expect(pinnedNode(realNode, binLink)).toBe(path.join(root, 'bin', 'node'));
      // No node beside the bin (a checkout, a custom prefix): execPath itself.
      expect(pinnedNode(realNode, path.join(root, 'lib', 'x', 'cli.js'))).toBe(realNode);
      // A different node beside the bin is not the one that ran setup.
      expect(pinnedNode('/opt/other/node', binLink)).toBe('/opt/other/node');
    });

    it('the shim falls back to the PATH node when the pinned one is gone', () => {
      const home = path.join(root, 'home');
      const cli = path.join(root, 'print-version.js');
      fs.writeFileSync(cli, 'console.log("ran", process.argv.slice(2).join(" "));\n');
      ensureHookShim(home, path.join(root, 'removed', 'node'), cli);
      const r = spawnSync('sh', [hookShimPath(home), 'check', '--x'], {
        encoding: 'utf-8',
        env: { PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin` },
      });
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(0);
      expect(r.stdout.trim()).toBe('ran check --x');
    });

    it('the shim runs the pinned node, not the first node on PATH', () => {
      const home = path.join(root, 'home');
      const cli = path.join(root, 'print-exec.js');
      fs.writeFileSync(cli, 'console.log(process.execPath);\n');
      // A decoy `node` first on PATH that would fail if it ran.
      const decoyDir = path.join(root, 'decoy');
      fs.mkdirSync(decoyDir);
      fs.writeFileSync(path.join(decoyDir, 'node'), '#!/bin/sh\nexit 42\n', { mode: 0o755 });
      ensureHookShim(home, process.execPath, cli);
      const r = spawnSync('sh', [hookShimPath(home)], {
        encoding: 'utf-8',
        env: { PATH: `${decoyDir}:/usr/bin:/bin` },
      });
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(0);
      expect(fs.realpathSync(r.stdout.trim())).toBe(fs.realpathSync(process.execPath));
    });

    it('keeps what the user added after the subcommand when it rewrites', () => {
      restoreProcess = stubProcess('/opt/node-v25/bin/node', binLink);
      vi.stubEnv('HOME', path.join(root, 'home'));
      const home = path.join(root, 'home');
      const shim = hookShimPath(home);
      const spy = vi.spyOn(os, 'homedir').mockReturnValue(home);
      expect(rewrittenHookCommand(`"${binLink}" check --no-ask`, 'check')).toBe(
        `"${shim}" check --no-ask`
      );
      expect(rewrittenHookCommand(`${binLink} log --agent pi`, 'log')).toBe(
        `"${shim}" log --agent pi`
      );
      // Nothing node9 recognises: the fallback subcommand.
      expect(rewrittenHookCommand('something else', 'check')).toBe(`"${shim}" check`);
      spy.mockRestore();
    });

    it('does not flag the PATH-node form when setup runs under bun (no churn)', () => {
      expect(isPathNodeHookForm(`"${binLink}" check`, 'linux', '/home/u/.bun/bin/bun')).toBe(false);
    });

    it('Codex keeps the bin form: its hooks are trusted by their exact text', () => {
      restoreProcess = stubProcess('/opt/node-v25/bin/node', binLink);
      const home = path.join(root, 'home');
      expect(fullPathCommand('check', 'linux', home, { pinGlobalBin: false })).toBe(
        `"${binLink}" check`
      );
      // A cli.js path still goes through the shim, as before.
      restoreProcess();
      restoreProcess = stubProcess('/opt/node-v25/bin/node', '/opt/node9/dist/cli.js');
      expect(fullPathCommand('check', 'linux', home, { pinGlobalBin: false })).toBe(
        `"${hookShimPath(home)}" check`
      );
    });

    it('reads the older shim body (exec "<node>" "<cli>") too', () => {
      const home = path.join(root, 'home');
      const shim = hookShimPath(home);
      fs.mkdirSync(path.dirname(shim), { recursive: true });
      fs.writeFileSync(
        shim,
        `#!/bin/sh\nexec "${path.join(root, 'gone', 'node')}" "${binLink}" "$@"\n`
      );
      expect(isStaleHookCommand(`"${shim}" check`)).toBe(true);
      fs.writeFileSync(shim, `#!/bin/sh\nexec "${process.execPath}" "${binLink}" "$@"\n`);
      expect(isStaleHookCommand(`"${shim}" check`)).toBe(false);
    });

    it('migrates the PATH-node global form on the next setup run', () => {
      for (const cmd of [
        `"${binLink}" check`,
        `"${binLink}" log`,
        `"${binLink}" hud`,
        // The unquoted pre-#185 form, still in configs that never re-ran setup.
        `${binLink} check`,
        `${binLink} log`,
      ]) {
        expect(isPathNodeHookForm(cmd, 'linux'), cmd).toBe(true);
        expect(needsRewrite(cmd, 'linux'), cmd).toBe(true);
      }
    });

    it('does not migrate a wrapper, the shim, the two-path form, or Windows', () => {
      const home = path.join(root, 'home');
      ensureHookShim(home, process.execPath, binLink);
      for (const cmd of [
        `"${shWrapper}" check`,
        `"${hookShimPath(home)}" check`,
        `"${process.execPath}" "${binLink}" check`,
        'node9 check',
      ]) {
        expect(isPathNodeHookForm(cmd, 'linux'), cmd).toBe(false);
      }
      expect(isPathNodeHookForm(`"${binLink}" check`, 'win32')).toBe(false);
    });

    it('reads a shim whose node is gone as stale, so setup rewrites it', () => {
      const home = path.join(root, 'home');
      ensureHookShim(home, path.join(root, 'removed-nvm', 'node'), binLink);
      const cmd = `"${hookShimPath(home)}" check`;
      expect(isStaleHookCommand(cmd)).toBe(true);
      expect(needsRewrite(cmd, 'linux')).toBe(true);
      // A live shim stays as it is: no churn on a working hook.
      ensureHookShim(home, process.execPath, binLink);
      expect(isStaleHookCommand(cmd)).toBe(false);
      expect(needsRewrite(cmd, 'linux')).toBe(false);
    });
  }
);

// MCP entries get a file of their own beside the hook shim: ~/.node9/bin/node9.
// The same script, so node9's own server and every wrapped server start on the
// Node that ran setup. Written as the bare `node9`, they started on the Node
// the agent's PATH held, and under an old one neither came up (2026-11-21).
describe.skipIf(process.platform === 'win32')('the launcher beside the hook shim', () => {
  let home = '';
  let restoreProcess: () => void = () => {};
  const NODE_PATH = '/opt/node-v25/bin/node';
  const CLI_PATH = '/opt/node9/dist/cli.js';

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubEnv('NODE9_TESTING', '');
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-launcher-'));
  });

  afterEach(() => {
    restoreProcess();
    restoreProcess = () => {};
    vi.unstubAllEnvs();
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('ensureShims writes both files, executable, and nothing on a second call', () => {
    expect(ensureShims(home, NODE_PATH, CLI_PATH)).toBe(true);
    const hook = shimPath('hook', home);
    const launcher = shimPath('node9', home);
    expect(hook).toBe(path.join(home, '.node9', 'bin', 'hook'));
    expect(launcher).toBe(path.join(home, '.node9', 'bin', 'node9'));
    expect(fs.statSync(hook).mode & 0o777).toBe(0o755);
    expect(fs.statSync(launcher).mode & 0o777).toBe(0o755);

    const before = [fs.statSync(hook).mtimeMs, fs.statSync(launcher).mtimeMs];
    expect(ensureShims(home, NODE_PATH, CLI_PATH)).toBe(false);
    expect([fs.statSync(hook).mtimeMs, fs.statSync(launcher).mtimeMs]).toEqual(before);

    // A Node upgrade rewrites both bodies; the paths agents hold do not move.
    expect(ensureShims(home, '/opt/node-v26/bin/node', CLI_PATH)).toBe(true);
    expect(fs.readFileSync(hook, 'utf-8')).toContain('node="/opt/node-v26/bin/node"');
    expect(fs.readFileSync(launcher, 'utf-8')).toContain('node="/opt/node-v26/bin/node"');
  });

  it('writes the missing one when only the hook shim is there (an upgrade)', () => {
    ensureHookShim(home, NODE_PATH, CLI_PATH);
    const hookMtime = fs.statSync(shimPath('hook', home)).mtimeMs;
    expect(fs.existsSync(shimPath('node9', home))).toBe(false);
    expect(ensureShims(home, NODE_PATH, CLI_PATH)).toBe(true);
    expect(fs.existsSync(shimPath('node9', home))).toBe(true);
    expect(fs.statSync(shimPath('hook', home)).mtimeMs).toBe(hookMtime);
  });

  // Every machine holds this file. A changed byte rewrites it on each of them.
  it('keeps the hook shim body byte for byte', () => {
    const expected =
      '#!/bin/sh\n' +
      '# node9 hook shim \u2014 written by `node9 init` / `node9 agents add`. Do not edit.\n' +
      '# Agents call this fixed path; node9 rewrites the lines below on upgrade so\n' +
      '# the hook command they trusted never changes (Codex keys trust to it).\n' +
      "# The node that ran setup runs node9, whatever the agent's PATH holds. If an\n" +
      '# upgrade removed it, the first node on PATH does, as a global install would.\n' +
      'node="/opt/node-v25/bin/node"\n' +
      '[ -x "$node" ] || node=node\n' +
      'exec "$node" "/opt/node9/dist/cli.js" "$@"\n';
    expect(shimBody('hook', NODE_PATH, CLI_PATH)).toBe(expected);
    expect(hookShimBody(NODE_PATH, CLI_PATH)).toBe(expected);
  });

  it('gives the launcher the same three lines that run node9', () => {
    const lines = (body: string) => body.split('\n').filter((l) => !l.startsWith('# '));
    expect(lines(shimBody('node9', NODE_PATH, CLI_PATH))).toEqual(
      lines(shimBody('hook', NODE_PATH, CLI_PATH))
    );
    expect(shimBody('node9', NODE_PATH, CLI_PATH)).toContain('# node9 launcher');
  });

  it('fullPathCommand writes the launcher with the hook shim', () => {
    restoreProcess = stubProcess(NODE_PATH, CLI_PATH);
    fullPathCommand('check', 'linux', home);
    expect(fs.readFileSync(shimPath('node9', home), 'utf-8')).toBe(
      shimBody('node9', NODE_PATH, CLI_PATH)
    );
  });

  it('isShimTargetStale reads the launcher as it reads the hook shim', () => {
    const cli = path.join(home, 'cli.js');
    fs.writeFileSync(cli, '');
    ensureShims(home, process.execPath, cli);
    expect(isShimTargetStale(shimPath('node9', home))).toBe(false);
    ensureShims(home, path.join(home, 'gone', 'node'), cli);
    expect(isShimTargetStale(shimPath('node9', home))).toBe(true);
    ensureShims(home, process.execPath, path.join(home, 'gone.js'));
    expect(isShimTargetStale(shimPath('node9', home))).toBe(true);
    // No file is not stale: there is nothing to rewrite.
    expect(isShimTargetStale(path.join(home, 'absent'))).toBe(false);
  });

  it('mcpLauncherArgv is the launcher, written by the call', () => {
    restoreProcess = stubProcess(NODE_PATH, CLI_PATH);
    expect(mcpLauncherArgv(home)).toEqual([shimPath('node9', home)]);
    expect(fs.readFileSync(shimPath('node9', home), 'utf-8')).toBe(
      shimBody('node9', NODE_PATH, CLI_PATH)
    );
  });

  it('mcpLauncherArgv keeps a bin that is not JavaScript, and the bare name in tests', () => {
    // pnpm writes a shell wrapper: node cannot run it, so it is the command itself.
    const wrapper = path.join(home, 'pnpm', 'node9');
    fs.mkdirSync(path.dirname(wrapper), { recursive: true });
    fs.writeFileSync(wrapper, '#!/bin/sh\nexec node "$basedir/cli.js" "$@"\n', { mode: 0o755 });
    restoreProcess = stubProcess(NODE_PATH, wrapper);
    expect(mcpLauncherArgv(home)).toEqual([wrapper]);
    expect(fs.existsSync(shimPath('node9', home))).toBe(false);

    vi.stubEnv('NODE9_TESTING', '1');
    expect(mcpLauncherArgv(home)).toEqual(['node9']);
  });

  // Setup skips what it reads as node9's and wraps the rest. An entry node9
  // wrote but does not read back would be wrapped on the next run.
  it('mcpLauncherArgv never returns a command node9 would not read back as its own', () => {
    const odd = path.join(home, 'bin', 'n9-wrapper');
    fs.mkdirSync(path.dirname(odd), { recursive: true });
    fs.writeFileSync(odd, '#!/bin/sh\nexec node "$basedir/cli.js" "$@"\n', { mode: 0o755 });
    restoreProcess = stubProcess(NODE_PATH, odd);
    expect(mcpLauncherArgv(home)).toEqual(['node9']);
  });

  it('readyLauncherArgv reads the launcher and never writes it', () => {
    expect(readyLauncherArgv(home)).toEqual(['node9']);
    expect(fs.existsSync(path.join(home, '.node9'))).toBe(false);

    const cli = path.join(home, 'cli.js');
    fs.writeFileSync(cli, '');
    ensureShims(home, process.execPath, cli);
    expect(readyLauncherArgv(home)).toEqual([shimPath('node9', home)]);

    // Not executable: an agent could not start it either.
    fs.chmodSync(shimPath('node9', home), 0o644);
    expect(readyLauncherArgv(home)).toEqual(['node9']);
    fs.chmodSync(shimPath('node9', home), 0o755);

    // Its node9 is gone: the bare name may still find an install on PATH.
    ensureShims(home, process.execPath, path.join(home, 'gone.js'));
    expect(readyLauncherArgv(home)).toEqual(['node9']);
  });
});
