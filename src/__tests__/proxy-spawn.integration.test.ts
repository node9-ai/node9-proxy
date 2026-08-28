import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

// `node9 <anything-not-a-subcommand>` is treated as a shell command to govern
// and wrap (cli.ts catch-all → runProxy). On Windows that path spawned a
// hardcoded /bin/bash and died with an unhandled 'error' event — a raw stack
// trace, exit code 1, no explanation (founder QA 2026-08-28).
//
// Runs on every platform; the Windows CI runner is what proves the fix. The
// POSIX assertions still guard the crash-handling contract everywhere.
describe('node9 <command> — proxy spawn (integration)', () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-proxy-spawn-'));

  function run(args: string[], timeout = 20000) {
    return spawnSync(process.execPath, [CLI, ...args], {
      env: {
        ...process.env,
        HOME: tmpHome,
        USERPROFILE: tmpHome,
        NODE9_TESTING: '1',
        NODE9_NO_AUTO_DAEMON: '1',
      },
      encoding: 'utf-8',
      timeout,
    });
  }

  it('runs an approved command through the platform shell', () => {
    // `echo` exists as a shell builtin on both cmd.exe and bash, so this
    // exercises the shell fallback path on either platform.
    const r = run(['echo', 'node9-spawn-ok']);
    expect(r.error).toBeUndefined();
    expect(`${r.stdout}${r.stderr}`).toContain('node9-spawn-ok');
  });

  it('never leaks a POSIX shell path or an unhandled error event', () => {
    const r = run(['echo', 'hello']);
    const out = `${r.stdout}${r.stderr}`;
    expect(out).not.toContain('spawn /bin/bash ENOENT');
    expect(out).not.toContain("Unhandled 'error' event");
    expect(out).not.toMatch(/at ChildProcess\._handle\.onexit/);
  });

  it('spawns a WORKING shell for a command that is not a binary', () => {
    // The load-bearing case: `which`/`where` fails for this name, so the code
    // takes the shell fallback — the branch that hardcoded /bin/bash. The
    // SHELL must be the one that reports the missing command, which proves it
    // launched. If the shell path itself were wrong, our own spawn-error
    // handler would answer instead, so asserting its ABSENCE is what
    // distinguishes a working shell from a missing one.
    const r = run(['n9-definitely-not-a-real-binary-xyz']);
    expect(r.error).toBeUndefined();
    const out = `${r.stdout}${r.stderr}`;
    expect(out).not.toContain('Node9 could not run');
    // …and the shell said its piece.
    expect(out).toMatch(/not found|not recognized/i);
  });

  it('a broken spawn is reported cleanly, never as Node internals', () => {
    const r = run(['n9-definitely-not-a-real-binary-xyz']);
    const out = `${r.stdout}${r.stderr}`;
    expect(out).not.toContain("Unhandled 'error' event");
    expect(out).not.toMatch(/node:internal\/child_process/);
  });
});
