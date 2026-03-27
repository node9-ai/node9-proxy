/**
 * Regression guard for GitHub issue #41 — ENOENT on Windows when spawning node9 subprocess.
 *
 * On Windows, spawn('node9', ...) fails because npm installs a .cmd shim, not a bare
 * executable. Node.js child_process.spawn without { shell: true } cannot resolve .cmd
 * wrappers. The fix is to use process.execPath + process.argv[1] instead, which is the
 * pattern already used in src/tui/tail.ts.
 *
 * These tests read cli.ts and cli/daemon-starter.ts to assert the unsafe pattern is absent
 * at all call sites: autoStartDaemonAndWait(), daemon --openui, daemon --background, node9 watch.
 */
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

const CLI_SRC = path.resolve(__dirname, '../cli.ts');
const DAEMON_STARTER_SRC = path.resolve(__dirname, '../cli/daemon-starter.ts');
const src = fs.readFileSync(CLI_SRC, 'utf-8');
const daemonStarterSrc = fs.readFileSync(DAEMON_STARTER_SRC, 'utf-8');

const SAFE_SPAWN_RE = /spawn\(process\.execPath,\s*\[process\.argv\[1\],\s*'daemon'\]/g;

describe('spawn Windows compatibility (#41)', () => {
  it('cli.ts does not spawn node9 by name (would fail on Windows — no .cmd resolution)', () => {
    // Any occurrence of spawn('node9' or spawn("node9" is the bug.
    expect(src).not.toMatch(/spawn\(['"]node9['"]/);
    expect(daemonStarterSrc).not.toMatch(/spawn\(['"]node9['"]/);
  });

  it('spawns daemon using process.execPath at all call sites', () => {
    // All daemon-spawning sites must use process.execPath as the first argument.
    // autoStartDaemonAndWait is in cli/daemon-starter.ts (1 call site);
    // daemon --openui, daemon --background, node9 watch are in cli.ts (3 call sites).
    const cliCalls = (src.match(SAFE_SPAWN_RE) ?? []).length;
    const starterCalls = (daemonStarterSrc.match(SAFE_SPAWN_RE) ?? []).length;
    expect(cliCalls + starterCalls).toBe(4);
  });
});
