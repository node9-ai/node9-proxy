/**
 * Regression guard for GitHub issue #41 — ENOENT on Windows when spawning node9 subprocess.
 *
 * On Windows, spawn('node9', ...) fails because npm installs a .cmd shim, not a bare
 * executable. Node.js child_process.spawn without { shell: true } cannot resolve .cmd
 * wrappers. The fix is to use process.execPath + process.argv[1] instead, which is the
 * pattern already used in src/tui/tail.ts.
 *
 * These tests read the cli.ts source to assert the unsafe pattern is absent at all three
 * call sites: autoStartDaemonAndWait(), daemon --openui, and daemon --background.
 */
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

const CLI_SRC = path.resolve(__dirname, '../cli.ts');
const src = fs.readFileSync(CLI_SRC, 'utf-8');

describe('spawn Windows compatibility (#41)', () => {
  it('cli.ts does not spawn node9 by name (would fail on Windows — no .cmd resolution)', () => {
    // Any occurrence of spawn('node9' or spawn("node9" is the bug.
    expect(src).not.toMatch(/spawn\(['"]node9['"]/);
  });

  it('cli.ts spawns daemon using process.execPath', () => {
    // All daemon-spawning sites must use process.execPath as the first argument.
    const spawnCalls = src.match(/spawn\(process\.execPath,\s*\[process\.argv\[1\],\s*'daemon'\]/g);
    // Three call sites: autoStartDaemonAndWait, daemon --openui, daemon --background
    expect(spawnCalls).toHaveLength(3);
  });
});
