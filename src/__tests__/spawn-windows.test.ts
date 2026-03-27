/**
 * Regression guard for GitHub issue #41 — ENOENT on Windows when spawning node9 subprocess.
 *
 * On Windows, spawn('node9', ...) fails because npm installs a .cmd shim, not a bare
 * executable. Node.js child_process.spawn without { shell: true } cannot resolve .cmd
 * wrappers. The fix is to use process.execPath + process.argv[1] instead, which is the
 * pattern already used in src/tui/tail.ts.
 *
 * Call sites (all must use process.execPath):
 *   cli/daemon-starter.ts  — autoStartDaemonAndWait()             (1)
 *   cli/commands/daemon-cmd.ts — daemon --openui, --background    (2)
 *   cli/commands/watch.ts  — watch mode daemon start              (1)
 */
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

const COMMANDS_DIR = path.resolve(__dirname, '../cli');
const sources = [
  fs.readFileSync(path.join(COMMANDS_DIR, 'daemon-starter.ts'), 'utf-8'),
  fs.readFileSync(path.join(COMMANDS_DIR, 'commands/daemon-cmd.ts'), 'utf-8'),
  fs.readFileSync(path.join(COMMANDS_DIR, 'commands/watch.ts'), 'utf-8'),
];

const SAFE_SPAWN_RE = /spawn\(process\.execPath,\s*\[process\.argv\[1\],\s*'daemon'\]/g;
const UNSAFE_SPAWN_RE = /spawn\(['"]node9['"]/;

describe('spawn Windows compatibility (#41)', () => {
  it('no file spawns node9 by name (would fail on Windows — no .cmd resolution)', () => {
    for (const src of sources) {
      expect(src).not.toMatch(UNSAFE_SPAWN_RE);
    }
  });

  it('spawns daemon using process.execPath at all 4 call sites', () => {
    // autoStartDaemonAndWait (1) + daemon --openui (1) + daemon --background (1) + watch (1)
    const total = sources.reduce((sum, src) => sum + (src.match(SAFE_SPAWN_RE) ?? []).length, 0);
    expect(total).toBe(4);
  });
});
