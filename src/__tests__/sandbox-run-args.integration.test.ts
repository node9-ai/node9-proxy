/**
 * Integration test: `node9 sandbox run` must pass `-- <flags>` through to the
 * agent (e.g. --resume, --dangerously-skip-permissions). Regression for a bug
 * where the single-positional `run [agent]` rejected extra args with "too many
 * arguments". Spawns the built CLI in an empty dir so it fails for a DIFFERENT
 * reason (no sandbox config) — proving arg parsing accepted the passthrough.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

describe('node9 sandbox run — argument passthrough', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI not found at ${CLI} — run npm run build`).toBe(true);
  });

  it('accepts `-- <flags>` without "too many arguments"', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-sbx-args-'));
    const r = spawnSync(
      process.execPath,
      [CLI, 'sandbox', 'run', 'claude', '--', '--resume', '--dangerously-skip-permissions'],
      {
        cwd: dir,
        encoding: 'utf-8',
        timeout: 20000,
        env: { ...process.env, NODE9_NO_AUTO_DAEMON: '1' },
      }
    );
    fs.rmSync(dir, { recursive: true, force: true });
    expect(r.error).toBeUndefined();
    const out = (r.stdout ?? '') + (r.stderr ?? '');
    // The bug surfaced as a commander parse error; it must NOT appear.
    expect(out).not.toContain('too many arguments');
    // Instead it fails because the empty dir has no recipe — i.e. parsing passed.
    expect(out).toMatch(/not found|sandbox new/i);
  });
});
