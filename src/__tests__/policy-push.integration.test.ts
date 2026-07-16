// Integration: `node9 policy push` (the config-mirror CLI). Spawns dist/cli.js —
// requires a build. Verifies the no-credentials path exits gracefully (the
// subprocess-command coverage CLAUDE.md requires).
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

describe('node9 policy push (integration)', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
  });

  it('exits non-zero with a graceful message when no API key is configured', () => {
    // Empty HOME → no credentials.json; ensure NODE9_API_KEY is unset.
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-push-'));
    const env: Record<string, string> = {
      ...process.env,
      HOME: home,
      // os.homedir() reads USERPROFILE on Windows, not HOME — set both so the
      // spawned CLI resolves ~/.node9 to the temp dir on every OS.
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
    };
    delete env.NODE9_API_KEY;

    const r = spawnSync(process.execPath, [CLI, 'policy', 'push'], {
      encoding: 'utf-8',
      env,
    });

    expect(r.error).toBeUndefined();
    expect(r.status).not.toBe(0);
    expect(`${r.stdout}${r.stderr}`).toMatch(/No API key configured/);
  });
});
