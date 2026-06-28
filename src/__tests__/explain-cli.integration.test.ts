// Integration: the rendered `node9 explain` output reflects the real engine
// verdict. Regression for the drift bug (credential read shown as ALLOW) and the
// render bug (block printed as REVIEW). Spawns dist/cli.js — requires build.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function explain(command: string): string {
  const r = spawnSync(process.execPath, [CLI, 'explain', 'bash', command], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(), // no project node9.config.json — built-in gates only
    env: { ...process.env, NODE9_NO_AUTO_DAEMON: '1', NODE9_TESTING: '1', NO_COLOR: '1' },
  });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

describe('node9 explain — rendered verdict matches the engine', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
  });

  it('a credential read renders BLOCK, not ALLOW/REVIEW (the drift + render bug)', () => {
    const out = explain('cat ~/.aws/credentials');
    expect(out).toMatch(/Decision: .*BLOCK/);
    expect(out).not.toMatch(/Decision: .*ALLOW/);
    expect(out).toMatch(/block-read-aws/);
  });

  it('a benign command still renders ALLOW', () => {
    const out = explain('ls -la');
    expect(out).toMatch(/Decision: .*ALLOW/);
  });
});
