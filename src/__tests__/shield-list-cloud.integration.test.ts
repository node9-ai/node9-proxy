// Integration: `node9 shield list` marks a shield as cloud-enabled when a synced
// cloud rule (rules-cache.json) carries `source: "SHIELD:<name>"`, and falls back
// to the rule description for caches synced before the source tag existed.
// Spawns dist/cli.js (file reads + subprocess, per CLAUDE.md). Requires build.
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function makeHome(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-shieldlist-'));
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  return h;
}

function run(home: string, args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: os.tmpdir(),
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
    },
  });
}

function writeCache(home: string, rules: unknown[]) {
  fs.writeFileSync(
    path.join(home, '.node9', 'rules-cache.json'),
    JSON.stringify({ fetchedAt: '2026-06-28T00:00:00Z', rules })
  );
}

function lineFor(out: string, name: string): string {
  return out.split('\n').find((l) => new RegExp(`\\b${name}\\b`).test(l)) ?? '';
}

describe('node9 shield list — cloud-enabled shields', () => {
  beforeAll(() => {
    expect(fs.existsSync(CLI), 'run `npm run build` first').toBe(true);
  });

  it('marks a shield cloud-enabled from the source tag (not locally enabled)', () => {
    const home = makeHome();
    writeCache(home, [
      {
        name: 'org:1',
        tool: '*',
        verdict: 'block',
        conditions: [{ field: 'command', op: 'matches', value: 'aws s3 rb' }],
        source: 'SHIELD:aws',
      },
    ]);

    const r = run(home, ['shield', 'list']);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);

    const out = `${r.stdout}${r.stderr}`;
    // aws is NOT locally enabled but IS cloud-active → must not read "disabled"
    const aws = lineFor(out, 'aws');
    expect(aws).toMatch(/cloud|via dashboard/i);
    expect(aws).not.toMatch(/disabled/i);
  });

  it('falls back to the description when a cloud rule has no source tag', () => {
    const home = makeHome();
    writeCache(home, [
      {
        name: 'org:1',
        tool: '*',
        verdict: 'block',
        conditions: [],
        description: 'S3 bucket deletion is irreversible — blocked by AWS shield',
      },
    ]);

    const out = `${run(home, ['shield', 'list']).stdout}`;
    expect(lineFor(out, 'aws')).toMatch(/cloud|via dashboard/i);
  });

  it('a shield with neither local nor cloud presence still shows disabled', () => {
    const home = makeHome();
    writeCache(home, []); // no cloud rules
    const out = `${run(home, ['shield', 'list']).stdout}`;
    // docker isn't enabled anywhere here
    expect(lineFor(out, 'docker')).toMatch(/disabled/i);
  });
});
