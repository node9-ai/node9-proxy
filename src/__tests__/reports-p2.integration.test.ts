// Reports cleanup P2 (fw#421): the posture score is the only N/100 the CLI
// prints. `blast` and `scan` show facts and point at `node9 posture`;
// `status` carries the posture number. Spawns the built CLI (dist/cli.js)
// against a synthetic HOME, like the other command integration tests.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

let home: string;

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  delete baseEnv.HERMES_HOME;
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 90_000,
    cwd: home,
    env: {
      ...baseEnv,
      HOME: home,
      USERPROFILE: home,
      NODE9_TESTING: '1',
      NODE9_NO_AUTO_DAEMON: '1',
      NO_COLOR: '1',
      FORCE_COLOR: '0',
    },
  });
  expect(r.error).toBeUndefined();
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-p2-'));
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ settings: { mode: 'standard' } })
  );
  // One reachable credential file, so blast has a row to print.
  fs.mkdirSync(path.join(home, '.ssh'), { recursive: true });
  fs.writeFileSync(path.join(home, '.ssh', 'id_rsa'), 'not a real key\n', { mode: 0o600 });
  // One recent Claude session with a Bash call, so scan renders its report
  // (an empty history returns before any panel).
  const projDir = path.join(home, '.claude', 'projects', '-tmp-p2-proj');
  fs.mkdirSync(projDir, { recursive: true });
  const now = new Date().toISOString();
  fs.writeFileSync(
    path.join(projDir, 'sess-p2.jsonl'),
    [
      JSON.stringify({
        type: 'user',
        timestamp: now,
        cwd: home,
        message: { content: [{ type: 'text', text: 'list the files' }] },
      }),
      JSON.stringify({
        type: 'assistant',
        timestamp: now,
        cwd: home,
        message: {
          model: 'claude-sonnet-4-6',
          content: [{ type: 'tool_use', id: 't1', name: 'Bash', input: { command: 'ls -la' } }],
          usage: { input_tokens: 100, output_tokens: 50 },
        },
      }),
    ].join('\n') + '\n'
  );
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('node9 blast prints facts, not a score', () => {
  it('lists the reachable file and points at posture, with no N/100', () => {
    const r = run(['blast']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('~/.ssh/id_rsa');
    expect(r.stdout).toMatch(/node9 posture/);
    expect(r.stdout).not.toMatch(/\/100/);
    expect(r.stdout).not.toMatch(/Security Score/);
  });
});

describe('node9 scan prints counts and one pointer', () => {
  it('classic view: no Security Score line, the pointer at the end', () => {
    const r = run(['scan', '--classic', '--days', '7']);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toMatch(/Security Score/);
    expect(r.stdout).not.toMatch(/\d+\/100/);
    expect(r.stdout).toMatch(/Machine score: run .*node9 posture/);
  });

  it('default view: the pointer is there too', () => {
    const r = run(['scan', '--days', '7']);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toMatch(/\d+\/100/);
    expect(r.stdout).toMatch(/Machine score: run .*node9 posture/);
  });

  it('--json keeps score and band until P3 (schemaVersion 1 contract)', () => {
    const r = run(['scan', '--json', '--days', '7']);
    expect(r.status).toBe(0);
    const env = JSON.parse(r.stdout) as { schemaVersion: number; score: number; band: string };
    expect(env.schemaVersion).toBe(1);
    expect(typeof env.score).toBe('number');
    expect(['good', 'at-risk', 'critical']).toContain(env.band);
  });
});

describe('node9 status carries the posture score', () => {
  it('prints Score: N/100 with the posture tier and the pointer', () => {
    const r = run(['status']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/Score:\s+\d+\/100\s+\((Good|At risk|Critical)\)/);
    expect(r.stdout).toMatch(/node9 posture/);
    // The same number posture prints.
    const p = run(['posture', '--json']);
    const posture = JSON.parse(p.stdout) as { score: number };
    const m = r.stdout.match(/Score:\s+(\d+)\/100/);
    expect(Number(m?.[1])).toBe(posture.score);
  });
});
