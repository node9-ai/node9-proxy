/**
 * The repository a call ran in (cases-session stage 2, change 7), through the
 * real built `node9 check` hook: every audit row a call writes carries
 * `projectRoot`, the nearest folder above the working folder that holds
 * `.git`. The cloud names the project by it and measures "outside" against
 * it.
 *
 * Spawns the real built CLI (`dist/cli.js`); run `npm run build` first.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

let home: string;
let base: string;

beforeAll(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-project-root-home-'));
  base = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-project-root-'));
  fs.mkdirSync(path.join(base, 'repo', '.git'), { recursive: true });
  fs.mkdirSync(path.join(base, 'repo', 'be'), { recursive: true });
  fs.mkdirSync(path.join(base, 'plain'), { recursive: true });
  // A worktree's .git is a file, not a folder.
  fs.mkdirSync(path.join(base, 'worktree', 'src'), { recursive: true });
  fs.writeFileSync(path.join(base, 'worktree', '.git'), 'gitdir: /elsewhere/.git/worktrees/w\n');
});

afterAll(() => {
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(base, { recursive: true, force: true });
});

let calls = 0;

/** The audit rows one `check` call wrote, from a Claude Code payload. Each
 *  call runs its own command: repeating one trips the loop detector. */
function rowsFor(cwd: string): Array<Record<string, unknown>> {
  calls += 1;
  const command = `echo call-${calls}`;
  const logPath = path.join(home, '.node9', 'audit.log');
  const before = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8').length : 0;
  const env = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  const r = spawnSync(
    process.execPath,
    [
      CLI,
      'check',
      JSON.stringify({
        session_id: 'sess-project-root',
        cwd,
        hook_event_name: 'PreToolUse',
        permission_mode: 'default',
        tool_name: 'Bash',
        tool_input: { command },
        tool_use_id: 'toolu_project_root',
      }),
    ],
    {
      encoding: 'utf-8',
      timeout: 60000,
      cwd,
      env: { ...env, NODE9_NO_AUTO_DAEMON: '1', NODE9_TESTING: '1', HOME: home, USERPROFILE: home },
    }
  );
  expect(r.error).toBeUndefined();
  expect(r.status).toBe(0);
  const rows = fs
    .readFileSync(logPath, 'utf8')
    .slice(before)
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .filter((row) => typeof row.eid === 'string');
  expect(rows.length).toBeGreaterThan(0);
  return rows;
}

describe('check hook: the project root on audit rows', () => {
  it('a call from a subfolder names the repository above it', () => {
    for (const row of rowsFor(path.join(base, 'repo', 'be'))) {
      expect(row.workingDir).toBe(path.join(base, 'repo', 'be'));
      expect(row.projectRoot).toBe(path.join(base, 'repo'));
    }
  });

  it('a call at the repository root names that folder', () => {
    for (const row of rowsFor(path.join(base, 'repo')))
      expect(row.projectRoot).toBe(path.join(base, 'repo'));
  });

  it('a git worktree is its own repository', () => {
    for (const row of rowsFor(path.join(base, 'worktree', 'src')))
      expect(row.projectRoot).toBe(path.join(base, 'worktree'));
  });

  it('a folder in no repository carries no root', () => {
    for (const row of rowsFor(path.join(base, 'plain')))
      expect(row).not.toHaveProperty('projectRoot');
  });

  it('the home folder is never the root, even when it holds .git', () => {
    fs.mkdirSync(path.join(home, '.git'), { recursive: true });
    const proj = path.join(home, 'proj');
    fs.mkdirSync(proj, { recursive: true });
    try {
      for (const row of rowsFor(proj)) expect(row).not.toHaveProperty('projectRoot');
    } finally {
      fs.rmSync(path.join(home, '.git'), { recursive: true, force: true });
    }
  });
});
