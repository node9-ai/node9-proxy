/**
 * Reads outside the project (cases-session stage 2, change 6), through the
 * real built `node9 log` hook: a Read of a file outside the session's project
 * marks the post-hook row with the shortened path; anything else leaves the
 * row unmarked.
 *
 * The project lives inside this checkout, not the OS temp folder: temp reads
 * are never "outside", so a temp-based fixture would test nothing (and the
 * test setup points HOME at a temp folder).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

let home: string;
let base: string;
let repo: string;
let cwd: string;

beforeAll(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-read-outside-home-'));
  base = fs.mkdtempSync(path.resolve(__dirname, '../../.read-outside-test-'));
  repo = path.join(base, 'repo');
  cwd = path.join(repo, 'be');
  fs.mkdirSync(path.join(repo, '.git'), { recursive: true });
  fs.mkdirSync(cwd, { recursive: true });
  fs.mkdirSync(path.join(repo, 'fe'), { recursive: true });
  fs.mkdirSync(path.join(base, 'other'), { recursive: true });
});

afterAll(() => {
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(base, { recursive: true, force: true });
});

function runLog(payload: object): Record<string, unknown> {
  const env = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  const logPath = path.join(home, '.node9', 'audit.log');
  const before = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8').length : 0;
  const result = spawnSync(process.execPath, [CLI, 'log'], {
    encoding: 'utf-8',
    input: JSON.stringify(payload),
    timeout: 60000,
    cwd,
    env: {
      ...env,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      HOME: home,
      USERPROFILE: home,
    },
  });
  expect(result.error).toBeUndefined();
  expect(result.status).toBe(0);
  const added = fs.readFileSync(logPath, 'utf8').slice(before).trim().split('\n');
  const row = added
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .find((r) => r.source === 'post-hook');
  expect(row).toBeDefined();
  return row!;
}

/** What Claude Code sends to the PostToolUse hook. */
const claudePayload = (tool: string, input: object, extra: object = {}) => ({
  hook_event_name: 'PostToolUse',
  tool_name: tool,
  tool_input: input,
  tool_response: { type: 'text', file: { content: 'x' } },
  tool_use_id: 'toolu_01ReadOutside',
  session_id: 'sess-read-outside',
  cwd,
  ...extra,
});

describe('log hook: reads outside the project', () => {
  it('marks a Read outside the project with the shortened path', () => {
    const row = runLog(claudePayload('Read', { file_path: path.join(base, 'other', 'notes.md') }));
    expect(row.readOutside).toBe('other/notes.md');
    expect(row.sessionId).toBe('sess-read-outside');
  });

  it('a file elsewhere in the same repository is inside, even from a subfolder', () => {
    const row = runLog(claudePayload('Read', { file_path: path.join(repo, 'fe', 'app.ts') }));
    expect(row).not.toHaveProperty('readOutside');
  });

  it('a read in a temp folder is never outside', () => {
    const row = runLog(claudePayload('Read', { file_path: path.join(os.tmpdir(), 'scratch.txt') }));
    expect(row).not.toHaveProperty('readOutside');
  });

  it('a Grep over a folder outside is not a file read', () => {
    const row = runLog(claudePayload('Grep', { pattern: 'x', path: path.join(base, 'other') }));
    expect(row).not.toHaveProperty('readOutside');
  });

  it('a call with no session id is not marked', () => {
    const row = runLog(
      claudePayload(
        'Read',
        { file_path: path.join(base, 'other', 'notes.md') },
        { session_id: undefined }
      )
    );
    expect(row).not.toHaveProperty('readOutside');
  });

  it('a relative cwd is unusable: nothing is marked', () => {
    const row = runLog(
      claudePayload(
        'Read',
        { file_path: path.join(base, 'other', 'notes.md') },
        { cwd: 'relative/dir' }
      )
    );
    expect(row).not.toHaveProperty('readOutside');
  });
});
