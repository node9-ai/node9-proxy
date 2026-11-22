// src/__tests__/session-turn.integration.test.ts
//
// The turn number, through the real hook (dist/cli.js): a prompt is counted,
// and every audit row of the calls that follow carries the count. One temp
// HOME per test, shared by its calls; no daemon.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

let root: string;
let n = 0;

beforeAll(() => {
  if (!fs.existsSync(CLI)) throw new Error(`dist/cli.js not found at ${CLI}; run npm run build`);
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-turn-'));
});

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

function newHome(): string {
  const home = path.join(root, `h${n++}`);
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.mkdirSync(path.join(home, 'tmp'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({
      settings: {
        mode: 'audit',
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
    })
  );
  return home;
}

function hook(home: string, payload: Record<string, unknown>) {
  const env = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  delete env.NODE9_MODE;
  const r = spawnSync(process.execPath, [CLI, 'check', JSON.stringify({ cwd: home, ...payload })], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: home,
    env: {
      ...env,
      HOME: home,
      USERPROFILE: home,
      // The hook binds its activity socket under TMPDIR.
      TMPDIR: path.join(home, 'tmp'),
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
    },
  });
  expect(r.error).toBeUndefined();
  expect(r.status).toBe(0);
  return r;
}

const prompt = (home: string, sessionId: string, text: string) =>
  hook(home, { hook_event_name: 'UserPromptSubmit', session_id: sessionId, prompt: text });

const bash = (home: string, sessionId: string, command: string) =>
  hook(home, {
    hook_event_name: 'PreToolUse',
    session_id: sessionId,
    tool_name: 'Bash',
    tool_input: { command },
  });

function rows(home: string): Array<Record<string, unknown>> {
  const f = path.join(home, '.node9', 'audit.log');
  if (!fs.existsSync(f)) return [];
  return fs
    .readFileSync(f, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

const turns = (home: string, sessionId: string) =>
  rows(home)
    .filter((r) => r.sessionId === sessionId)
    .map((r) => r.turn);

describe('the turn number on audit rows', () => {
  it('calls after a prompt carry its number, and the next prompt starts the next turn', () => {
    const home = newHome();
    prompt(home, 's-one', 'list the files');
    bash(home, 's-one', 'ls -la');
    bash(home, 's-one', 'pwd');
    prompt(home, 's-one', 'now the date');
    bash(home, 's-one', 'date');
    expect(turns(home, 's-one')).toEqual([1, 1, 2]);
  });

  it('a session whose agent sent no prompt hook has no turn', () => {
    const home = newHome();
    bash(home, 's-none', 'ls -la');
    const mine = rows(home).filter((r) => r.sessionId === 's-none');
    expect(mine).toHaveLength(1);
    expect('turn' in mine[0]).toBe(false);
  });

  it('each session counts its own prompts', () => {
    const home = newHome();
    prompt(home, 's-a', 'first');
    prompt(home, 's-a', 'second');
    prompt(home, 's-b', 'first');
    bash(home, 's-a', 'ls');
    bash(home, 's-b', 'ls');
    expect(turns(home, 's-a')).toEqual([2]);
    expect(turns(home, 's-b')).toEqual([1]);
  });

  it('records a count and never the prompt', () => {
    const home = newHome();
    const SENTINEL = 'ZZPROMPTSENTINEL';
    prompt(home, 's-private', `please refactor ${SENTINEL} for me`);
    bash(home, 's-private', 'ls');
    const dir = path.join(home, '.node9', 'session-turns');
    const files = fs.readdirSync(dir);
    expect(files).toHaveLength(1);
    // The file is named by a hash, not by the session id, and holds digits.
    expect(files[0]).not.toContain('s-private');
    expect(fs.readFileSync(path.join(dir, files[0]), 'utf-8')).toBe('1');
    expect(fs.readFileSync(path.join(home, '.node9', 'audit.log'), 'utf-8')).not.toContain(
      SENTINEL
    );
  });

  it('a counter file that is not a number is read as no turn, and the next prompt repairs it', () => {
    const home = newHome();
    prompt(home, 's-bad', 'first');
    const dir = path.join(home, '.node9', 'session-turns');
    const f = path.join(dir, fs.readdirSync(dir)[0]);
    fs.writeFileSync(f, 'not-a-number');
    bash(home, 's-bad', 'ls');
    prompt(home, 's-bad', 'second');
    bash(home, 's-bad', 'pwd');
    expect(turns(home, 's-bad')).toEqual([undefined, 1]);
  });
});
