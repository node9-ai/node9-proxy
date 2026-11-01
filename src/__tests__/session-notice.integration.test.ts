/**
 * fw#420 step 2 at the real hook: `node9 check` from dist/cli.js, a clean HOME.
 * The first ALLOWED call of a Claude Code session carries the level notice as
 * PreToolUse additionalContext (plus systemMessage for the CLI); every other
 * call prints what it printed before. NODE9_SESSION_NOTICE=1 turns the notice
 * on under NODE9_TESTING, which keeps it off for every other test.
 *
 * Requirements: `npm run build` first. Skipped on Windows (/dev/tty, stdio).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { claimSessionNotice, SESSION_NOTICE_INSTRUCTION } from '../notices/session-notice';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const cliExists = fs.existsSync(CLI);
if (!cliExists) {
  console.warn(`[session-notice] skipped: dist/cli.js not found. Run "npm run build".`);
}
const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);

const SHIELD = '\u{1F6E1}\uFE0F';
const STANDARD = `${SHIELD} Node9 is on (Standard). Every action in this session is checked.`;
const AUDIT = `${SHIELD} Node9 is in Audit mode: actions are logged, nothing is blocked.`;

interface HookOut {
  hookSpecificOutput?: Record<string, unknown>;
  systemMessage?: string;
}

let room: string;

beforeAll(() => {
  room = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-notice-'));
});

afterAll(() => {
  if (room) fs.rmSync(room, { recursive: true, force: true });
});

/** A fresh HOME + project; `mode` is written as settings.mode when given. */
function makeHome(name: string, mode?: string): { home: string; project: string } {
  const home = path.join(room, name, 'home');
  const project = path.join(room, name, 'proj');
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  fs.writeFileSync(path.join(project, '.env'), 'DEMO_FLAG=1\n');
  fs.writeFileSync(
    path.join(home, '.node9', 'shields.json'),
    JSON.stringify({ active: ['bash-safe', 'filesystem', 'project-jail'] })
  );
  if (mode) {
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({ settings: { mode } })
    );
  }
  return { home, project };
}

function check(
  where: { home: string; project: string },
  sessionId: string,
  command: string,
  agentFlag?: string
) {
  const env = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  const payload = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
    cwd: where.project,
    session_id: sessionId,
  };
  const args = [CLI, 'check'];
  if (agentFlag) args.push('--agent', agentFlag);
  args.push(JSON.stringify(payload));
  const result = spawnSync(process.execPath, args, {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: where.project,
    env: {
      ...env,
      HOME: where.home,
      USERPROFILE: where.home,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      NODE9_SESSION_NOTICE: '1',
    },
  });
  expect(result.error).toBeUndefined();
  const out = (result.stdout ?? '').trim();
  return {
    status: result.status,
    out,
    json: out ? (JSON.parse(out) as HookOut) : null,
  };
}

describe('the session level notice at the real hook (fw#420)', () => {
  itUnix('the first allowed call carries the notice, without a decision', () => {
    const where = makeHome('first');
    const r = check(where, 'sess-first', 'ls');
    expect(r.status).toBe(0);
    const h = r.json?.hookSpecificOutput ?? {};
    expect(h.hookEventName).toBe('PreToolUse');
    expect(h.additionalContext).toBe(`${STANDARD}\n${SESSION_NOTICE_INSTRUCTION}`);
    expect(h.permissionDecision).toBeUndefined();
    expect(r.json?.systemMessage).toBe(STANDARD);
  });

  itUnix('the second call in the same session prints nothing, a new session gets it again', () => {
    const where = makeHome('again');
    expect(check(where, 'sess-a', 'ls').json).not.toBeNull();
    const second = check(where, 'sess-a', 'pwd');
    expect(second.status).toBe(0);
    expect(second.out).toBe('');
    expect(check(where, 'sess-b', 'ls').json?.systemMessage).toBe(STANDARD);
  });

  itUnix('Audit says that nothing is blocked', () => {
    const where = makeHome('audit', 'audit');
    expect(check(where, 'sess-audit', 'ls').json?.systemMessage).toBe(AUDIT);
  });

  itUnix('observe, the older name of Audit, says the same', () => {
    const where = makeHome('observe', 'observe');
    expect(check(where, 'sess-observe', 'ls').json?.systemMessage).toBe(AUDIT);
  });

  itUnix('a block is unchanged and does not use up the notice', () => {
    const where = makeHome('block');
    const blocked = check(where, 'sess-block', 'cat .env');
    expect(blocked.status).toBe(2);
    expect(blocked.json?.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(blocked.json?.hookSpecificOutput?.additionalContext).toBeUndefined();
    expect(check(where, 'sess-block', 'ls').json?.systemMessage).toBe(STANDARD);
  });

  itUnix('another agent gets no notice', () => {
    const where = makeHome('copilot');
    const r = check(where, 'sess-copilot', 'ls', 'copilot');
    expect(r.status).toBe(0);
    expect(r.out).toBe('');
  });

  itUnix('a session id that cannot be a file name gets no notice', () => {
    const where = makeHome('badid');
    const r = check(where, '../../etc/x', 'ls');
    expect(r.status).toBe(0);
    expect(r.out).toBe('');
  });
});

describe('claimSessionNotice', () => {
  it('is true once per session id', () => {
    const home = fs.mkdtempSync(path.join(room, 'claim-'));
    expect(claimSessionNotice('s1', home)).toBe(true);
    expect(claimSessionNotice('s1', home)).toBe(false);
    expect(claimSessionNotice('s2', home)).toBe(true);
  });

  it('removes flags older than seven days when a new session claims one', () => {
    const home = fs.mkdtempSync(path.join(room, 'gc-'));
    expect(claimSessionNotice('old', home)).toBe(true);
    const old = path.join(home, '.node9', 'notice-sessions', 'old');
    const eightDays = (Date.now() - 8 * 24 * 60 * 60 * 1000) / 1000;
    fs.utimesSync(old, eightDays, eightDays);
    expect(claimSessionNotice('new', home)).toBe(true);
    expect(fs.existsSync(old)).toBe(false);
  });

  it('refuses an id that is not a plain name', () => {
    const home = fs.mkdtempSync(path.join(room, 'bad-'));
    expect(claimSessionNotice('../x', home)).toBe(false);
    expect(claimSessionNotice('', home)).toBe(false);
    expect(claimSessionNotice(undefined, home)).toBe(false);
  });
});
