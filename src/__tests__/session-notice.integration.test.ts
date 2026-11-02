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
import { execFileSync, spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { claimSessionNotice, SESSION_NOTICE_NOTE } from '../notices/session-notice';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const cliExists = fs.existsSync(CLI);
if (!cliExists) {
  console.warn(`[session-notice] skipped: dist/cli.js not found. Run "npm run build".`);
}
const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);

const SHIELD = '\u{1F6E1}\uFE0F';
const STANDARD = `${SHIELD} Node9 is on (Standard). Every action in this session is checked.`;
const AUDIT = `${SHIELD} Node9 is in Audit mode: actions are logged, nothing is blocked.`;
const CHANGED_AUDIT = `${SHIELD} Node9 level changed to Audit: actions are logged, nothing is blocked.`;
const CHANGED_STRICT = `${SHIELD} Node9 level changed to Strict. Every action in this session is checked.`;
const setMode = (home: string, mode: string) =>
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ settings: { mode } })
  );

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
  agentFlag?: string,
  extra: Record<string, unknown> = {},
  envExtra: Record<string, string> = {}
) {
  const env = { ...process.env, ...envExtra };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  const payload = {
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
    cwd: where.project,
    session_id: sessionId,
    ...extra,
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
    expect(h.additionalContext).toBe(`${STANDARD}\n${SESSION_NOTICE_NOTE}`);
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

  // fw#420 step 3: the CLI shows systemMessage directly, so a block carries
  // node9's own line there as well as in the reason the agent quotes.
  itUnix('a block carries the user line as systemMessage', () => {
    const where = makeHome('block-cli');
    const blocked = check(where, 'sess-block-cli', 'cat .env');
    const reason = String(blocked.json?.hookSpecificOutput?.permissionDecisionReason ?? '');
    expect(blocked.json?.systemMessage).toBe(reason.split('\n')[0]);
    expect(blocked.json?.systemMessage).toMatch(/^\u{1F6E1}\uFE0F Node9 blocked/u);
  });

  // /code-review: a subagent's reply goes to the parent agent, not the user.
  itUnix("a subagent's call neither shows nor spends the notice", () => {
    const where = makeHome('subagent');
    const sub = check(where, 'sess-sub', 'ls', undefined, {
      agent_id: 'a1debb48f698832fb',
      agent_type: 'Explore',
    });
    expect(sub.status).toBe(0);
    expect(sub.out).toBe('');
    expect(check(where, 'sess-sub', 'ls').json?.systemMessage).toBe(STANDARD);
  });

  itUnix('another agent gets no notice', () => {
    const where = makeHome('copilot');
    const r = check(where, 'sess-copilot', 'ls', 'copilot');
    expect(r.status).toBe(0);
    expect(r.out).toBe('');
  });

  // Review: a paused node9 checks nothing, so it must not say it does, and the
  // flag stays free for the first checked call after the pause.
  itUnix('a paused node9 shows no notice and keeps the flag for later', () => {
    const where = makeHome('paused');
    const paused = check(where, 'sess-paused', 'ls', undefined, {}, { NODE9_PAUSED: '1' });
    expect(paused.status).toBe(0);
    expect(paused.out).toBe('');
    expect(check(where, 'sess-paused', 'ls').json?.systemMessage).toBe(STANDARD);
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
    expect(claimSessionNotice('s1', home)).toBe('first');
    expect(claimSessionNotice('s1', home)).toBeNull();
    expect(claimSessionNotice('s2', home)).toBe('first');
  });

  it('removes flags older than seven days when a new session claims one', () => {
    const home = fs.mkdtempSync(path.join(room, 'gc-'));
    expect(claimSessionNotice('old', home)).toBe('first');
    const old = path.join(home, '.node9', 'notice-sessions', 'old.node9-flag');
    const eightDays = (Date.now() - 8 * 24 * 60 * 60 * 1000) / 1000;
    fs.utimesSync(old, eightDays, eightDays);
    expect(claimSessionNotice('new', home)).toBe('first');
    expect(fs.existsSync(old)).toBe(false);
  });

  // Review: the flag directory sits under ~/.node9, which the agent can reach
  // with mv and ln. A link there must not let node9 delete files elsewhere.
  itUnix('a flag directory that is a link is not used, and nothing it points to is removed', () => {
    const home = fs.mkdtempSync(path.join(room, 'link-'));
    const victim = fs.mkdtempSync(path.join(room, 'victim-'));
    const oldFile = path.join(victim, 'old-notes.txt');
    fs.writeFileSync(oldFile, 'keep me');
    const thirtyDays = (Date.now() - 30 * 24 * 60 * 60 * 1000) / 1000;
    fs.utimesSync(oldFile, thirtyDays, thirtyDays);
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.symlinkSync(victim, path.join(home, '.node9', 'notice-sessions'));
    expect(claimSessionNotice('s-link', home)).toBeNull();
    expect(fs.existsSync(oldFile)).toBe(true);
    expect(fs.readdirSync(victim)).toEqual(['old-notes.txt']);
  });

  itUnix('clean-up removes only old flag files, never other entries', () => {
    const home = fs.mkdtempSync(path.join(room, 'only-flags-'));
    expect(claimSessionNotice('first', home)).toBe('first');
    const dir = path.join(home, '.node9', 'notice-sessions');
    const eightDays = (Date.now() - 8 * 24 * 60 * 60 * 1000) / 1000;
    const notAFlag = path.join(dir, 'not a flag.txt');
    const makefile = path.join(dir, 'Makefile');
    const subdir = path.join(dir, 'subdir');
    const outside = fs.mkdtempSync(path.join(room, 'outside-'));
    const outsideFile = path.join(outside, 'target');
    fs.writeFileSync(outsideFile, 'x');
    const link = path.join(dir, 'linkflag.node9-flag');
    fs.writeFileSync(notAFlag, 'x');
    fs.writeFileSync(makefile, 'x');
    fs.mkdirSync(subdir);
    fs.symlinkSync(outsideFile, link);
    for (const p of [notAFlag, makefile, subdir, outsideFile])
      fs.utimesSync(p, eightDays, eightDays);
    fs.lutimesSync(link, eightDays, eightDays);
    expect(claimSessionNotice('second', home)).toBe('first');
    expect(fs.existsSync(notAFlag)).toBe(true);
    expect(fs.existsSync(makefile)).toBe(true);
    expect(fs.existsSync(subdir)).toBe(true);
    expect(fs.lstatSync(link).isSymbolicLink()).toBe(true);
    expect(fs.existsSync(outsideFile)).toBe(true);
  });

  it('refuses an id that is not a plain name', () => {
    const home = fs.mkdtempSync(path.join(room, 'bad-'));
    expect(claimSessionNotice('../x', home)).toBeNull();
    expect(claimSessionNotice('', home)).toBeNull();
    expect(claimSessionNotice(undefined, home)).toBeNull();
  });
});

// 2026-11-02, after 2.48.0: Claude repeated the notice in every later reply,
// because the quote instruction stays in the conversation, and after the
// founder moved the workspace back to Audit the repeated line named the old
// level. Design: docs/roadmap/active/notice-repeat-fix-code-design.md.
describe('the notice is shown once, and once more only when the level changes', () => {
  // Fallback c: the measured "once" wording still repeated (1 session in 5).
  it('the session notice asks the agent for nothing but silence', () => {
    expect(SESSION_NOTICE_NOTE).not.toMatch(/start your|show the line|quote/i);
    expect(SESSION_NOTICE_NOTE).toMatch(/do not mention it/i);
  });

  itUnix('a level change mid-session gives one notice with the new level, then nothing', () => {
    const where = makeHome('change', 'standard');
    expect(check(where, 'sess-chg', 'ls').json?.systemMessage).toBe(STANDARD);
    setMode(where.home, 'audit');
    const changed = check(where, 'sess-chg', 'ls');
    expect(changed.status).toBe(0);
    expect(changed.json?.systemMessage).toBe(CHANGED_AUDIT);
    expect(String(changed.json?.hookSpecificOutput?.additionalContext)).toContain(CHANGED_AUDIT);
    expect(check(where, 'sess-chg', 'pwd').out).toBe('');
    setMode(where.home, 'strict');
    expect(check(where, 'sess-chg', 'ls').json?.systemMessage).toBe(CHANGED_STRICT);
  });

  itUnix('a flag written by 2.48.0 (no level) is filled in without a second notice', () => {
    const where = makeHome('legacy', 'standard');
    const dir = path.join(where.home, '.node9', 'notice-sessions');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const flag = path.join(dir, 'sess-old.node9-flag');
    fs.writeFileSync(flag, '');
    expect(check(where, 'sess-old', 'ls').out).toBe('');
    expect(fs.readFileSync(flag, 'utf8')).toBe('standard');
    setMode(where.home, 'audit');
    expect(check(where, 'sess-old', 'ls').json?.systemMessage).toBe(CHANGED_AUDIT);
  });

  // Review: a FIFO (or a link to one) in place of the flag must not stall the
  // hook: it is not a regular file, so it is not read.
  itUnix('a FIFO in place of the flag gives no notice and does not hang', () => {
    const where = makeHome('fifo', 'standard');
    const dir = path.join(where.home, '.node9', 'notice-sessions');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    execFileSync('mkfifo', [path.join(dir, 'sess-fifo.node9-flag')]);
    const started = Date.now();
    const r = check(where, 'sess-fifo', 'ls');
    expect(r.status).toBe(0);
    expect(r.out).toBe('');
    expect(Date.now() - started).toBeLessThan(20_000);
  });

  it('claimSessionNotice says first, then nothing, then changed', () => {
    const home = fs.mkdtempSync(path.join(room, 'kinds-'));
    expect(claimSessionNotice('k1', home, 'standard')).toBe('first');
    expect(claimSessionNotice('k1', home, 'standard')).toBeNull();
    expect(claimSessionNotice('k1', home, 'audit')).toBe('changed');
    expect(claimSessionNotice('k1', home, 'audit')).toBeNull();
  });
});
