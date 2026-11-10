/**
 * The Codex session notice at the real hook (`dist/cli.js`): the line that
 * says node9 is on, at the start of a Codex session.
 *
 * Codex 0.154 runs a SessionStart hook when a session starts. Its payload has
 * no turn_id (node9's Codex fingerprint), so the hook is registered as
 * `node9 check --agent codex`. Exit 0 output: systemMessage (shown to the user)
 * and hookSpecificOutput.additionalContext (given to the model); Codex rejects
 * any unknown field (deny_unknown_fields), so every output is checked against
 * the keys Codex knows. Source: openai/codex rust-v0.154.0,
 * hooks/src/events/session_start.rs and hooks/schema/generated/*.json.
 *
 * Requirements: `npm run build` first. Skipped on Windows (/dev/tty, stdio).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SESSION_NOTICE_ASK, SESSION_NOTICE_DONE } from '../notices/session-notice';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const cliExists = fs.existsSync(CLI);
const itUnix = it.skipIf(process.platform === 'win32' || !cliExists);

const SHIELD = '\u{1F6E1}️';
const STANDARD = `${SHIELD} Node9 is on (Standard). Every action in this session is checked.`;
const AUDIT = `${SHIELD} Node9 is in Audit mode: actions are logged, nothing is blocked.`;
const CHANGED_AUDIT = `${SHIELD} Node9 level changed to Audit: actions are logged, nothing is blocked.`;

// Output keys Codex 0.154 accepts, per event (top level, hookSpecificOutput).
const UNIVERSAL = ['continue', 'stopReason', 'suppressOutput', 'systemMessage'];
const CODEX_KEYS: Record<string, { top: string[]; hso: string[] }> = {
  SessionStart: {
    top: [...UNIVERSAL, 'hookSpecificOutput'],
    hso: ['additionalContext', 'hookEventName'],
  },
  PreToolUse: {
    top: [...UNIVERSAL, 'decision', 'reason', 'hookSpecificOutput'],
    hso: [
      'additionalContext',
      'hookEventName',
      'permissionDecision',
      'permissionDecisionReason',
      'updatedInput',
    ],
  },
  UserPromptSubmit: {
    top: [...UNIVERSAL, 'decision', 'reason', 'hookSpecificOutput'],
    hso: ['additionalContext', 'hookEventName'],
  },
};

/** The output parses under Codex's schema for `event` and never stops the session. */
function expectCodexAccepts(event: string, out: Record<string, unknown>): void {
  const keys = CODEX_KEYS[event];
  for (const k of Object.keys(out)) expect(keys.top, `top-level key ${k}`).toContain(k);
  const hso = out.hookSpecificOutput as Record<string, unknown> | undefined;
  if (hso) {
    expect(hso.hookEventName).toBe(event);
    for (const k of Object.keys(hso)) expect(keys.hso, `hookSpecificOutput key ${k}`).toContain(k);
  }
  expect(out.continue).toBeUndefined();
  expect(out.stopReason).toBeUndefined();
}

let room: string;
beforeAll(() => {
  room = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-codex-notice-'));
});
afterAll(() => {
  if (room) fs.rmSync(room, { recursive: true, force: true });
});

function makeHome(name: string, mode = 'standard'): { home: string; project: string } {
  const home = path.join(room, name, 'home');
  const project = path.join(room, name, 'proj');
  fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
  fs.mkdirSync(project, { recursive: true });
  setMode(home, mode);
  return { home, project };
}

function setMode(home: string, mode: string, extra: Record<string, unknown> = {}): void {
  fs.writeFileSync(
    path.join(home, '.node9', 'config.json'),
    JSON.stringify({ settings: { mode, ...extra } })
  );
}

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
  json: Record<string, unknown> | null;
}

function run(
  where: { home: string; project: string },
  payload: Record<string, unknown>,
  args: string[] = [],
  envExtra: Record<string, string> = {}
): Run {
  const env = { ...process.env };
  delete env.NODE9_API_KEY;
  delete env.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, 'check', ...args, JSON.stringify(payload)], {
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
      ...envExtra,
    },
  });
  expect(r.error).toBeUndefined();
  const stdout = r.stdout ?? '';
  return {
    status: r.status,
    stdout,
    stderr: r.stderr ?? '',
    json: stdout.trim() ? (JSON.parse(stdout) as Record<string, unknown>) : null,
  };
}

// Codex 0.154 payloads (the required fields of each input schema).
const sessionStart = (
  where: { project: string },
  sessionId: string,
  source = 'startup',
  extra: Record<string, unknown> = {}
) => ({
  session_id: sessionId,
  transcript_path: null,
  cwd: where.project,
  hook_event_name: 'SessionStart',
  model: 'gpt-6-astra',
  permission_mode: 'default',
  source,
  ...extra,
});
const userPrompt = (where: { project: string }, sessionId: string, text = 'hello') => ({
  session_id: sessionId,
  turn_id: 'turn-1',
  transcript_path: null,
  cwd: where.project,
  hook_event_name: 'UserPromptSubmit',
  model: 'gpt-6-astra',
  permission_mode: 'default',
  prompt: text,
});
const preToolUse = (where: { project: string }, sessionId: string, command = 'ls') => ({
  session_id: sessionId,
  turn_id: 'turn-1',
  transcript_path: null,
  cwd: where.project,
  hook_event_name: 'PreToolUse',
  model: 'gpt-6-astra',
  permission_mode: 'default',
  tool_name: 'Bash',
  tool_input: { command },
  tool_use_id: 'call_1',
});

const CODEX = ['--agent', 'codex'];
const flagOf = (home: string, sessionId: string) =>
  fs.readFileSync(path.join(home, '.node9', 'notice-sessions', `${sessionId}.node9-flag`), 'utf8');

describe('Codex session notice: SessionStart', () => {
  itUnix('a new Codex session gets the line at start, in the shape Codex reads', () => {
    const where = makeHome('start');
    const r = run(where, sessionStart(where, 'cx-start'), CODEX);
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
    expect(r.json).toEqual({
      systemMessage: STANDARD,
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: `${STANDARD}\n${SESSION_NOTICE_ASK}`,
      },
    });
    expectCodexAccepts('SessionStart', r.json!);
    expect(flagOf(where.home, 'cx-start')).toBe('standard+start');
  });

  itUnix('Audit says that nothing is blocked', () => {
    const where = makeHome('start-audit', 'audit');
    expect(run(where, sessionStart(where, 'cx-audit'), CODEX).json?.systemMessage).toBe(AUDIT);
  });

  itUnix('with the daemon down and automatic start off, the line says so', () => {
    const where = makeHome('daemon-down');
    setMode(where.home, 'standard', { autoStartDaemon: false });
    const r = run(where, sessionStart(where, 'cx-dd'), CODEX);
    expect(r.json?.systemMessage).toBe(
      `${STANDARD} The node9 daemon is not running: outside-content checks are off until it starts (node9 daemon start).`
    );
    expectCodexAccepts('SessionStart', r.json!);
  });

  itUnix('resume and compact of a told session say nothing', () => {
    const where = makeHome('resume');
    expect(run(where, sessionStart(where, 'cx-res'), CODEX).json).not.toBeNull();
    for (const source of ['resume', 'compact']) {
      const r = run(where, sessionStart(where, 'cx-res', source), CODEX);
      expect(r.status).toBe(0);
      expect(r.stdout).toBe('');
      expect(r.stderr).toBe('');
    }
  });

  itUnix('compact never opens a notice, even for an untold session', () => {
    const where = makeHome('compact');
    const r = run(where, sessionStart(where, 'cx-compact', 'compact'), CODEX);
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
  });

  itUnix('a resumed session whose level changed gets the changed line', () => {
    const where = makeHome('resume-change');
    run(where, sessionStart(where, 'cx-rc'), CODEX);
    setMode(where.home, 'audit');
    const r = run(where, sessionStart(where, 'cx-rc', 'resume'), CODEX);
    expect(r.json?.systemMessage).toBe(CHANGED_AUDIT);
    expectCodexAccepts('SessionStart', r.json!);
    expect(flagOf(where.home, 'cx-rc')).toBe('audit+start');
  });

  itUnix('a paused node9 says nothing and keeps the flag free', () => {
    const where = makeHome('paused');
    const r = run(where, sessionStart(where, 'cx-paused'), CODEX, { NODE9_PAUSED: '1' });
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    expect(run(where, sessionStart(where, 'cx-paused'), CODEX).json?.systemMessage).toBe(STANDARD);
  });

  itUnix('a subagent session says nothing', () => {
    const where = makeHome('sub');
    const r = run(where, sessionStart(where, 'cx-sub', 'startup', { agent_id: 'a1' }), CODEX);
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
  });

  itUnix('SessionStart without --agent codex says nothing and never blocks', () => {
    const where = makeHome('noflag');
    const r = run(where, sessionStart(where, 'cx-noflag'));
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).toBe('');
  });

  itUnix('a broken config still exits 0 silently', () => {
    const where = makeHome('broken');
    fs.writeFileSync(path.join(where.home, '.node9', 'config.json'), '{not json');
    const r = run(where, sessionStart(where, 'cx-broken'), CODEX);
    expect(r.status).toBe(0);
    expect(r.stdout === '' || JSON.parse(r.stdout).continue === undefined).toBe(true);
  });
});

describe('Codex session notice: after SessionStart', () => {
  itUnix('the first prompt keeps the ask open, the second closes it', () => {
    const where = makeHome('close');
    run(where, sessionStart(where, 'cx-close'), CODEX);
    const first = run(where, userPrompt(where, 'cx-close'));
    expect(first.status).toBe(0);
    expect(first.stdout).toBe('');
    expect(flagOf(where.home, 'cx-close')).toBe('standard+open');
    const second = run(where, userPrompt(where, 'cx-close', 'next'));
    expect(second.status).toBe(0);
    expect(second.json).toEqual({
      hookSpecificOutput: {
        hookEventName: 'UserPromptSubmit',
        additionalContext: SESSION_NOTICE_DONE,
      },
    });
    expectCodexAccepts('UserPromptSubmit', second.json!);
    expect(flagOf(where.home, 'cx-close')).toBe('standard');
    expect(run(where, userPrompt(where, 'cx-close', 'third')).stdout).toBe('');
  });

  itUnix('an allowed tool call after SessionStart says nothing', () => {
    const where = makeHome('tool-after');
    run(where, sessionStart(where, 'cx-ta'), CODEX);
    run(where, userPrompt(where, 'cx-ta'));
    const r = run(where, preToolUse(where, 'cx-ta'));
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
  });
});

describe('Codex session notice: PreToolUse fallback', () => {
  itUnix('without SessionStart, the first allowed Codex call carries the notice', () => {
    const where = makeHome('fallback');
    const r = run(where, preToolUse(where, 'cx-fb'));
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
    expect(r.json).toEqual({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        additionalContext: `${STANDARD}\n${SESSION_NOTICE_ASK}`,
      },
      systemMessage: STANDARD,
    });
    expectCodexAccepts('PreToolUse', r.json!);
    expect(run(where, preToolUse(where, 'cx-fb', 'pwd')).stdout).toBe('');
    // A tool call's notice opens in reply 1: the next prompt closes it.
    expect(run(where, userPrompt(where, 'cx-fb')).json).not.toBeNull();
  });

  itUnix('a level change mid-session reaches Codex on the next allowed call', () => {
    const where = makeHome('fallback-change');
    run(where, sessionStart(where, 'cx-fc'), CODEX);
    run(where, userPrompt(where, 'cx-fc'));
    setMode(where.home, 'audit');
    const r = run(where, preToolUse(where, 'cx-fc'));
    expect(r.json?.systemMessage).toBe(CHANGED_AUDIT);
    expectCodexAccepts('PreToolUse', r.json!);
  });
});
