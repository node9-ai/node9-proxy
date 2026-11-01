// src/notices/session-notice.ts
// fw#420 step 2: tell the user, once per agent session, that node9 is on and at
// which level. Nothing else told them: on 2026-10-30 a workspace sat at Audit
// (log only) unnoticed, and a dry run looked as if node9 did not work.
//
// The channel is the agent's reply, not systemMessage: the Claude desktop app
// keeps a hook's systemMessage behind the collapsed tool row. Measured
// 2026-10-30 (Claude Code 2.1.280, Opus 5.5): PreToolUse additionalContext on
// the first allowed call put the line at the top of the reply 3 of 3 times;
// UserPromptSubmit context only 1 of 3. systemMessage is added as well, for
// the CLI, where it is shown.
//
// UX only: a failure here never changes the decision and never blocks.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { levelOf, type Level } from '@node9/policy-engine';

const ICON = '\u{1F6E1}\uFE0F';

const LEVEL_NAMES: Readonly<Record<Level, string>> = {
  audit: 'Audit',
  soft: 'Soft',
  standard: 'Standard',
  strict: 'Strict',
  'block-all': 'Block all',
};

export const SESSION_NOTICE_INSTRUCTION =
  'Start your next reply to the user with the line above, exactly as written, on its own line.';

/** Session flags older than this are removed when a new session claims one. */
const FLAG_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const SAFE_SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** The line the user reads, for the level `settings.mode` names. */
export function sessionNoticeLine(mode: string | undefined): string {
  const level = levelOf(mode);
  if (level === 'audit') {
    return `${ICON} Node9 is in Audit mode: actions are logged, nothing is blocked.`;
  }
  return `${ICON} Node9 is on (${LEVEL_NAMES[level]}). Every action in this session is checked.`;
}

/** The PreToolUse hook output that carries the notice on an ALLOWED call. No
 *  permissionDecision: the agent's own permission flow is untouched. */
export function sessionNoticeOutput(mode: string | undefined): string {
  const line = sessionNoticeLine(mode);
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      additionalContext: `${line}\n${SESSION_NOTICE_INSTRUCTION}`,
    },
    systemMessage: line,
  });
}

/** NODE9_TESTING=1 turns off node9's UI in tests (approvers, popups); the
 *  notice is UI too, so tests that read an allowed call's empty stdout keep
 *  working. NODE9_SESSION_NOTICE=1 turns it back on for the test of the notice. */
export function sessionNoticeEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.NODE9_SESSION_NOTICE === '1') return true;
  return env.NODE9_TESTING !== '1';
}

/** True exactly once per session id: the first caller creates the flag file
 *  (O_EXCL, so two concurrent hook calls cannot both win). An unusable id or
 *  any filesystem error returns false: no notice is better than one per call. */
export function claimSessionNotice(sessionId: string | undefined, home = os.homedir()): boolean {
  if (!sessionId || !SAFE_SESSION_ID.test(sessionId)) return false;
  const dir = path.join(home, '.node9', 'notice-sessions');
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.closeSync(fs.openSync(path.join(dir, sessionId), 'wx'));
  } catch {
    return false;
  }
  removeOldFlags(dir);
  return true;
}

function removeOldFlags(dir: string): void {
  const cutoff = Date.now() - FLAG_TTL_MS;
  try {
    for (const name of fs.readdirSync(dir)) {
      const p = path.join(dir, name);
      try {
        if (fs.statSync(p).mtimeMs < cutoff) fs.unlinkSync(p);
      } catch {
        /* another hook removed it, or it is unreadable: leave it */
      }
    }
  } catch {
    /* best effort */
  }
}
