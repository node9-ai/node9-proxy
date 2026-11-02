// src/notices/session-notice.ts
// fw#420 step 2: tell the user, once per agent session, that node9 is on and at
// which level. Nothing else told them: on 2026-10-30 a workspace sat at Audit
// (log only) unnoticed, and a dry run looked as if node9 did not work.
//
// The channel is systemMessage. 2.48.0 also asked the agent to quote the line
// at the top of its reply (the desktop app keeps systemMessage behind the
// collapsed tool row), but the instruction stays in the conversation and was
// obeyed in every later reply; measured 2026-11-02, see SESSION_NOTICE_NOTE.
// The agent now gets the line as context and is asked not to mention it.
// A level change mid-session gets one more notice.
//
// UX only: a failure here never changes the decision and never blocks.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { levelOf, type Level } from '@node9/policy-engine';
import { atomicWriteSync } from '../utils/atomic-write';
import {
  ensureOwnDir,
  isSameOwnDir,
  removeOldFlag,
  SESSION_FLAG_SUFFIX,
  type OwnDir,
} from '../utils/own-dir';

const ICON = '\u{1F6E1}\uFE0F';

const LEVEL_NAMES: Readonly<Record<Level, string>> = {
  audit: 'Audit',
  soft: 'Soft',
  standard: 'Standard',
  strict: 'Strict',
  'block-all': 'Block all',
};

// No quote instruction (fallback c of the notice-repeat design). Measured
// 2026-11-02 in Claude Code: with "show the line once ... leave it out of later
// replies" one session in five still opened all four replies with it, and a
// level-change line came back in the next reply. The line now reaches the user
// as systemMessage only; the agent is told the fact and asked not to mention it.
export const SESSION_NOTICE_NOTE =
  'node9 shows the user this line itself. Do not mention it unless the user asks about node9.';

/** What the hook says this call: the first notice of the session, a notice
 *  that the level changed, or nothing. */
export type SessionNoticeKind = 'first' | 'changed';

/** Session flags older than this are removed when a new session claims one. */
const FLAG_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const SAFE_SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** The line the user reads, for the level `settings.mode` names. A level
 *  change mid-session reads "level changed to ...". */
export function sessionNoticeLine(
  mode: string | undefined,
  kind: SessionNoticeKind = 'first'
): string {
  const level = levelOf(mode);
  const name = LEVEL_NAMES[level];
  if (kind === 'changed') {
    return level === 'audit'
      ? `${ICON} Node9 level changed to Audit: actions are logged, nothing is blocked.`
      : `${ICON} Node9 level changed to ${name}. Every action in this session is checked.`;
  }
  if (level === 'audit') {
    return `${ICON} Node9 is in Audit mode: actions are logged, nothing is blocked.`;
  }
  return `${ICON} Node9 is on (${name}). Every action in this session is checked.`;
}

/** The PreToolUse hook output that carries the notice on an ALLOWED call. No
 *  permissionDecision: the agent's own permission flow is untouched. */
export function sessionNoticeOutput(
  mode: string | undefined,
  kind: SessionNoticeKind = 'first'
): string {
  const line = sessionNoticeLine(mode, kind);
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      additionalContext: `${line}\n${SESSION_NOTICE_NOTE}`,
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

/** Longest flag content read back: a level name. */
const FLAG_MAX_BYTES = 32;

/**
 * Whether this call carries a notice. The flag file `<id>.node9-flag` holds
 * the level the session was last told about:
 * - no flag: create it (O_EXCL, so two concurrent hook calls cannot both
 *   win) with the level, and say 'first';
 * - a flag with another level: rewrite it (temp file and rename) and say
 *   'changed';
 * - the same level: nothing;
 * - an empty flag (written by 2.48.0, which kept no level): record the level
 *   without a notice, so an upgrade does not re-announce live sessions.
 * An unusable id or any filesystem error returns null: no notice is better
 * than one per call.
 */
export function claimSessionNotice(
  sessionId: string | undefined,
  home = os.homedir(),
  level: string = 'standard'
): SessionNoticeKind | null {
  if (!sessionId || !SAFE_SESSION_ID.test(sessionId)) return null;
  const dir = path.join(home, '.node9', 'notice-sessions');
  // The agent can reach ~/.node9 with mv and ln: a link here would point the
  // flag write and the clean-up below at a directory of its choosing.
  const seen = ensureOwnDir(dir);
  if (!seen) return null;
  const flag = path.join(dir, sessionId + SESSION_FLAG_SUFFIX);
  let created = false;
  try {
    if (!isSameOwnDir(dir, seen)) return null;
    const fd = fs.openSync(flag, 'wx', 0o600);
    created = true;
    try {
      fs.writeSync(fd, level);
    } finally {
      fs.closeSync(fd);
    }
  } catch (err) {
    // A flag created but not written would read later as a 2.48.0 flag and
    // swallow the session's first notice: remove it.
    if (created) {
      try {
        fs.unlinkSync(flag);
      } catch {
        /* best effort */
      }
      return null;
    }
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') return null;
    return levelChange(dir, seen, flag, level);
  }
  removeOldFlags(dir, seen);
  return 'first';
}

/** The flag exists: 'changed' when it holds another level (and now holds this
 *  one), null otherwise. Only a regular file with one name is read. */
function levelChange(dir: string, seen: OwnDir, flag: string, level: string): 'changed' | null {
  try {
    const told = readFlag(flag);
    if (told === null) return null;
    if (told === level) return null;
    if (!isSameOwnDir(dir, seen)) return null;
    atomicWriteSync(flag, level, { mode: 0o600 });
    return told === '' ? null : 'changed';
  } catch {
    return null;
  }
}

/** The level a flag holds, or null when it is not a small regular file with
 *  one name. Read through one descriptor opened without following a link and
 *  without blocking, so a link or FIFO swapped in after a check cannot stall
 *  the hook or make it read a large file. */
function readFlag(flag: string): string | null {
  const c = fs.constants;
  const lst = fs.lstatSync(flag);
  if (!lst.isFile()) return null;
  const fd = fs.openSync(flag, c.O_RDONLY | (c.O_NOFOLLOW ?? 0) | (c.O_NONBLOCK ?? 0));
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.nlink !== 1 || st.size > FLAG_MAX_BYTES) return null;
    const buf = Buffer.alloc(FLAG_MAX_BYTES);
    const n = fs.readSync(fd, buf, 0, FLAG_MAX_BYTES, 0);
    return buf.toString('utf8', 0, n).trim();
  } finally {
    fs.closeSync(fd);
  }
}

/** Removes old flag files only: regular files named `<id>.node9-flag`, and
 *  only while the directory is still the one that was checked. */
function removeOldFlags(dir: string, seen: OwnDir): void {
  const cutoff = Date.now() - FLAG_TTL_MS;
  try {
    for (const name of fs.readdirSync(dir)) removeOldFlag(dir, seen, name, cutoff);
  } catch {
    /* best effort */
  }
}
