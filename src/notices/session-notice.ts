// src/notices/session-notice.ts
// fw#420 step 2: tell the user, once per agent session, that node9 is on and at
// which level. Nothing else told them: on 2026-10-30 a workspace sat at Audit
// (log only) unnoticed, and a dry run looked as if node9 did not work.
//
// Two channels. systemMessage, which the CLI shows and the desktop app hides
// behind the collapsed tool row; and the agent, asked to open its next reply
// with the line (node9Firewall#442). That ask stays in the conversation, and
// 2.48.0 measured it obeyed in every later reply (one session in five, 2026-11-02),
// so the user's next prompt closes it: UserPromptSubmit tells the agent the line
// was shown. The prompt, not the next tool call: the first reply usually makes
// several calls before it writes any text, and a close sent on the second of
// them would land before the line was ever shown.
// A level change mid-session gets one more notice, closed the same way.
//
// UX only: a failure here never changes the decision and never blocks.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { levelOf, holdsSendsWithoutDaemon, type Level } from '@node9/policy-engine';
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

/** Asks the agent to show the line once; sent with it on an allowed call. */
export const SESSION_NOTICE_ASK =
  'Start your next reply to the user with the line above, exactly as written, then continue.';

/** Sent on the user's next prompt: the line is shown and stays out from now on. */
export const SESSION_NOTICE_DONE =
  'The node9 line was already shown to the user. Do not include it in this reply or any later one. ' +
  'If node9 sends a new node9 line later, show that one once, as it asks.';

/** Flag suffix while the agent has been asked for the line and the user's next
 *  prompt has not closed the ask yet. A flag without it is closed. */
const OPEN_MARK = '+open';

/** What the hook says this call: the first notice of the session, a notice
 *  that the level changed, one that the daemon stopped or came back
 *  (node9Firewall#445 follow-up), or nothing. */
export type SessionNoticeKind = 'first' | 'changed' | 'daemon';

/** Kept in the session flag after the level while the daemon stays down. */
export const NO_DAEMON_SUFFIX = ':no-daemon';

function daemonSentence(mode: string | undefined): string {
  return holdsSendsWithoutDaemon(mode)
    ? 'Sends to unknown addresses are held until it starts (node9 daemon start).'
    : 'Outside-content checks are off until it starts (node9 daemon start).';
}

/** Session flags older than this are removed when a new session claims one. */
const FLAG_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const SAFE_SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** The line the user reads, for the level `settings.mode` names. A level
 *  change mid-session reads "level changed to ...". */
export function sessionNoticeLine(
  mode: string | undefined,
  kind: SessionNoticeKind = 'first',
  daemonDown = false
): string {
  if (kind === 'daemon') {
    return daemonDown
      ? `${ICON} Node9: the daemon is not running. ${daemonSentence(mode)}`
      : `${ICON} Node9: the daemon is running again. Every action in this session is checked.`;
  }
  const line = levelLine(mode, kind);
  if (!daemonDown) return line;
  const sentence = daemonSentence(mode);
  return `${line} The node9 daemon is not running: ${sentence[0].toLowerCase()}${sentence.slice(1)}`;
}

function levelLine(mode: string | undefined, kind: 'first' | 'changed'): string {
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
  kind: SessionNoticeKind = 'first',
  daemonDown = false,
  /** A budget line due on the same call (node9Firewall#427), told with it. */
  extraLine: string | null = null
): string {
  const line = sessionNoticeLine(mode, kind, daemonDown);
  const shown = extraLine ? `${line}\n${extraLine}` : line;
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      additionalContext: `${shown}\n${SESSION_NOTICE_ASK}`,
    },
    systemMessage: shown,
  });
}

/** A budget line alone on an allowed call (node9Firewall#427): shown to the
 *  user, and given to the agent so it can wind down. No permissionDecision. */
export function budgetNoticeOutput(line: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      additionalContext: line,
    },
    systemMessage: line,
  });
}

/** The UserPromptSubmit hook output that closes an open notice. */
export function sessionNoticeClosedOutput(): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'UserPromptSubmit',
      additionalContext: SESSION_NOTICE_DONE,
    },
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
 * the level the session was last told about, with `+open` until the user's
 * next prompt closes the ask (closeSessionNotice):
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
      fs.writeSync(fd, level + OPEN_MARK);
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
function levelChange(
  dir: string,
  seen: OwnDir,
  flag: string,
  level: string
): 'changed' | 'daemon' | null {
  try {
    const content = readFlag(flag);
    if (content === null) return null;
    const told = content.endsWith(OPEN_MARK) ? content.slice(0, -OPEN_MARK.length) : content;
    if (told === level) return null;
    if (!isSameOwnDir(dir, seen)) return null;
    // A 2.48.0 flag (empty) records the level without a notice, so it stays
    // closed; every notice below asks for the line and waits for the close.
    atomicWriteSync(flag, told === '' ? level : level + OPEN_MARK, { mode: 0o600 });
    if (told === '') return null;
    // Only the daemon part moved (a flag of 2.48.1 to 2.51 holds the level alone).
    const levelPart = (v: string) => v.split(':')[0];
    return levelPart(told) === levelPart(level) ? 'daemon' : 'changed';
  } catch {
    return null;
  }
}

/**
 * The user's next prompt after a notice: true when the session's flag was open,
 * which it now no longer is. Called on UserPromptSubmit, so the agent is told
 * the line was shown before it writes the next reply. Any problem returns false:
 * at worst the agent shows the line once more.
 */
export function closeSessionNotice(sessionId: string | undefined, home = os.homedir()): boolean {
  if (!sessionId || !SAFE_SESSION_ID.test(sessionId)) return false;
  const dir = path.join(home, '.node9', 'notice-sessions');
  try {
    // Most prompts have nothing to close: no directory made, no checks run.
    if (!fs.existsSync(path.join(dir, sessionId + SESSION_FLAG_SUFFIX))) return false;
    const seen = ensureOwnDir(dir);
    if (!seen) return false;
    const flag = path.join(dir, sessionId + SESSION_FLAG_SUFFIX);
    const content = readFlag(flag);
    if (content === null || !content.endsWith(OPEN_MARK)) return false;
    if (!isSameOwnDir(dir, seen)) return false;
    atomicWriteSync(flag, content.slice(0, -OPEN_MARK.length), { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

/** The level a flag holds, or null when it is not a small regular file with
 *  one name. Read through one descriptor opened without following a link and
 *  without blocking, so a link or FIFO swapped in after a check cannot stall
 *  the hook or make it read a large file. */
function readFlag(flag: string): string | null {
  const c = fs.constants;
  // No lstat first: the checks run on the opened descriptor (CodeQL
  // js/file-system-race), and the open itself refuses a link and a FIFO wait.
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
