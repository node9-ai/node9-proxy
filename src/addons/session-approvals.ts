// src/addons/session-approvals.ts
// An add-on a person approved in this agent session (node9Firewall#376 item 6,
// under the `review` rule): the next uses of it in the same session are not
// asked about again. The MCP gateway keeps the same promise in memory (one
// card per server connection); the hook is a new process per call, so it keeps
// it in a small file per session. A block is never remembered here, and a new
// session asks again.
//
// ~/.node9/addon-sessions/<session id>.json, written only in a real directory
// of this user (a link planted under ~/.node9 is not followed). Best effort:
// any failure means "not approved yet", so the person is asked.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { ensureOwnDir, isSameOwnDir } from '../utils/own-dir';

const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_RULES = 200;
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

function dirOf(home: string): string {
  return path.join(home, '.node9', 'addon-sessions');
}

function readRules(file: string): string[] {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size > 64 * 1024) return [];
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as { rules?: unknown };
    return Array.isArray(raw.rules)
      ? raw.rules.filter((r): r is string => typeof r === 'string')
      : [];
  } catch {
    return [];
  }
}

/** Did a person approve this add-on (`ruleName`, `addon:<type>:<name>`)
 *  earlier in this session? */
export function addonApprovedForSession(
  sessionId: string | undefined,
  ruleName: string,
  home: string = os.homedir()
): boolean {
  if (!sessionId || !SESSION_ID.test(sessionId)) return false;
  return readRules(path.join(dirOf(home), `${sessionId}.json`)).includes(ruleName);
}

/** Remember that a person approved this add-on for the rest of the session. */
export function approveAddonForSession(
  sessionId: string | undefined,
  ruleName: string,
  home: string = os.homedir()
): void {
  if (!sessionId || !SESSION_ID.test(sessionId) || !ruleName) return;
  const dir = dirOf(home);
  const own = ensureOwnDir(dir);
  if (!own) return;
  const file = path.join(dir, `${sessionId}.json`);
  const rules = readRules(file);
  if (rules.includes(ruleName)) return;
  try {
    if (!isSameOwnDir(dir, own)) return;
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ rules: [...rules, ruleName].slice(-MAX_RULES) }), {
      mode: 0o600,
    });
    fs.renameSync(tmp, file);
  } catch {
    /* not remembered: the person is asked again */
  }
  // Old sessions' files go after a week.
  try {
    const cutoff = Date.now() - MAX_AGE_MS;
    for (const name of fs.readdirSync(dir)) {
      if (!/^[A-Za-z0-9_-]{1,128}\.json$/.test(name)) continue;
      const p = path.join(dir, name);
      const st = fs.lstatSync(p);
      if (st.isFile() && st.mtimeMs < cutoff && isSameOwnDir(dir, own)) fs.unlinkSync(p);
    }
  } catch {
    /* clean-up is best effort */
  }
}
