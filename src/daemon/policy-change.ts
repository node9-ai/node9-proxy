// src/daemon/policy-change.ts
// What a policy sync changed, in words a person can check against the
// dashboard (node9-proxy#506). `node9 policy sync` printed only a rule count,
// so a change of level or of an add-on decision was invisible; and the daemon
// usually syncs first (a heartbeat every 5 minutes picks a change up), so the
// manual sync then gets a 304 and has nothing to compare. Every sync writes
// the policy through one function (sync.ts writeCache), which compares the
// old cache with the new one here and keeps the lines of the last change in
// ~/.node9/policy-last-change.json for the command to show.
//
// Daemon and CLI only: the hook never loads this file. Nothing here throws.

import os from 'os';
import path from 'path';
import { levelOf } from '@node9/policy-engine';
import { atomicWriteSync } from '../utils/atomic-write';
import { readSmallFile } from '../utils/read-small-file';

/** The parts of the policy cache compared (sync.ts RulesCache), read loosely:
 *  the old cache is whatever an earlier version left on disk. */
type Cache = Record<string, unknown>;

export interface PolicyChangeRecord {
  /** When the sync that changed something ran (ISO-8601). */
  at: string;
  lines: string[];
}

/** Decisions listed one by one before the rest is counted. */
const MAX_DECISION_LINES = 6;
const MAX_LINES = 20;
const MAX_NAME = 80;
const MAX_RECORD_BYTES = 64 * 1024;
/** The one line for settings this module does not name. */
const OTHER_SETTINGS = 'Other settings changed';
/** A record this far ahead of the clock is still read: clocks get stepped. */
const CLOCK_SLACK_MS = 5 * 60_000;
/** A stored change older than this is not news any more. */
export const LAST_CHANGE_MAX_AGE_MS = 24 * 60 * 60_000;

export function policyChangePath(home: string = os.homedir()): string {
  return path.join(home, '.node9', 'policy-last-change.json');
}

function rec(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

/** Text from the server, safe on a terminal line. */
function clean(v: string): string {
  const s = v.replace(/\p{Cc}/gu, ' ').trim();
  return s.length > MAX_NAME ? `${s.slice(0, MAX_NAME)}...` : s;
}

/** JSON with sorted keys, so two caches that differ only in key order match. */
function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stable(o[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

/** The level a cache sets, in the words `node9 status` uses. */
export function levelWord(cache: Cache | null): string {
  const mode = rec(cache?.managedConfig).mode;
  return levelOf(typeof mode === 'string' ? mode : undefined);
}

const UNAPPROVED_WORDS: Record<string, string> = {
  off: 'allow, no alerts',
  log: 'allow and alert',
  review: 'ask a person',
  block: 'block until approved',
};

function unapprovedOf(cache: Cache | null): string | undefined {
  const v = rec(rec(cache?.managedConfig).addons).unapproved;
  return typeof v === 'string' ? v : undefined;
}

function unapprovedWord(v: string | undefined): string {
  return v !== undefined && Object.hasOwn(UNAPPROVED_WORDS, v) ? UNAPPROVED_WORDS[v] : 'not set';
}

/** Every add-on decision of a cache as `<kind> <name>` -> decision. A skill
 *  or plugin decision carries the versions it covers; a change of those is a
 *  change too, so they are part of the value compared, not of the word shown. */
function decisionsOf(cache: Cache | null): Map<string, { word: string; whole: string }> {
  const out = new Map<string, { word: string; whole: string }>();
  const addons = rec(rec(cache?.managedConfig).addons);
  const kinds: Array<[string, string]> = [
    ['mcp', 'MCP server'],
    ['skills', 'skill'],
    ['plugins', 'plugin'],
  ];
  for (const [field, kind] of kinds) {
    for (const [name, raw] of Object.entries(rec(addons[field]))) {
      const word = typeof raw === 'string' ? raw : rec(raw).decision;
      if (typeof word !== 'string') continue;
      out.set(`${kind} ${clean(name)}`, { word: clean(word), whole: stable(raw) });
    }
  }
  return out;
}

function namesOf(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/**
 * The lines for what differs between two policy caches, most important
 * first. Empty when nothing a person would name changed, and when there is no
 * earlier cache (a first sync has nothing to compare with).
 */
export function policyChangeLines(prev: Cache | null, next: Cache): string[] {
  if (!prev) return [];
  const lines: string[] = [];
  try {
    const onOff = (v: unknown) => (v === true ? 'on' : 'off');
    if ((prev.panicMode === true) !== (next.panicMode === true))
      lines.push(`Panic mode: ${onOff(prev.panicMode)} → ${onOff(next.panicMode)}`);
    const [levelBefore, levelNow] = [levelWord(prev), levelWord(next)];
    if (levelBefore !== levelNow) lines.push(`Level: ${levelBefore} → ${levelNow}`);
    if ((prev.shadowMode === true) !== (next.shadowMode === true))
      lines.push(`Shadow mode: ${onOff(prev.shadowMode)} → ${onOff(next.shadowMode)}`);

    const [ruleBefore, ruleNow] = [unapprovedOf(prev), unapprovedOf(next)];
    if (ruleBefore !== ruleNow)
      lines.push(
        `Add-ons nobody approved: ${unapprovedWord(ruleBefore)} → ${unapprovedWord(ruleNow)}`
      );

    const [before, now] = [decisionsOf(prev), decisionsOf(next)];
    const decisions: string[] = [];
    for (const name of new Set([...before.keys(), ...now.keys()])) {
      const [a, b] = [before.get(name), now.get(name)];
      if (a?.whole === b?.whole) continue;
      decisions.push(
        a?.word === b?.word
          ? `${name}: ${b?.word ?? 'no decision'}, the versions it covers changed`
          : `${name}: ${a?.word ?? 'no decision'} → ${b?.word ?? 'no decision'}`
      );
    }
    decisions.sort();
    lines.push(...decisions.slice(0, MAX_DECISION_LINES));
    if (decisions.length > MAX_DECISION_LINES)
      lines.push(`and ${decisions.length - MAX_DECISION_LINES} more add-on decisions`);

    const [rulesBefore, rulesNow] = [
      Array.isArray(prev.rules) ? prev.rules : [],
      Array.isArray(next.rules) ? next.rules : [],
    ];
    if (rulesBefore.length !== rulesNow.length)
      lines.push(`Custom rules: ${rulesBefore.length} → ${rulesNow.length}`);
    else if (stable(rulesBefore) !== stable(rulesNow)) lines.push('Custom rules changed');

    const [shieldsBefore, shieldsNow] = [namesOf(prev.shields), namesOf(next.shields)];
    const added = shieldsNow.filter((s) => !shieldsBefore.includes(s)).map(clean);
    const removed = shieldsBefore.filter((s) => !shieldsNow.includes(s)).map(clean);
    if (added.length > 0) lines.push(`Shields added: ${added.slice(0, 8).join(', ')}`);
    if (removed.length > 0) lines.push(`Shields removed: ${removed.slice(0, 8).join(', ')}`);

    // The spend budget's level and month are a status the server works out
    // (how much of the month's limit is used), not a setting somebody changed.
    const spend = (c: Cache) => rec(rec(c.managedConfig).spendBudget);
    const [spentBefore, spentNow] = [spend(prev).level, spend(next).level];
    if (typeof spentNow === 'number' && typeof spentBefore === 'number' && spentBefore !== spentNow)
      lines.push(`Spend budget used: ${spentBefore}% → ${spentNow}% of the limit`);

    // Everything else the workspace manages, as one line: naming each
    // setting here would need a second copy of the catalog.
    const rest = (c: Cache) => {
      const others: Record<string, unknown> = { ...rec(c.managedConfig) };
      for (const named of ['mode', 'addons', 'spendBudget']) delete others[named];
      return stable([others, spend(c).limitUSD ?? null, c.config ?? null]);
    };
    if (rest(prev) !== rest(next)) lines.push(OTHER_SETTINGS);
  } catch {
    /* a cache of an unexpected shape: say what was found so far */
  }
  return lines.slice(0, MAX_LINES);
}

/** The state a cache sets, for the line shown after every sync. */
export function policyStateLine(cache: Cache | null): string {
  if (!cache) return '';
  const parts = [`Level: ${levelWord(cache)}`];
  const rule = unapprovedOf(cache);
  if (rule !== undefined) parts.push(`add-ons nobody approved: ${unapprovedWord(rule)}`);
  let blocked = 0;
  for (const d of decisionsOf(cache).values()) if (d.word === 'blocked') blocked++;
  if (blocked > 0) parts.push(`${blocked} add-on${blocked === 1 ? '' : 's'} blocked`);
  return parts.join(' · ');
}

/** Keep the lines of a change for `node9 policy sync` to show. Best effort. */
export function recordPolicyChange(
  lines: string[],
  home: string = os.homedir(),
  now: number = Date.now()
): void {
  if (lines.length === 0) return;
  try {
    // A change this module cannot name does not replace a named one that is
    // still shown: the level somebody just set is what they look for, and
    // some settings in the cache move without anybody touching them.
    if (lines.every((l) => l === OTHER_SETTINGS) && readPolicyChange(home, now)) return;
    const record: PolicyChangeRecord = { at: new Date(now).toISOString(), lines };
    atomicWriteSync(policyChangePath(home), JSON.stringify(record), { mode: 0o600 });
  } catch {
    /* the sync itself already succeeded */
  }
}

/** The last recorded change, or null when there is none, it is too old, or
 *  the file is not one this module wrote. */
export function readPolicyChange(
  home: string = os.homedir(),
  now: number = Date.now()
): PolicyChangeRecord | null {
  try {
    const text = readSmallFile(policyChangePath(home), MAX_RECORD_BYTES, { noFollow: true });
    if (text === null) return null;
    const raw = rec(JSON.parse(text));
    const at = typeof raw.at === 'string' ? Date.parse(raw.at) : NaN;
    if (Number.isNaN(at) || at > now + CLOCK_SLACK_MS || now - at > LAST_CHANGE_MAX_AGE_MS)
      return null;
    const lines = namesOf(raw.lines)
      .slice(0, MAX_LINES)
      .map((l) => l.replace(/\p{Cc}/gu, ' ').slice(0, 300));
    return lines.length > 0 ? { at: new Date(at).toISOString(), lines } : null;
  } catch {
    return null;
  }
}
