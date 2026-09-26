// src/ci-check/suppress.ts
// A committed `.node9-ignore.json`: the team's way to say "this finding is known and
// accepted". Every scanner is wrong sometimes; with no way to say so, the whole tool gets
// muted.
//
// The file is part of the committed agent surface, so it is attacker-controlled input like
// everything else the scanner reads. That gives it one security property, enforced in
// diff.ts, not here: a suppression that did not exist in the base does not apply to a finding
// introduced in the same change. Here: parse, validate, and mark. A suppressed finding is
// never deleted from the output — it is marked, counted, and kept out of `worst`.

import type { CiFinding, Severity } from './types';

export const SUPPRESSIONS_FILE = '.node9-ignore.json';

/** More entries than any team reviews by hand. Over it the file is treated as malformed and
 *  NOTHING is honoured: a 200,000-entry file once overflowed the stack, killed the CLI, and
 *  the Action then failed open (review H.1, 2026-09-27). */
export const MAX_SUPPRESSIONS = 1000;

export interface Suppression {
  /** Stable rule id, e.g. `CI-3.mcp-unpinned`. */
  rule: string;
  /** Repo-relative file the finding anchors to. */
  file: string;
  /** The finding's locator (an MCP server name, a hook command). Absent = any locator of
   *  that rule in that file. */
  locator?: string;
  /** Required. An entry without one does not suppress and is itself reported. */
  reason: string;
  /** ISO date. Past → the entry is ignored and noted. */
  expires?: string;
}

/** Readable identity: rule + file + locator. Deliberately NOT the fingerprint — a file a
 *  person edits must be a file a person can read. A rename ends a suppression; that is
 *  the correct failure direction. */
export function suppressionKey(s: { rule: string; file: string; locator?: string }): string {
  // `null`, not `''`: an entry with `locator: ""` matches nothing and must not share a key
  // with an entry that has no locator and matches everything (review H.7).
  return JSON.stringify([s.rule, s.file, s.locator ?? null]);
}

/** A value read from the file, made safe to put inside a backtick span in a signal or a PR
 *  comment: one line, no backtick, bounded. The file is attacker-controlled (review H.6). */
export function safeText(v: unknown, max = 120): string {
  return String(v)
    .replace(/[\r\n\u2028\u2029]+/g, ' ')
    .replace(/`/g, "'")
    .slice(0, max);
}

function mk(
  rule: string,
  severity: Severity,
  title: string,
  signal: string,
  fix: string,
  locator?: string
): CiFinding {
  return {
    check: 'CI-0',
    rule,
    dimension: 'files',
    severity,
    title,
    file: SUPPRESSIONS_FILE,
    ...(locator ? { locator } : {}),
    signals: [signal],
    fix,
  };
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** Midnight UTC of a real `YYYY-MM-DD` date, or null. Round-trips to reject `2026-02-30`. */
function isoDay(v: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return null;
  const t = Date.parse(`${v}T00:00:00Z`);
  if (!Number.isFinite(t)) return null;
  return new Date(t).toISOString().slice(0, 10) === v ? t : null;
}

/** Parse the file. Pure, never throws: a malformed file suppresses nothing and is reported
 *  as such; an entry without a reason suppresses nothing and is reported as such; an
 *  expired entry suppresses nothing and is noted with its date. */
export function parseSuppressions(
  content: string,
  today: Date
): { active: Suppression[]; notes: string[]; findings: CiFinding[] } {
  const active: Suppression[] = [];
  const notes: string[] = [];
  const findings: CiFinding[] = [];
  let raw: unknown;
  try {
    raw = JSON.parse(content);
  } catch {
    findings.push(
      mk(
        'CI-0.suppression-malformed',
        'advisory',
        'Suppression file is not valid JSON — nothing is suppressed',
        `${SUPPRESSIONS_FILE} could not be parsed`,
        'Fix the JSON. Until then every finding is reported as if the file were absent.'
      )
    );
    return { active, notes, findings };
  }
  if (!Array.isArray(raw) || raw.length > MAX_SUPPRESSIONS) {
    findings.push(
      mk(
        'CI-0.suppression-malformed',
        'advisory',
        Array.isArray(raw)
          ? `Suppression file has more than ${MAX_SUPPRESSIONS} entries — nothing is suppressed`
          : 'Suppression file is not a list of entries — nothing is suppressed',
        Array.isArray(raw)
          ? `${raw.length} entries in ${SUPPRESSIONS_FILE}`
          : `${SUPPRESSIONS_FILE} must be a JSON array of { rule, file, locator?, reason, expires? }`,
        'Fix the file. Until then every finding is reported as if the file were absent.'
      )
    );
    return { active, notes, findings };
  }
  for (const e of raw) {
    if (!e || typeof e !== 'object') continue;
    const s = e as Record<string, unknown>;
    if (typeof s.rule !== 'string' || typeof s.file !== 'string') continue;
    const entry: Suppression = {
      rule: s.rule,
      file: s.file,
      ...(typeof s.locator === 'string' ? { locator: s.locator } : {}),
      reason: typeof s.reason === 'string' ? s.reason.trim() : '',
      ...(typeof s.expires === 'string' ? { expires: s.expires } : {}),
    };
    if (!entry.reason) {
      findings.push(
        mk(
          'CI-0.suppression-unjustified',
          'advisory',
          'Suppression entry has no reason — not applied',
          `\`${safeText(entry.rule)}\` in \`${safeText(entry.file)}\`${entry.locator ? ` (\`${safeText(entry.locator)}\`)` : ''} is suppressed without saying why`,
          'Add a `reason`. A suppression is a reviewed decision; the review needs the why.',
          suppressionKey(entry)
        )
      );
      continue;
    }
    if (s.expires !== undefined) {
      // Only a calendar date, and it must be a real one: `2026-13-45`, `never` or a number
      // used to leave the entry active forever, silently (review H.8).
      const t = typeof s.expires === 'string' ? isoDay(s.expires) : null;
      if (t === null) {
        findings.push(
          mk(
            'CI-0.suppression-invalid-expiry',
            'advisory',
            'Suppression entry has an invalid expiry — not applied',
            `\`${safeText(entry.rule)}\` in \`${safeText(entry.file)}\`: expires must be a date written YYYY-MM-DD`,
            'Write the expiry as YYYY-MM-DD, or remove it.',
            suppressionKey(entry)
          )
        );
        continue;
      }
      // An entry is good through the END of the day it names.
      if (t + DAY_MS <= today.getTime()) {
        notes.push(
          `suppression for \`${safeText(entry.rule)}\` in \`${safeText(entry.file)}\` expired ${entry.expires} — not applied.`
        );
        continue;
      }
    }
    active.push(entry);
  }
  return { active, notes, findings };
}

/** Mark every finding an active entry covers. Mutates; never removes. The matched entry's
 *  key travels with the finding so the diff can ask "did this suppression exist before?". */
export function applySuppressions(findings: CiFinding[], active: Suppression[]): number {
  let n = 0;
  for (const f of findings) {
    // The file's own findings are never suppressible: `CI-0.suppression-unjustified` could
    // otherwise silence itself (review H.9).
    if (f.check === 'CI-0') continue;
    const hit = active.find(
      (s) =>
        s.rule === f.rule &&
        s.file === f.file &&
        (s.locator === undefined || s.locator === (f.locator ?? ''))
    );
    if (!hit) continue;
    f.suppressed = {
      reason: hit.reason,
      key: suppressionKey(hit),
      ...(hit.expires ? { expires: hit.expires } : {}),
    };
    n++;
  }
  return n;
}
