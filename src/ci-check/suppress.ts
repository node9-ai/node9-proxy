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
  return `${s.rule}\n${s.file}\n${s.locator ?? ''}`;
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
  if (!Array.isArray(raw)) return { active, notes, findings };
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
          `\`${entry.rule}\` in \`${entry.file}\`${entry.locator ? ` (${entry.locator})` : ''} is suppressed without saying why`,
          'Add a `reason`. A suppression is a reviewed decision; the review needs the why.',
          suppressionKey(entry)
        )
      );
      continue;
    }
    if (entry.expires) {
      const t = Date.parse(entry.expires);
      if (Number.isFinite(t) && t < today.getTime()) {
        notes.push(
          `suppression for \`${entry.rule}\` in \`${entry.file}\` expired ${entry.expires} — not applied.`
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
