// src/ci-check/tier.ts
// ONE answer to "does this finding count" (§Q). A quality study of 768 public repositories labeled
// every content finding (instruction prose, and the scripts an agent runs): 394 findings, 0 true —
// a pattern cannot tell an instruction to the agent from an install note, a quoted attack or a test.
// The structural rules carried the value (injectable workflow at medium and up: 15 of 15 true). So:
//   alert  — counted: the result (`worst`), the exit code, fail-on, CI-5's introduced severity.
//   review — listed under "Worth a look", said plainly to be uncertain; never counted.
//   note   — information (a gated workflow, a file too large to read); never counted.
// Concealment is the exception among content rules: hidden characters have no legitimate use in an
// instruction file, so they stay alerts.

import type { CiFinding } from './types';

export type Tier = 'alert' | 'review' | 'note';

// A script the scan did not read: listed for a person to check, never shown as clean.
const UNREAD_RULES = new Set([
  'CI-1.hook-script-unscanned',
  'CI-1.hook-script.unscanned-size',
  'CI-6.skill-script.unscanned-size',
]);
const CONCEALMENT = new Set(['CI-6.unicode-tag-chars', 'CI-6.bidi-override']);

export function tierOf(f: Pick<CiFinding, 'rule' | 'severity'>): Tier {
  const { rule, severity } = f;
  // Accurate, but for most skills it is what the skill needs: summarized, never counted.
  if (rule === 'CI-1.skill-allowed-tools') return 'review';
  if (UNREAD_RULES.has(rule)) return 'review';
  // The workflow checks already grade a gated workflow down to advisory (28 of 30 false as alerts).
  if (rule.startsWith('CI-2.') || rule.startsWith('CI-4.'))
    return severity === 'advisory' ? 'note' : 'alert';
  // Hidden characters in an instruction file. In a script they are listed for review: across 768
  // repositories the only ones were a security tool's own detection regexes (7 of 7 false).
  if (CONCEALMENT.has(rule)) return 'alert';
  // Critical only when concealed: an override decoded from base64, or revealed by stripping
  // zero-width characters. A plain phrase is usually a quoted example.
  if (rule === 'CI-6.prompt-override' || rule === 'CI-6.zero-width')
    return severity === 'critical' ? 'alert' : 'review';
  if (rule.startsWith('CI-6.') || rule.startsWith('CI-1.hook-script')) return 'review';
  return 'alert';
}

/** Counted in the result. A finding without a tier (an older CLI's output) counts. */
export const isAlert = (f: Pick<CiFinding, 'tier'>): boolean => !f.tier || f.tier === 'alert';

/** Listed under "Worth a look": review items that are not suppressed. Skill grants are summarized. */
export const isReviewItem = (f: Pick<CiFinding, 'tier' | 'suppressed'>): boolean =>
  f.tier === 'review' && !f.suppressed;
export const GRANT_RULE = 'CI-1.skill-allowed-tools';
export const REVIEW_FILES = 10;
export const REVIEW_LINES_PER_FILE = 3;

/** One check question per kind of review item, so a reviewer knows what to look for. The action's
 *  comment.js carries the same wording. */
export function reviewQuestion(rule: string): string {
  if (/fetch-and-obey|remote-exec/.test(rule))
    return "Is the agent told to run this, or is it a note for a person? Is the source the vendor's own?";
  if (/prompt-override/.test(rule)) return 'Is this aimed at the model, or quoted as an example?';
  if (/exfil/.test(rule)) return "Where does the data go: your own service, or someone else's?";
  if (/secret/.test(rule))
    return 'Is the agent asked to read or send the file, or is it only named?';
  if (/hook-script-missing/.test(rule))
    return 'Does this hook exist on every machine that runs it?';
  if (/hidden-chars/.test(rule))
    return 'Why does this script hold invisible characters? A list of them to detect is fine.';
  if (/unscanned/.test(rule))
    return 'node9 did not read this script (too large, or outside the folders it reads). What does it run?';
  return 'Is this an instruction the agent follows, or text for a person?';
}

const RANK = { critical: 4, high: 3, medium: 2, advisory: 1 } as const;
const worstRank = (fs: CiFinding[]): number => Math.max(...fs.map((f) => RANK[f.severity] ?? 0));
/** The files most worth opening first: the worst item, then the most items. Stable otherwise. */
const fileOrder = (a: [string, CiFinding[]], b: [string, CiFinding[]]): number =>
  worstRank(b[1]) - worstRank(a[1]) || b[1].length - a[1].length;

/** Review items grouped per file, in first-seen order; skill grants apart. */
export function groupReview(findings: CiFinding[]): {
  byFile: Map<string, CiFinding[]>;
  grants: number;
} {
  const byFile = new Map<string, CiFinding[]>();
  let grants = 0;
  for (const f of findings) {
    if (!isReviewItem(f)) continue;
    if (f.rule === GRANT_RULE) {
      grants++;
      continue;
    }
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file)!.push(f);
  }
  return { byFile: new Map([...byFile].sort(fileOrder)), grants };
}
