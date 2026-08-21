import { describe, it, expect } from 'vitest';
import { SENSITIVE_PATH_RULES, PATH_SEGMENT_SENTINEL as SENT } from './index';

// #51 — a path is not gone because part of it is a variable.
//
// `extractLiteralArgs` discards an ENTIRE command argument the moment any part
// of it is dynamic. `$HOME` is a ParamExp, so `cat $HOME/.ssh/id_rsa` reaches
// the sensitive-path matcher with no path at all, and is allowed — while
// `cat ~/.ssh/id_rsa`, the same file, blocks. Same shape as the rest of this
// arc: a null meaning "I could not resolve this" read as "there is nothing
// here".
//
// Proof it is a bug and not a scope question: isProtectedHomePath ALREADY
// handles `$HOME` and `${HOME}` and returns the right answer for both. That
// branch has simply never been reachable, because the extractor throws the
// argument away first.
//
// The fix resolves the literal segments and substitutes a SENTINEL for the
// unknown ones. The two describes below are the two halves of that claim, and
// the first is the one that keeps the second honest.

describe('the invariant the sentinel rests on: every matcher is anchored', () => {
  // This is the load-bearing spec of #51, and it exists because the safety of
  // the whole fix reduces to one property of rules written elsewhere: a
  // sensitive segment must be preceded by `^` or a separator.
  //
  // If a future rule lands unanchored, `$PREFIX.env` starts reading as a .env
  // file, the widening stops being self-limiting, and nothing else in the
  // suite notices. So the property is asserted over the LIVE rule set rather
  // than described in a comment.

  // One path per rule that it genuinely matches today. Kept minimal on
  // purpose: the point is the anchoring transform, not the coverage.
  const SAMPLES: Array<[string, string]> = [
    ['ssh', 'home/u/.ssh/id_rsa'],
    ['aws', 'home/u/.aws/credentials'],
    ['env', 'app/.env'],
    ['credentials', 'home/u/.netrc'],
  ];

  it('exercises every rule in the live set (guards against a vacuous pass)', () => {
    // If a rule is added and no sample matches it, the loop below would silently
    // skip it — the exact failure this arc keeps finding.
    const covered = SENSITIVE_PATH_RULES.filter((r) => SAMPLES.some(([, p]) => r.match(p)));
    expect(
      covered.length,
      'a SENSITIVE_PATH_RULES entry has no sample here — add one, or the anchoring ' +
        'invariant is unasserted for that rule'
    ).toBe(SENSITIVE_PATH_RULES.length);
  });

  it.each(SAMPLES)('%s: an unknown prefix WITHOUT a separator must not BLOCK', (_n, sample) => {
    // `$PREFIX.env` → `<NUL>.env`. We do not know what $PREFIX holds.
    //
    // The first run of this spec refuted the stronger claim it originally made
    // ("no matcher fires"): review-read-credentials matches a filename SUFFIX
    // (`…\.netrc$`) and is anchored only at the END, so `<NUL>.netrc` does fire.
    //
    // That is not a defect to paper over, and the fix is NOT to edit the rule —
    // anchoring it would silently stop covering `backup.netrc`, which is a
    // calibration decision and not part of this bug. The correct invariant is
    // about CONSEQUENCE:
    //
    //   verdict 'block'  → MUST be separator-anchored. An over-fire from an
    //                      unknown prefix would stop legitimate work with no
    //                      local recourse.
    //   verdict 'review' → may match loosely. An over-fire costs a human
    //                      prompt, which is already this rule's own answer.
    //
    // The live set partitions exactly along that line — the three block rules
    // are anchored, the one loose matcher is the one whose author chose
    // 'review'. This row fails the moment a future BLOCK rule is written
    // unanchored, which is the case that actually hurts.
    const tail = sample.slice(sample.lastIndexOf('/') + 1);
    const blockers = SENSITIVE_PATH_RULES.filter(
      (r) => r.match(SENT + tail) && (r.verdict ?? 'block') === 'block'
    );
    expect(
      blockers.map((r) => r.rule),
      `"${SENT + tail}" hit a BLOCK matcher that is not anchored on ^ or a separator — ` +
        'a dynamic prefix would be read as a real path and stop the user with no recourse'
    ).toEqual([]);
  });

  it.each(SAMPLES)('%s: an unknown prefix WITH a literal separator must match', (_n, sample) => {
    // `$HOME/.ssh/id_rsa` → `<NUL>/.ssh/id_rsa`. The separator is literal, so
    // the sensitive segment is genuinely present and must still be seen.
    const idx = sample.indexOf('/');
    const withSep = SENT + sample.slice(idx);
    expect(
      SENSITIVE_PATH_RULES.some((r) => r.match(withSep)),
      `"${withSep}" did not match, so substituting a sentinel would LOSE a real hit`
    ).toBe(true);
  });

  it('records WHICH matchers over-fire on an unknown prefix, so growth is visible', () => {
    // The loose set is allowed but never silent. If a second matcher joins it —
    // or the existing one changes verdict — this row fails and someone decides
    // deliberately instead of discovering it in production.
    const loose = SENSITIVE_PATH_RULES.filter((r) => r.match(SENT + '.netrc')).map((r) => ({
      rule: r.rule,
      verdict: r.verdict ?? 'block',
    }));
    expect(loose).toEqual([
      { rule: 'shield:project-jail:review-read-credentials', verdict: 'review' },
    ]);
  });

  it('rules out the obvious alternative: deleting the dynamic part', () => {
    // Simply dropping `$PREFIX` turns `$PREFIX.env` into `.env`, which every
    // anchored matcher accepts via its `^` branch. Pinned so nobody "simplifies"
    // the sentinel away — this is the measurement that chose the design.
    expect(SENSITIVE_PATH_RULES.some((r) => r.match('.env'))).toBe(true);
    expect(SENSITIVE_PATH_RULES.some((r) => r.match(SENT + '.env'))).toBe(false);
  });
});
