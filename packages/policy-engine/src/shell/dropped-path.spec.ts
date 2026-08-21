import { describe, it, expect } from 'vitest';
import {
  SENSITIVE_PATH_RULES,
  PATH_SEGMENT_SENTINEL as SENT,
  analyzeFsOperation,
  isRmCreatedInCommandCleanup,
} from './index';

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

const rank = { allow: 0, review: 1, block: 2 } as const;
function verdictOf(command: string): 'allow' | 'review' | 'block' {
  const v = analyzeFsOperation(command);
  return v ? v.verdict : 'allow';
}
function ruleOf(command: string): string {
  return analyzeFsOperation(command)?.ruleName ?? '';
}

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

describe('#51 must-fire — the same file, a different spelling', () => {
  it.each([
    ['$HOME/.ssh/id_rsa', 'cat $HOME/.ssh/id_rsa', 'block'],
    ['${HOME} braces', 'cat ${HOME}/.ssh/id_rsa', 'block'],
    ['$HOME + a widened reader', 'strings $HOME/.aws/credentials', 'block'],
    ['$HOME/.env', 'cat $HOME/.env', 'block'],
    ['an unknown var, separator literal', 'cat $CFG/.netrc', 'review'],
    // Quoted forms take a different AST branch (DblQuoted with an inner
    // ParamExp). A mutation that broke ONLY the quoted branch survived the
    // first pass because every row here was unquoted — the corpus, not the
    // fix, was the gap.
    ['quoted var read', 'cat "$HOME/.ssh/id_rsa"', 'block'],
    ['quoted var rm', 'rm -rf "$HOME/projects"', 'block'],
    ['quoted bare home', 'rm -rf "$HOME"', 'block'],
  ])('%s', (_name, command, want) => {
    expect(rank[verdictOf(command)]).toBeGreaterThanOrEqual(rank[want as 'block']);
  });

  it('names the rule, not just the verdict', () => {
    // Ten rows in the parity corpus pass for an unrelated reason — bash-safe's
    // rm guard rescues `${HOME}`, the inline-exec tier decides `sh -c`. A row
    // asserting only the decision looks healthy while proving nothing, and lets
    // a mutation through CI.
    expect(ruleOf('cat $HOME/.ssh/id_rsa')).toBe('shield:project-jail:block-read-ssh');
  });

  it('a redirect target is a path', () => {
    // `cat < ~/.ssh/id_rsa` — the path lives in a Redir node on the enclosing
    // Stmt, never in Args, so the CallExpr loop never sees it.
    expect(ruleOf('cat < ~/.ssh/id_rsa')).toBe('shield:project-jail:block-read-ssh');
    expect(ruleOf('grep KEY < ~/.aws/credentials')).toBe('shield:project-jail:block-read-aws');
  });

  it('a redirect read carries commit 2 with it', () => {
    expect(ruleOf('cat < $HOME/.ssh/id_rsa')).toBe('shield:project-jail:block-read-ssh');
  });

  it('the redirect IS the read, whatever the command is', () => {
    // The shell delivers the bytes before the program runs, so the command
    // name is the wrong thing to condition on. ⚠️ This deliberately makes the
    // redirect path WIDER than the argument path: `md5sum < ~/.ssh/id_rsa`
    // blocks while `md5sum ~/.ssh/id_rsa` still allows, because md5sum is not
    // in FS_READ_TOOLS. That asymmetry is a symptom of the reader set being a
    // hand-maintained list — the same shape as the 22-reader gap — and belongs
    // to that calibration thread, not to this bug. Pinned so it reads as a
    // decision rather than an accident.
    expect(ruleOf('md5sum < ~/.ssh/id_rsa')).toBe('shield:project-jail:block-read-ssh');
    expect(ruleOf('wc -l < ~/.aws/credentials')).toBe('shield:project-jail:block-read-aws');
  });

  it('rm -rf $HOME reaches the guard that already knows about $HOME', () => {
    // isProtectedHomePath('$HOME/projects') is already true. This row proves
    // the value now arrives there.
    expect(verdictOf('rm -rf $HOME/projects')).toBe('block');
    expect(verdictOf('rm -rf ${HOME}/projects')).toBe('block');
  });
});

describe('#51 must-allow — the half that makes the widening honest', () => {
  it.each([
    ['unknown prefix, no separator', 'cat $PREFIX.env'],
    ['unknown prefix, no separator (ssh)', 'cat $X.ssh/id_rsa'],
    ['printing a variable is not a read', 'echo $HOME'],
    ['an ordinary relative file', 'cat build.env'],
    ['a dynamic build output path', 'cat $DIST/bundle.js'],
    ['the cache allow-list still applies', 'rm -rf $HOME/.cache'],
  ])('%s', (_name, command) => {
    expect(verdictOf(command)).toBe('allow');
  });

  it.each([
    ['a heredoc is content, not a path', 'cat <<EOF\n~/.ssh/id_rsa\nEOF'],
    ['a herestring is content, not a path', 'cat <<< "~/.ssh/id_rsa"'],
    ['a WRITE redirect is out of scope by decision', 'echo x > ~/.ssh/note'],
    ['an ordinary file redirect', 'cat < build.env'],
    ['an unknown prefix through a redirect', 'cat < $PREFIX.env'],
  ])('redirect must-allow: %s', (_name, command) => {
    expect(verdictOf(command)).toBe('allow');
  });

  it('the false positive suppression exists to kill stays dead', () => {
    // `echo '{"command":"cat .env"}'` is the row AST_FS_REGEX_RULES was built
    // for. Resolving more paths must not resurrect it.
    expect(verdictOf('echo \'{"command":"cat ~/.ssh/id_rsa"}\'')).toBe('allow');
  });
});

describe('#51 caller 2: the rm-cleanup waiver must stay fail-closed', () => {
  // ⭐ The reason this fix could not be a one-line change to the extractor.
  //
  // The waiver used the DROP ITSELF as its fail-closed signal:
  //   if (args.length - 1 > flags.length + paths.length) { refuse }
  // i.e. "an argument was unresolvable, so I cannot prove this rm is safe".
  // Correct and deliberate. Stop dropping, and that count stops firing — the
  // waiver would proceed on a path it never actually resolved, and fail later
  // only BY ACCIDENT because the sentinel text is not in the created-set. A
  // guard that works by accident is a guard that stops working silently.
  //
  // So the signal moves from inferred-by-counting to stated: hasUnresolved.
  //
  // These are REGRESSION guards, not proof of the fix — the refusals are
  // already correct today, and the point is that they stay correct once the
  // count they were derived from no longer exists. The positive row is what
  // proves the feature was not collaterally killed.
  //
  // Input shape matters here and was measured, not assumed: a file counts as
  // "created" only when its statement carries BOTH a heredoc and a truncate
  // redirect, at top level. `touch x && rm x` and `echo hi > x && rm x` are
  // both false today — the first has no redirect, the second is inside a
  // BinaryCmd, which the collector deliberately skips.
  const CREATE = 'cat > out.log <<EOF\nhi\nEOF\n';

  it('still waives a genuine same-command cleanup', () => {
    expect(isRmCreatedInCommandCleanup(CREATE + 'rm -f out.log')).toBe(true);
  });

  it('refuses when a target could not be resolved at all', () => {
    expect(isRmCreatedInCommandCleanup(CREATE + 'rm -f $TMP/out.log')).toBe(false);
  });

  it('refuses when only PART of the word is unresolvable', () => {
    // The counting check could be satisfied by a word that still produced one
    // path. The stated flag cannot — this is where the two differ.
    expect(isRmCreatedInCommandCleanup(CREATE + 'rm -f out$N.log')).toBe(false);
  });

  it('still refuses a file this command did not create', () => {
    expect(isRmCreatedInCommandCleanup(CREATE + 'rm -f other.log')).toBe(false);
  });
});
