/**
 * Jail gauntlet (task #19, surface 1) — prove the credential jail AT THE GATE.
 *
 * Why this suite exists: jail's only gate-level coverage
 * (jail.integration.test.ts) asserts through `node9 explain`, which
 * [[project_jail_add_path]] records as under-reporting and not ground truth.
 * This probes `node9 check` — the layer that actually decides — with the payload
 * a real agent hook sends.
 *
 * ⚠️ IT FOUND A REAL BUG ON THE FIRST PROBE (see `read/grep` cases below):
 *   `node9 jail add <path>` prints "AI reads of this path now BLOCK", and Bash
 *   reads ARE blocked — but the `Read` and `Grep` tools are ALLOWED, because:
 *     • `jail add` enables the shield named `user-jail` (shields/jail.ts:18,
 *       USER_JAIL_SHIELD), while
 *     • the orchestrator guard that exists precisely to stop Read/Grep/Glob
 *       fast-pathing past a jail checks `readActiveShields().includes(
 *       'project-jail')` — the OTHER shield name.
 *   So `Read`/`Grep` hit the ignoredTools fast-path allow and never reach the
 *   jail's rules. Read is the primary way an agent reads a file, so the jail is
 *   inert on its main path while reporting success.
 *
 * Note on the earlier "bash bypass was a misdiagnosis" note: that investigation
 * checked BASH (which genuinely works) and concluded the jail was fine. The gap
 * is the opposite direction — the file tools, not the shell.
 */
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { FS_READ_TOOLS, analyzeFsOperation } from '@node9/policy-engine';
import {
  CLI,
  makeHome,
  runCli,
  probe,
  explain,
  cleanup,
  writeConfig,
  writeCloudCache,
} from './helpers/gauntlet';

const homes: string[] = [];
function jailedHome(): { home: string; jailed: string } {
  const home = makeHome('node9-jail-gauntlet-');
  homes.push(home);
  const jailed = path.join(home, '.secrets');
  fs.mkdirSync(jailed, { recursive: true });
  const r = runCli(home, ['jail', 'add', jailed]);
  expect(r.error).toBeUndefined();
  expect(r.status).toBe(0);
  return { home, jailed };
}

/**
 * The ORG-managed jail (task #22): managedConfig.jailPaths, no `jail add`.
 * It enables no shield and writes no local path store — it only injects
 * org:-prefixed rules — which is why it kept task #20's file-tool bypass after
 * the local jail was fixed. Local mode is `observe` here on purpose: that is
 * the exact production shape (task #21) and it must not soften the mandate.
 */
function orgJailedHome(): { home: string; jailed: string } {
  const home = makeHome('node9-jail-gauntlet-org-');
  homes.push(home);
  const jailed = path.join(home, '.secrets');
  fs.mkdirSync(jailed, { recursive: true });
  writeConfig(home, {
    settings: {
      mode: 'observe',
      approvalTimeoutMs: 0,
      approvers: { native: false, browser: false, cloud: false, terminal: false },
    },
    policy: {},
  });
  writeCloudCache(home, {
    fetchedAt: '2026-07-01T00:00:00Z',
    rules: [],
    managedConfig: { jailPaths: [{ path: jailed, verdict: 'block' }] },
  });
  return { home, jailed };
}

beforeAll(() => {
  expect(fs.existsSync(CLI), `built CLI missing at ${CLI} — run npm run build`).toBe(true);
});
afterEach(() => {
  for (const h of homes.splice(0)) cleanup(h);
});

describe('jail gauntlet — the credential jail holds at the real gate', () => {
  // ── CONTROL: without this passing, every "not allowed" below is vacuous ────
  it('CONTROL: a shell read of a jailed path is blocked (proves the jail armed)', () => {
    const { home, jailed } = jailedHome();
    const r = probe(home, 'Bash', { command: `cat ${jailed}/key.txt` });
    expect(r.verdict).toBe('block');
  });

  it('CONTROL: an UNjailed path is allowed (proves we are not blanket-denying)', () => {
    const { home } = jailedHome();
    const r = probe(home, 'Bash', { command: 'cat /tmp/harmless.txt' });
    expect(r.verdict).toBe('allow');
  });

  // ── THE BUG (task #20, now fixed): the file tools bypassed the jail ───────
  // `jail add` promises reads BLOCK, so these assert `block` — not merely
  // "not allow" — matching the Bash CONTROL above.
  it('the Read tool is blocked on a jailed path', () => {
    const { home, jailed } = jailedHome();
    const r = probe(home, 'Read', { file_path: path.join(jailed, 'key.txt') });
    expect(r.verdict).toBe('block');
  });

  it('the Grep tool is blocked on a jailed path (pattern field)', () => {
    const { home, jailed } = jailedHome();
    const r = probe(home, 'Grep', { pattern: path.join(jailed, 'key.txt') });
    expect(r.verdict).toBe('block');
  });

  it('the Grep tool is blocked when the jailed dir rides in `path` (real Grep shape)', () => {
    const { home, jailed } = jailedHome();
    // Real Grep exfil shape: benign pattern, jailed directory as search root.
    const r = probe(home, 'Grep', { pattern: '.*', path: jailed });
    expect(r.verdict).toBe('block');
  });

  it('the Glob tool is blocked on a jailed path', () => {
    const { home, jailed } = jailedHome();
    const r = probe(home, 'Glob', { pattern: path.join(jailed, '*') });
    expect(r.verdict).toBe('block');
  });

  it('an unjailed Read still takes the fast path (no blanket regression)', () => {
    const { home } = jailedHome();
    const r = probe(home, 'Read', { file_path: '/tmp/harmless.txt' });
    expect(r.verdict).toBe('allow');
  });

  // ── The ORG-managed jail (task #22) ───────────────────────────────────────
  // Found by the real `node9 check` e2e AFTER task #20 shipped and every unit
  // test was green: Bash blocked, Read allowed. The managed route enables no
  // shield, so the guard never armed — and the existing jail-managed.spec only
  // ever asserted Bash, the same blind spot that hid #20 in the first place.
  it('CONTROL: an org-managed jail blocks a shell read (mandate armed)', () => {
    const { home, jailed } = orgJailedHome();
    const r = probe(home, 'Bash', { command: `cat ${jailed}/key.txt` });
    expect(r.verdict).toBe('block');
  });

  it('an org-managed jail blocks the Read tool', () => {
    const { home, jailed } = orgJailedHome();
    const r = probe(home, 'Read', { file_path: path.join(jailed, 'key.txt') });
    expect(r.verdict).toBe('block');
  });

  it('an org-managed jail blocks Grep on the jailed dir', () => {
    const { home, jailed } = orgJailedHome();
    const r = probe(home, 'Grep', { pattern: '.*', path: jailed });
    expect(r.verdict).toBe('block');
  });

  it('an org-managed jail blocks Glob over the jailed dir', () => {
    const { home, jailed } = orgJailedHome();
    const r = probe(home, 'Glob', { pattern: path.join(jailed, '*') });
    expect(r.verdict).toBe('block');
  });

  it('CONTROL: an org-managed jail still allows an unjailed Read', () => {
    const { home } = orgJailedHome();
    const r = probe(home, 'Read', { file_path: '/tmp/harmless.txt' });
    expect(r.verdict).toBe('allow');
  });

  // ── Reporting vs reality ──────────────────────────────────────────────────
  // Not an enforcement assertion — a consistency one. `jail add` promises reads
  // block; whatever the gate does, the CLI and the gate must agree, or a user
  // is told they are protected when they are not.
  it('the gate agrees with what `jail add` promised about reads', () => {
    const { home, jailed } = jailedHome();
    const gate = probe(home, 'Read', { file_path: path.join(jailed, 'key.txt') });
    const e = explain(home, 'Read', path.join(jailed, 'key.txt'));
    const explainSaysAllow = /ALLOW/i.test(e.stdout ?? '');
    // The promise printed by `jail add` is "AI reads of this path now BLOCK".
    // So an allow at the gate is a broken promise regardless of what explain says.
    expect({ gate: gate.verdict, explainSaysAllow }, 'jail add promised reads BLOCK').toMatchObject(
      { gate: expect.not.stringMatching(/^allow$/) }
    );
  });
});

/**
 * The VERB axis (added 2026-08-31).
 *
 * Everything above varies WHICH TOOL carries the path — Read, Grep, Glob,
 * shell. Every shell case is `cat`. That single hard-coded verb is why
 * `base64 ~/.ssh/id_rsa` shipped undetected: it prints a file exactly like
 * `cat` does, it simply was never in the suite because nobody thought to add
 * it. A hand-written case list only ever covers what its author imagined.
 *
 * So this block DERIVES its cases from `FS_READ_TOOLS` — the same set the
 * engine consults at `shell/index.ts:1765`. Add a name to that set and it gains
 * jail coverage for free; remove one and the deletion shows up in the diff.
 * Identical rule to the one the regex beside the set already follows:
 * "DERIVED from FS_READ_TOOLS, never hand-written beside it."
 */
describe('jail gauntlet — the verb axis, derived from FS_READ_TOOLS', () => {
  for (const verb of [...FS_READ_TOOLS].sort()) {
    it(`shell: \`${verb}\` on a jailed path is blocked`, () => {
      const { home, jailed } = jailedHome();
      const r = probe(home, 'Bash', { command: `${verb} ${jailed}/key.txt` });
      expect(r.verdict, `${verb} reads file contents — the jail must stop it`).toBe('block');
    });
  }
});

/** Build a command that MOVES rather than prints, per verb. */
function copyCmd(verb: string, src: string): string {
  if (verb === 'tar') return `tar cf /tmp/n9-gauntlet.tar ${src}`;
  if (verb === 'ln') return `ln -s ${src} /tmp/n9-gauntlet-link`;
  return `${verb} ${src} /tmp/n9-gauntlet-copy`;
}
const COPY_VERBS = ['cp', 'install', 'ln', 'rsync', 'tar'];

/**
 * ⭐ The two jails do NOT share a mechanism, and it decides copy coverage.
 *
 * Written 2026-08-31 after this suite refuted the assumption behind
 * `BUGS.md` § A. § A says copy verbs escape the jail. That is true of the
 * BUILT-IN baseline only — a `jail add` / fleet path covers them fine:
 *
 *   user + org jail  →  `pathRules` emits a bash rule matching the PATH
 *                       anywhere in the command (shields/build.ts:107).
 *                       Verb-agnostic, so `cp`/`tar`/`rsync` are caught.
 *   built-in baseline → `analyzeFsOperation`, which resolves the VERB first
 *                       and only then its target paths. A verb outside
 *                       `FS_READ_TOOLS` is never reached, so copying escapes.
 *
 * Same promise, two implementations, opposite coverage — the four-list problem
 * in miniature. These blocks pin both halves so the difference can't drift.
 */
describe('jail gauntlet — copy verbs ARE covered by a user/org jail', () => {
  for (const verb of COPY_VERBS) {
    it(`\`${verb}\` out of a user-jailed dir is blocked`, () => {
      const { home, jailed } = jailedHome();
      const r = probe(home, 'Bash', { command: copyCmd(verb, `${jailed}/key.txt`) });
      expect(r.verdict, `the path rule matches ${verb} regardless of verb`).toBe('block');
    });
  }
});

/**
 * KNOWN UNCOVERED — the real, narrowed `BUGS.md` § A.
 *
 * The baseline paths (`~/.ssh`, `~/.aws`, `.env`) are guarded by the AST tier,
 * which asks "which command PRINTS a file". `cp`/`tar`/`rsync` don't print,
 * they move — and once the secret sits at /tmp every rule is gone, because they
 * all key on the original path.
 *
 * ⚠️ These assertions are deliberately INVERTED: they assert the gap still
 * exists. Until now it lived only in a doc — nothing told a reader it was
 * there, nothing failed if someone half-fixed it, nothing would catch a later
 * regression. As a test it is a fact CI reads every run.
 *
 * ✅ WHEN YOU FIX ONE this test FAILS. That is success — move the verb up into
 * the covered block and delete its line here. Never silence it by loosening
 * the assertion.
 *
 * ⚠️ WINDOWS — skipped, because the premise itself is absent there.
 * `path.join` yields backslashes on win32, and mvdan-sh parses `\` as a POSIX
 * escape and EATS it, so the literal reaching the matcher has no separators
 * left at all:
 *
 *   POSIX    paths ["/home/x/.ssh/id_rsa"]   6 tokens  → block
 *   win32    paths ["C:Usersx.sshid_rsa"]    2 tokens  → NULL
 *
 * So on Windows the built-in baseline never fires for ANY verb, and both the
 * "copy escapes" rows and their CONTROL become vacuous — the rows would pass
 * for the wrong reason and the CONTROL fails outright. That is a real product
 * gap, not a test bug; it is pinned platform-independently by the engine-level
 * block below so skipping here hides nothing.
 *
 * `pathRules` (user + fleet jail) is unaffected — it is a regex over raw
 * command text with `[\s/\\]` separators and never meets the parser. The
 * derived read-verb suite above therefore still runs everywhere.
 */
describe.skipIf(process.platform === 'win32')(
  'jail gauntlet — copy verbs escape the BUILT-IN baseline (BUGS.md § A)',
  () => {
    for (const verb of COPY_VERBS) {
      it(`⚠️ \`${verb}\` on ~/.ssh still escapes — read the block comment before fixing`, () => {
        const { home } = jailedHome();
        const ssh = path.join(home, '.ssh');
        fs.mkdirSync(ssh, { recursive: true });
        const r = probe(home, 'Bash', { command: copyCmd(verb, path.join(ssh, 'id_rsa')) });
        expect(r.verdict, `${verb} moves the baseline secret out unnoticed`).toBe('allow');
      });
    }

    it('CONTROL: a PRINTING verb on the same baseline path IS blocked', () => {
      const { home } = jailedHome();
      const ssh = path.join(home, '.ssh');
      fs.mkdirSync(ssh, { recursive: true });
      const r = probe(home, 'Bash', { command: `cat ${path.join(ssh, 'id_rsa')}` });
      expect(r.verdict, 'without this the block above proves nothing').toBe('block');
    });
  }
);

/**
 * ⚠️ KNOWN UNCOVERED — the AST tier is blind to Windows backslash paths.
 *
 * Pure-function assertions, so they run on EVERY platform: the gap stays
 * visible on Linux CI instead of only surfacing when a Windows runner happens
 * to execute the integration block above.
 *
 * `mvdan-sh` treats `\` as a POSIX escape and removes it, so a real Windows
 * path arrives at the matcher with no separators. Consequence on a real
 * Windows box: the built-in jail (`~/.ssh`, `~/.aws`, `.env`) never fires —
 * not merely for copy verbs, for everything.
 *
 * ⛔ Bigger and NOT yet measured: the destructive AST rules (rm / mkfs / dd)
 * very likely go blind the same way, since this is a parse-level loss rather
 * than a matcher-level one.
 *
 * ⭐ These use `it.fails`, NOT an assertion that the gap exists. The difference
 * matters. Asserting the broken value (`toBeNull()`) would write the bug into
 * the suite as if it were the spec: a reader sees the wrong expectation, and
 * whoever fixes the parser gets a red test whose easiest "fix" is to edit the
 * assertion — silently re-hiding the gap. With `it.fails` the body states the
 * DESIRED behaviour and only the marker says "known broken", so a fix makes
 * vitest raise `Expect test to fail`, which cannot be satisfied by weakening
 * an assertion — only by deleting the marker. Verified, not assumed.
 */
describe('AST tier — Windows path blindness (known gap)', () => {
  const WIN_CASES: Array<[string, string]> = [
    ['~/.ssh', 'cat C:\\Users\\x\\.ssh\\id_rsa'],
    ['~/.aws', 'cat C:\\Users\\x\\.aws\\credentials'],
    ['.env', 'cat C:\\proj\\.env'],
    [
      'quoted — quotes do not help, POSIX escapes apply inside them too',
      'cat "C:\\Users\\x\\.ssh\\id_rsa"',
    ],
  ];
  for (const [label, cmd] of WIN_CASES) {
    // Body = what SHOULD happen. Marker = it does not yet. Delete the marker
    // when the parse is fixed; never touch the expectation.
    it.fails(`a Windows backslash path should be detected: ${label}`, () => {
      expect(analyzeFsOperation(cmd)?.verdict).toBe('block');
    });
  }

  it('CONTROL: the same Windows path with FORWARD slashes IS detected', () => {
    const r = analyzeFsOperation('cat C:/Users/x/.ssh/id_rsa');
    expect(r?.verdict, 'proves the matcher is fine — only the separator breaks it').toBe('block');
  });

  it('CONTROL: the POSIX equivalent IS detected', () => {
    expect(analyzeFsOperation('cat /home/x/.ssh/id_rsa')?.verdict).toBe('block');
  });
});
