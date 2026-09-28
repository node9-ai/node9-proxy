import { describe, it, expect } from 'vitest';
import { analyzeFsOperation, normalizeCommandForPolicy } from '../shell/index';

// ─────────────────────────────────────────────────────────────────────────────
// JAIL-19: A QUOTED WORD WITH A SHELL METACHARACTER MADE THE JAIL READ NOTHING
//
// Reported from the website demo recording: an agent masked a secret with
//   grep -i stripe <demo>/.env | sed -E 's/=(.{8}).*(.{4})$/=\1…\2/'
// and node9 allowed it; the audit row says the file was read.
//
// The normaliser de-obfuscates quoting (`r''m` -> `rm`) by rewriting any quoted
// word whose literal has no whitespace with that literal UNQUOTED. `'s/(a)/b/'`
// became `s/(a)/b/`, and the rewritten command was no longer valid shell.
// analyzeFsOperation parses the NORMALISED string, got PARSE_FAIL, and returned
// null: the read was judged by nobody, and the regex twin is suppressed for
// bash. `#` did not even fail the parse; it commented out the rest of the line.
// A lone `(` survived only because stage 6 refused to rewrite a word into a
// bare operator; a balanced pair is not a bare operator.
//
// Fix: the jail reader reads the RAW command whenever the normalised reading
// does not parse, and the normaliser never unquotes a word into one starting
// with `#`. The normalised reading itself is otherwise unchanged, because the
// text rules depend on it.
// ─────────────────────────────────────────────────────────────────────────────

const v = (c: string) => {
  const r = analyzeFsOperation(c);
  return r ? r.verdict : 'null';
};

describe('JAIL-19 — controls', () => {
  it.each([
    [`grep x .env | sed 's/a/b/'`, 'block'],
    [`cat .env`, 'block'],
    [`cat .env | tr '(' 'x'`, 'block'],
    [`grep '(' .env`, 'block'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});

describe('JAIL-19 — a quoted metacharacter no longer hides the read', () => {
  it.each([
    // the reported pair and the recorded command
    [`grep x .env | sed 's/(a)/b/'`, 'block'],
    [`grep -i stripe /home/u/demo/.env | sed -E 's/=(.{8}).*(.{4})$/=\\1…\\2/'`, 'block'],
    // the class, each character on its own
    [`cat .env | sed 's/(a)/b/'`, 'block'],
    [`cat .env; echo '(a)'`, 'block'],
    [`echo '#'; cat .env`, 'block'],
    [`echo 'a"b'; cat .env`, 'block'],
    [`echo 'x\`y'; cat .env`, 'block'],
    [`echo '$(x'; cat .env`, 'block'],
    // every jail rule and the copy tier, not only .env
    [`cat ~/.ssh/id_rsa | sed 's/(a)/b/'`, 'block'],
    [`cat ~/.aws/credentials; echo '(x)'`, 'block'],
    [`cp ~/.ssh/id_rsa /tmp/k; echo '(x)'`, 'review'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});

describe("JAIL-19 — the fix stays out of the text rules' way", () => {
  // A first cut returned the RAW command whenever the normalised reading did
  // not parse. That threw away every de-obfuscation in the whole command, and
  // the text rules, which never needed a parse, stopped matching tokens they
  // matched before (/code-review on 5ddb367). The raw fallback now lives only
  // in the jail reader; the normalised reading is what it always was.
  it('one unparseable word does not undo the de-obfuscation of the others', () => {
    expect(normalizeCommandForPolicy(`ca''t notes.txt; echo '(a)'`)).toContain('cat notes.txt');
  });

  it('a quoted script payload is still de-obfuscated for the text rules', () => {
    expect(normalizeCommandForPolicy(`node -e 'con''sole.log(1)'`)).toContain('console.log(1)');
  });

  it('a `#` word is left quoted, so it is not a comment', () => {
    const n = normalizeCommandForPolicy(`echo '#'; cat .env`);
    expect(n).toContain('cat .env');
    expect(n).not.toMatch(/^echo #;/);
  });
});

describe('JAIL-19 — de-obfuscation still works on ordinary tokens', () => {
  it.each([
    [`r''m -rf /tmp/x`, 'rm -rf /tmp/x'],
    [`\\rm -rf /tmp/x`, 'rm -rf /tmp/x'],
    [`git pu''sh --force`, 'git push --force'],
    [`ca''t .e''nv`, 'cat .env'],
  ])('%s -> %s', (c, want) => expect(normalizeCommandForPolicy(c)).toBe(want));

  it('an obfuscated read still blocks', () => {
    expect(v(`ca''t .e''nv`)).toBe('block');
  });
});
