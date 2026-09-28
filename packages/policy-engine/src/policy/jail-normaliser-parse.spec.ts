import { describe, it, expect } from 'vitest';
import { analyzeFsOperation, normalizeCommandForPolicy } from '../shell/index';
import { parseShared, PARSE_FAIL } from '../shell/index';

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
// Two layers: a word whose literal holds a shell metacharacter is never
// rewritten, and a normalised reading that does not parse while the raw
// command did falls back to the raw command, which closes the class for any
// character the first layer does not list.
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

describe('JAIL-19 — the normalised reading parses whenever the raw one does', () => {
  it.each([
    `grep x .env | sed 's/(a)/b/'`,
    `echo '#'; cat .env`,
    `echo 'a"b'; cat .env`,
    `echo 'x\`y'; cat .env`,
    `echo '$(x'; cat .env`,
    `awk '{print $1}' f`,
    `printf '%s\\n' "(x)"`,
  ])('%s', (c) => {
    expect(parseShared(c)).not.toBe(PARSE_FAIL); // the raw command is valid shell
    expect(parseShared(normalizeCommandForPolicy(c))).not.toBe(PARSE_FAIL);
  });

  it('a `#` inside a quoted word is not turned into a comment', () => {
    expect(normalizeCommandForPolicy(`echo '#'; cat .env`)).toContain('cat .env');
    expect(normalizeCommandForPolicy(`echo '#'; cat .env`)).not.toMatch(/^echo #;/);
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
