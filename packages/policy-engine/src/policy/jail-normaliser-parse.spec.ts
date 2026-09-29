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
// Fix: the jail reader parses the RAW command, as bash will run it, and
// resolves quoting word by word itself. The normalised reading is used only
// for the prescreen and by the text rules, and is unchanged.
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
  // matched before (/code-review on 5ddb367). The jail now parses the raw
  // command directly (1de6241); the normalised reading is what it always was.
  it('one unparseable word does not undo the de-obfuscation of the others', () => {
    expect(normalizeCommandForPolicy(`ca''t notes.txt; echo '(a)'`)).toContain('cat notes.txt');
  });

  it('a quoted script payload is still de-obfuscated for the text rules', () => {
    expect(normalizeCommandForPolicy(`node -e 'con''sole.log(1)'`)).toContain('console.log(1)');
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

describe('JAIL-19 — a rewrite that still PARSES but changes structure cannot hide the read', () => {
  // The headline class of the final fix (jail reads the raw command). Each of
  // these unquotes to text that parses fine, but as a different command that no
  // longer contains the read: a lone `"` pair swallows the statements between
  // it into one string; a `;#` word comments out the rest of the line. On the
  // parse-failure-only fallback (1686d1f) these were ALLOW; the raw-command
  // reader (1de6241) blocks them.
  it.each([
    [`echo '"'; cat .env; echo '"'`, 'block'],
    [`echo 'x;#'; cat .env`, 'block'],
  ])('%s -> %s', (c, want) => expect(v(c)).toBe(want));
});

describe('JAIL-19 — the verdict cache is keyed by the RAW command', () => {
  // Two commands with the SAME normalised text but different real meaning:
  // `echo 'x;cat' .env` is one echo (no read); `echo x\;cat .env` is
  // `echo x` then `cat .env` (a read). Both normalise to `echo x;cat .env`.
  // Keyed by the normalised text, whichever ran first would decide the other;
  // keyed by the raw command, each keeps its own verdict, in either order.
  it('the read is not masked by an earlier no-read command that normalises alike', () => {
    expect(normalizeCommandForPolicy(`echo 'x;cat' .env`)).toBe(
      normalizeCommandForPolicy(`echo x\;cat .env`)
    );
    expect(v(`echo 'x;cat' .env`)).toBe('null'); // warms the cache with the no-read verdict
    expect(v(`echo x\;cat .env`)).toBe('block'); // must not read the cached null
  });

  it('and in the other order', () => {
    expect(v(`echo x\;cat .env`)).toBe('block');
    expect(v(`echo 'x;cat' .env`)).toBe('null');
  });
});
