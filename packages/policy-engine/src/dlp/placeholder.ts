// packages/policy-engine/src/dlp/placeholder.ts
// Is this matched secret a placeholder (a template slot, filler, a
// documentation value) rather than a credential?
//
// It replaces the stopword list that asked "does `here` / `your` / `example`
// occur ANYWHERE in the match" (node9Firewall#301, DLP-1). That test dropped a
// real key or password that merely contained one of those letters runs, at all
// three raw entrypoints. The judgement here is on the token's SHAPE: a word
// counts only where it stands as a word. No rule matches a word list by
// substring; that was the defect and it must not come back under a new name.
//
// Callers pass the SECRET part of a match (the pattern's `secretGroup` when it
// has one), never text the writer of the command controls (a host name, a
// scheme word).

/** A template variable or an angle-bracket slot is not a value. */
const TEMPLATE_RE = /\$\{|\{\{|%\{|<[^<>\s]{1,80}>/;

/** Eight of one character in a row: a masked or zero-filled value. A ratio and
 *  a run, not a substring list, so six zeros inside a real key do not count. */
const RUN_RE = /(.)\1{7}/;
const DOMINANT_SHARE = 0.6;

/** Documentation words vendors put on a real-shaped token. */
const DOC_WORDS = ['example', 'sample', 'fake', 'dummy', 'placeholder', 'changeme', 'redacted'];

/**
 * Words that mark a placeholder when they stand ALONE between separators
 * (`sk-your-key-here`, `my.fake.value`). `test` is not one: `sk_test_` is a
 * real prefix. `key`, `token` and `secret` are not either: real tokens carry
 * them as prefixes (`secret_...`, `AGE-SECRET-KEY-1...`).
 */
const STANDALONE_WORDS = new Set([...DOC_WORDS, 'your', 'here', 'insert', 'replace']);

/**
 * A doc word at the very START or END of the token, with no separator needed:
 * the AWS documentation keys end in EXAMPLE and EXAMPLEKEY, and a fixture
 * password is written `examplepass123` or `FAKEPASSWORD12`. Anchored, so the
 * same letters in the middle of a key are not this.
 */
const DOC_EDGE_RE = new RegExp(
  `^(?:${DOC_WORDS.join('|')})|(?:${DOC_WORDS.join('|')})(?:[_-]?(?:key|token|secret))?$`
);

/**
 * Words a placeholder is BUILT from (`your_key_here`, `yourKeyHere`,
 * `password`, `test1234`). One of them inside real material means nothing: the
 * rule needs every alphabetic segment of the token to be made of these.
 */
const VOCABULARY = [
  ...DOC_WORDS,
  'your',
  'here',
  'insert',
  'replace',
  'put',
  'change',
  'goes',
  'with',
  'this',
  'please',
  'real',
  'actual',
  'me',
  'my',
  'the',
  'an',
  'key',
  'token',
  'secret',
  'password',
  'passwd',
  'api',
  'apikey',
  'access',
  'auth',
  'test',
  'value',
  'xxx',
];
const VOCABULARY_SET = new Set(VOCABULARY);
/** Longer than any composition worth reading; a longer run of letters is material. */
const MAX_COMPOSED_SEGMENT = 48;

/** `yourkeyhere`: the segment is a vocabulary word or a chain of them. */
function madeOfVocabulary(segment: string): boolean {
  if (VOCABULARY_SET.has(segment)) return true;
  if (segment.length > MAX_COMPOSED_SEGMENT) return false;
  const reachable = new Array<boolean>(segment.length + 1).fill(false);
  reachable[0] = true;
  for (let i = 0; i < segment.length; i++) {
    if (!reachable[i]) continue;
    for (const word of VOCABULARY) {
      if (segment.startsWith(word, i)) reachable[i + word.length] = true;
    }
  }
  return reachable[segment.length];
}

const isUpper = (c: number): boolean => c >= 65 && c <= 90;
const isLower = (c: number): boolean => c >= 97 && c <= 122;

/**
 * The runs of letters in a token, split at separators, digits and case
 * boundaries (`yourKeyHere` -> your, key, here; `APIKey` -> api, key), lower
 * case. One pass over the characters: a token can be as long as the text.
 */
function alphabeticSegments(token: string): string[] {
  const segments: string[] = [];
  let start = -1;
  const close = (end: number): void => {
    if (start >= 0) segments.push(token.slice(start, end).toLowerCase());
    start = -1;
  };
  for (let i = 0; i < token.length; i++) {
    const c = token.charCodeAt(i);
    if (!isUpper(c) && !isLower(c)) {
      close(i);
      continue;
    }
    if (start >= 0 && isUpper(c)) {
      const prev = token.charCodeAt(i - 1);
      const next = i + 1 < token.length ? token.charCodeAt(i + 1) : 0;
      // lower|Upper, or the last capital of a run that starts a word (APIKey).
      if (isLower(prev) || (isUpper(prev) && isLower(next))) close(i);
    }
    if (start < 0) start = i;
  }
  close(token.length);
  return segments;
}

function dominatedByOneChar(s: string): boolean {
  if (s.length < 4) return false;
  const counts = new Map<string, number>();
  let top = 0;
  for (const ch of s) {
    const n = (counts.get(ch) ?? 0) + 1;
    counts.set(ch, n);
    if (n > top) top = n;
  }
  return top / s.length >= DOMINANT_SHARE;
}

/** A longer token is material, not a phrase; also keeps this rule cheap. */
const MAX_PHRASE_LENGTH = 160;

function builtFromVocabulary(token: string): boolean {
  if (token.length > MAX_PHRASE_LENGTH) return false;
  const segments = alphabeticSegments(token);
  if (segments.length === 0 || !segments.every(madeOfVocabulary)) return false;
  // Letters must carry the token: `key-` followed by thirty digits is an id.
  const letters = token.replace(/[^A-Za-z]/g, '').length;
  const alphanumerics = token.replace(/[^A-Za-z0-9]/g, '').length;
  return letters * 2 >= alphanumerics;
}

/**
 * Only lower-case words joined by `-`, `_` or `.`, three or more, with no
 * digit and no capital: a phrase (a URL slug, a kebab-case name), never a
 * generated token. `pypi-package-backdoored-to-steal-credentials...` in an
 * article URL was redacted as a PyPI token (node9Firewall#374). A random
 * token of 20 characters has no digit and no capital less than once in ten
 * million. A word is at most 20 letters: `dp.pt.` followed by 43 letters is a
 * token body, not a third word.
 *
 * For vendor TOKEN patterns only. A password a person chose can be exactly
 * this shape (four words and three dashes), so the validators that judge a
 * password do not ask this.
 */
const PHRASE_RE = /^[a-z]{1,20}(?:[-_.][a-z]{1,20}){2,}$/;
export function isPhrase(secret: string): boolean {
  return PHRASE_RE.test(secret);
}

export function isPlaceholder(secret: string): boolean {
  if (secret.length === 0) return false;
  // 1. a template marker anywhere
  if (TEMPLATE_RE.test(secret)) return true;
  // 2. filler
  if (RUN_RE.test(secret) || dominatedByOneChar(secret)) return true;
  const lower = secret.toLowerCase();
  // 3. a doc word that stands as a word, or opens or closes the token
  if (lower.split(/[^a-z0-9]+/).some((part) => STANDALONE_WORDS.has(part))) return true;
  if (DOC_EDGE_RE.test(lower)) return true;
  // 4. built from placeholder vocabulary
  return builtFromVocabulary(secret);
}
