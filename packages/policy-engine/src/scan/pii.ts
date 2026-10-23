// PII detection. Pure regex (plus a checksum) over a string. Used by the
// canonical extractor (and historically by the daemon watermark) to flag
// email / SSN / phone / credit-card values that leak through tool output or
// assistant text.
//
// Each regex requires structural delimiters that real PII has:
//   - Email needs `@` plus a TLD-like suffix
//   - SSN needs the dash-delimited 3-2-4 layout
//   - Phone (US) needs 3-3-4 with separators
//   - Credit card needs a valid IIN prefix, the right digit count for that
//     network (16 for Visa/Mastercard/Discover, 15 for Amex), and a passing
//     Luhn check
//
// Without these anchors the FP rate would explode. PII in non-standard
// layouts (no dashes for SSN, a card glued to a letter, Amex written 4-4-4-3)
// won't fire — known and accepted gaps. Both card regexes are anchored with
// \b on both sides, so a digit immediately before or after the number
// defeats them, exactly as it did before Luhn was added.
//
// An unseparated card-shaped run that is the fractional part of a number is
// not a card: after `<digit>.`, after a leading `.` at the start of the text
// (".479..."), or after a lone `0,` at the start of the text or after `;`
// (comma decimal). A `.` and a `,` are word boundaries, so without
// that rule a float printed at full precision (16 or 17 fractional digits) is
// read as a card, and 70 of the 4,950 fractions k/n with 2 <= n <= 100 pass
// Luhn in each spelling (node9Firewall#333). The rule lives in hasValidCard
// (isDecimalFraction), not in the regexes, so they stay lookbehind-free
// (safe-regex2, house style). Accepted gaps: an unseparated card written
// directly after "1.", at the very start of a text after "." or "0,", or
// after ";0," is not detected; a grouped one still is, since a fraction has
// no separators. A comma decimal above 1
// ("12,479...") is still read as a card: "1,<run>" is a CSV row.
//
// This file is part of the extractor-version hash set
// (scripts/check-extractor-version.mjs): editing it changes detector output.

import {
  validateLuhn,
  validateIban,
  validateAbaRouting,
  validateCodiceFiscale,
  validateSpanishId,
  validatePesel,
  validateCnp,
  validateNir,
  validateSwissAhv,
  validateSwissUid,
  validateSwedishPersonnummer,
  validateNorwegianFnr,
  validateFinnishHetu,
} from './checksums';

const PII_EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const PII_SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/;
const PII_PHONE_RE = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/;

// Card regexes are REGEX LITERALS, not strings: a literal is syntax-checked at
// parse time, whereas `new RegExp('\b...')` in a plain string compiles to a
// backspace and silently matches nothing. The global copies used for scanning
// are derived from `.source` per call — see hasValidCard for why they are
// never held at module level.
//
// 16 digits, 4-4-4-4: Visa (4), Mastercard (51-55 and the 2-series 2221-2720,
// issued since 2017), Discover (6), JCB (3528-3589), Mir (2200-2204). A dot
// is a separator too (fw#372 B1). The Amex prefixes are deliberately NOT
// here: Amex is 15 digits, so any 16-digit run starting 34/37 is by
// construction not a card.
const PII_CC16_RE =
  /\b(?:4\d{3}|5[1-5]\d{2}|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)|6\d{3}|35(?:2[89]|[3-8]\d)|220[0-4])[-\s.]?\d{4}[-\s.]?\d{4}[-\s.]?\d{4}\b/;
// 15 digits, 4-6-5: American Express (34, 37).
const PII_CC15_RE = /\b3[47]\d{2}[-\s.]?\d{6}[-\s.]?\d{5}\b/;
// 14 digits, 4-6-4: Diners Club (300-305, 36, 38).
const PII_CC14_RE = /\b3(?:0[0-5]\d|[68]\d\d)[-\s.]?\d{6}[-\s.]?\d{4}\b/;
// Visa's 13-digit (4-3-3-3) and 19-digit (4-4-4-4-3) lengths. A 15-digit Visa
// is left out on purpose: a Luhn-valid 15-digit device id sits in a benign
// corpus, and no network issues that length.
const PII_CC13_RE = /\b4\d{3}[-\s.]?\d{3}[-\s.]?\d{3}[-\s.]?\d{3}\b/;
const PII_CC19_RE = /\b4\d{3}[-\s.]?\d{4}[-\s.]?\d{4}[-\s.]?\d{4}[-\s.]?\d{3}\b/;
/** Every card shape, the common ones first; detection and masking share it. */
const CARD_PATTERNS = [PII_CC16_RE, PII_CC15_RE, PII_CC14_RE, PII_CC13_RE, PII_CC19_RE];

// A US bank routing number (ABA RTN): nine digits whose 3-7-1 weighted sum is
// 0 mod 10, named as one by a label within 24 characters on either side
// (`routing`, `ABA`, `RTN`). Nine-digit numbers are everywhere and the
// checksum alone leaves one in ten, so the label is what makes this a
// finding (fw#372 B3).
const PII_ROUTING_RE = /\b\d{9}\b/;
const ROUTING_LABEL_RE = /\b(?:routing|aba|rtn)\b/i;
const ROUTING_LABEL_WINDOW = 24;

// National identifiers with a check digit (fw#372 B2). A shape with a strong
// format of its own (an Italian codice fiscale, a Spanish DNI letter, a Swiss
// AHV or UID with its dots, a French NIR with its department and key, a
// Polish PESEL or Romanian CNP with a coded birth date) is a finding on the
// checksum alone. The Nordic numbers are plain digit runs, so they also need
// their name within 32 characters before them (`personnummer`,
// `fødselsnummer`, `hetu`, `henkilötunnus`). The date rules keep timestamps
// and phone numbers out.
interface NationalIdShape {
  regex: RegExp;
  validate: (raw: string) => boolean;
  labelled?: true;
}
const NATIONAL_ID_SHAPES: readonly NationalIdShape[] = [
  { regex: /\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b/, validate: validateCodiceFiscale },
  { regex: /\b(?:\d{8}|[XYZ]\d{7})[A-Z]\b/, validate: validateSpanishId },
  { regex: /\b756\.\d{4}\.\d{4}\.\d{2}\b/, validate: validateSwissAhv },
  { regex: /\bCHE-\d{3}\.\d{3}\.\d{3}\b/i, validate: validateSwissUid },
  {
    regex: /\b[12] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b/,
    validate: validateNir,
  },
  // PESEL and CNP are bare 11- and 13-digit runs: a millisecond timestamp
  // passes the CNP rules about 1 time in 400 and a random 11-digit id passes
  // PESEL about 1 in 50 (measured), so both need their name nearby.
  { regex: /\b\d{11}\b/, validate: validatePesel, labelled: true },
  { regex: /\b[1-9]\d{12}\b/, validate: validateCnp, labelled: true },
  { regex: /\b\d{6}[-+]\d{4}\b/, validate: validateSwedishPersonnummer, labelled: true },
  { regex: /\b\d{11}\b/, validate: validateNorwegianFnr, labelled: true },
  { regex: /\b\d{6}[-+A-FU-Y]\d{3}[0-9A-Y]\b/, validate: validateFinnishHetu, labelled: true },
];
const NATIONAL_ID_LABEL_RE =
  /\b(?:personnummer|personal identity number|f[øo]dselsnummer|hetu|henkil[öo]tunnus|pesel|cnp|cod numeric personal|codul numeric personal|national id(?:entification)?(?: number)?)\b/i;
const NATIONAL_ID_LABEL_WINDOW = 32;
// Cheap guard: every shape carries a run of three digits, or a codice fiscale's letters.
const NATIONAL_ID_GUARD_RE = /\d{3}|[A-Z]{6}\d{2}/;

/** True if `text` holds a national identifier whose check digit holds. */
function hasNationalId(text: string): boolean {
  if (!NATIONAL_ID_GUARD_RE.test(text)) return false;
  const labelled = NATIONAL_ID_LABEL_RE.test(text);
  for (const shape of NATIONAL_ID_SHAPES) {
    if (shape.labelled && !labelled) continue;
    const flags = shape.regex.flags.includes('g') ? shape.regex.flags : shape.regex.flags + 'g';
    const re = new RegExp(shape.regex.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (!shape.validate(m[0])) continue;
      if (!shape.labelled) return true;
      const before = text.slice(Math.max(0, m.index - NATIONAL_ID_LABEL_WINDOW), m.index);
      if (NATIONAL_ID_LABEL_RE.test(before)) return true;
    }
  }
  return false;
}

/** True if `text` holds a checksum-valid routing number next to its label. */
function hasRoutingNumber(text: string): boolean {
  if (!ROUTING_LABEL_RE.test(text)) return false;
  const re = new RegExp(PII_ROUTING_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (!validateAbaRouting(m[0])) continue;
    const before = text.slice(Math.max(0, m.index - ROUTING_LABEL_WINDOW), m.index);
    const end = m.index + m[0].length;
    const after = text.slice(end, end + ROUTING_LABEL_WINDOW);
    if (ROUTING_LABEL_RE.test(before) || ROUTING_LABEL_RE.test(after)) return true;
  }
  return false;
}

// IBAN (ISO 13616): two letters, two check digits, then 11..30 alphanumerics
// optionally grouped by single spaces or dashes ("GB29 NWBK 6016 1331 9268 19").
// The natural `(?:[ -]?[A-Z0-9]){11,30}` is a nested quantifier and fails
// safe-regex2; this alternation form passes and behaves identically. It is
// greedy, so an IBAN followed by more text (a BIC) over-matches; validateIban
// applies the country length as a MINIMUM and validates the prefix, so the
// IBAN is still recognised. Uppercase only: a lowercase 22-char hex hash
// would otherwise reach mod-97 and pass 1 time in 97.
const PII_IBAN_RE = /\b[A-Z]{2}\d{2}(?:[A-Z0-9]|[ -][A-Z0-9]){11,30}\b/;

/**
 * Every card-shaped run in `text` that the detector accepts for one pattern:
 * not the fractional part of a number (isDecimalFraction) and passing Luhn.
 * Shared by hasValidCard and replaceValidCards, so detection and the masking
 * in exposure/mask.ts cannot drift apart.
 *
 * Two properties matter here and both were found by adversarial review:
 *
 * 1. OVERLAPPING search. On a rejected match the scan resumes at m.index + 1,
 *    not after the failed match. Otherwise a decoy 4-digit token directly in
 *    front of a real card ("4000 <valid visa>") is consumed together with the
 *    card's first three groups, fails Luhn, and the real card is never seen.
 *    The leading \b means the retry only lands on the next word boundary, so
 *    the cost is one extra exec per failed window, not one per character.
 *    An accepted run resumes after its end.
 *
 * 2. NO module-level /g regex. A shared global regex carries lastIndex across
 *    calls and the repo's house style is `.test()` on module-level regexes,
 *    which would reintroduce alternating results. A fresh RegExp per call is
 *    ~70 ns (V8 caches compiled patterns by source+flags) and cannot be
 *    misused.
 */
function* validCardRuns(
  text: string,
  base: RegExp,
  exemptFractions = true
): Generator<{ index: number; length: number; digits: string }> {
  const re = new RegExp(base.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const digits = m[0].replace(/\D/g, '');
    const fraction =
      exemptFractions && isDecimalFraction(text, m.index, digits.length === m[0].length);
    if (!fraction && validateLuhn(digits)) {
      yield { index: m.index, length: m[0].length, digits };
    } else {
      re.lastIndex = m.index + 1;
    }
  }
}

/** True if `text` contains at least one card the detector accepts. */
function hasValidCard(text: string): boolean {
  for (const base of CARD_PATTERNS) {
    if (!validCardRuns(text, base).next().done) return true;
  }
  return false;
}

/**
 * Replace every card the detector accepts with `replace(digits)`, the 16-digit
 * pattern first, then the 15-digit one on the result. Used by the personal
 * data masking (exposure/mask.ts), which shares the detector's patterns and
 * Luhn check. `exemptFractions: false` drops the decimal-fraction exemption:
 * masking text, a card after "1." is hidden too, at the cost of also hiding a
 * Luhn-valid fractional part (a log shows "0.**** ..."); the detector keeps
 * the exemption because a false positive there blocks the agent.
 */
export function replaceValidCards(
  text: string,
  replace: (digits: string) => string,
  { exemptFractions = true }: { exemptFractions?: boolean } = {}
): string {
  let out = text;
  for (const base of CARD_PATTERNS) {
    let res = '';
    let last = 0;
    for (const run of validCardRuns(out, base, exemptFractions)) {
      res += out.slice(last, run.index) + replace(run.digits);
      last = run.index + run.length;
    }
    out = res + out.slice(last);
  }
  return out;
}

/**
 * True if an unseparated digit run at `index` is the fractional part of a
 * number (node9Firewall#333). Three spellings are recognised:
 *   `<digit>.<run>`  "0.479...", "12.479..."  (JavaScript, Python, JSON)
 *   `.<run>`         ".479..." only at the very start of the text, or after a
 *                    sign that itself starts it ("-.479...")
 *   `0,<run>`        "0,479..." with the `0` at the start of the text or right
 *                    after ";" (a semicolon CSV with comma decimals)
 * Anywhere else the dot or the "0," is one character an injected instruction
 * can put in front of a card ("text=.<card>"), so the run is judged as a card.
 * A full-precision leading-dot fraction is rare in practice (JavaScript,
 * Python, Go and JSON print "0."; bc prints 20 digits, which no card pattern
 * matches); 0 of the strings in 994 local session transcripts changed when
 * the exemption was narrowed from "after any number-lead character".
 * A grouped run ("4xxx 4xxx ...") is never a fraction, so it is not exempt.
 * A comma after any other digit is NOT exempt: "1,<run>" is a CSV row.
 */
function isDecimalFraction(text: string, index: number, unseparated: boolean): boolean {
  if (!unseparated) return false;
  const sep = text[index - 1];
  const a = text[index - 2]; // undefined at the start of the text
  if (sep === '.') {
    if (a !== undefined && a >= '0' && a <= '9') return true;
    return a === undefined || ((a === '-' || a === '+') && index === 2);
  }
  if (sep === ',' && a === '0') {
    const b = text[index - 3];
    return b === undefined || b === ';';
  }
  return false;
}

/** Same overlapping-search shape as hasValidCard; validateIban strips formatting itself. */
function hasValidIban(text: string): boolean {
  const re = new RegExp(PII_IBAN_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (validateIban(m[0])) return true;
    re.lastIndex = m.index + 1;
  }
  return false;
}

export type PiiPattern =
  'Email' | 'SSN' | 'Phone' | 'Credit Card' | 'IBAN' | 'Bank Routing Number' | 'National ID';

/**
 * Detect PII patterns in a string. Returns a deduplicated list — one entry
 * per distinct pattern type, never multiple "Email" findings from one input.
 */
export function detectPii(text: string): PiiPattern[] {
  const found = new Set<PiiPattern>();
  // Cheap substring guards before the full regex — most strings contain none
  // of these characters and skip the regex engine entirely.
  if (/@/.test(text) && PII_EMAIL_RE.test(text)) found.add('Email');
  if (/-/.test(text) && PII_SSN_RE.test(text)) found.add('SSN');
  if (PII_PHONE_RE.test(text)) found.add('Phone');
  if (hasValidCard(text)) found.add('Credit Card');
  if (hasValidIban(text)) found.add('IBAN');
  if (hasRoutingNumber(text)) found.add('Bank Routing Number');
  if (hasNationalId(text)) found.add('National ID');
  return [...found];
}

// High-signal PII worth gating in REAL TIME. Email and Phone are deliberately
// excluded — they appear constantly in normal dev work (commit author emails,
// configs, fixtures) and would make realtime enforcement too noisy. They are
// still surfaced by the offline scan via detectPii(). SSN and Credit Card
// require structural delimiters and are rarely legitimate in agent tool args.
// IBAN joins the realtime set: the country registry plus mod-97 leave a
// residual false-positive class of roughly 1 in 97 registered-prefix
// hex-looking tokens at exactly the right length, and 0 regex hits were
// measured over 50,867 strings of real history.
// A routing number joins it for the same reason: a checksum plus a label, and
// a bank's routing number next to the word "routing" is bank details leaving
// the machine, not dev work.
export const REALTIME_PII_PATTERNS: readonly PiiPattern[] = [
  'SSN',
  'Credit Card',
  'IBAN',
  'Bank Routing Number',
  'National ID',
];

// Don't scan more than 100 KB of string content per call — mirrors the DLP
// scanner's MAX_STRING_BYTES bound so a huge tool payload can't stall the
// regexes. Applied cumulatively across leaves.
const MAX_PII_SCAN_BYTES = 100_000;

/**
 * Walk a tool-args value and yield every string leaf, plus finite numbers as
 * their decimal text (a 16-digit card fits under MAX_SAFE_INTEGER and used to
 * be caught via JSON.stringify; keep that). Depth-capped so a circular object
 * terminates. Mirrors `stringValues` in canonical.ts.
 */
function* stringLeaves(
  v: unknown,
  depth = 0,
  key?: string
): Generator<[string, string | undefined]> {
  if (depth > 6) return;
  if (typeof v === 'string') {
    if (v.length > 0) yield [v, key];
    return;
  }
  if (typeof v === 'number') {
    if (Number.isFinite(v)) yield [String(v), key];
    return;
  }
  if (!v || typeof v !== 'object') return;
  if (Array.isArray(v)) {
    for (const x of v) yield* stringLeaves(x, depth + 1, key);
    return;
  }
  for (const [k, x] of Object.entries(v)) yield* stringLeaves(x, depth + 1, k);
}

/** Every string leaf of a tool call's arguments, joined by newlines, bounded. */
export function argumentLeavesText(args: unknown, limit = MAX_PII_SCAN_BYTES): string {
  const parts: string[] = [];
  let size = 0;
  for (const [leaf] of stringLeaves(args)) {
    if (size >= limit) break;
    parts.push(leaf);
    size += leaf.length + 1;
  }
  return parts.join('\n').slice(0, limit);
}

// Argument keys under which an IBAN is WHERE the money goes, not personal
// data leaking: a transfer's `recipient`, an email's `to`, a payment's
// `iban`. The exposure gate judges such a destination; the PII gate stays
// out of its way when the IBAN is the whole value (fw#372 X1). An IBAN inside
// a longer text under the same key is still leaked data.
const IBAN_DESTINATION_KEYS = new Set([
  'to',
  'recipient',
  'recipients',
  'payee',
  'beneficiary',
  'destination',
  'iban',
  'account',
  'account_number',
  'accountnumber',
]);
const WHOLE_IBAN_RE = /^[A-Z]{2}\d{2}[A-Z0-9 -]{11,34}$/;

function isIbanDestination(leaf: string, key: string | undefined): boolean {
  if (!key || !IBAN_DESTINATION_KEYS.has(key.toLowerCase())) return false;
  const value = leaf.trim();
  return WHOLE_IBAN_RE.test(value) && validateIban(value);
}

// JSON string escapes that hide a word boundary: `\n`, `\t`, `\r`, `\"`,
// `\\`, `\/` and `\uXXXX`. A leaf that carries them is text typed INTO a
// shell or an HTTP body (a curl `-d '{"rows":"a\n<card>"}'`), where the
// escape is two characters and `n` is a word character, so a card or an SSN
// that starts a line inside it had no `\b` in front (fw#372 A4).
const JSON_ESCAPE_RE = /\\(?:[ntr"\\/]|u[0-9a-fA-F]{4})/g;
const JSON_ESCAPES: Record<string, string> = {
  n: '\n',
  t: '\t',
  r: '\r',
  '"': '"',
  '\\': '\\',
  '/': '/',
};

/** The leaf with its JSON string escapes decoded, or null when it has none. */
function jsonUnescapedView(leaf: string): string | null {
  if (!/\\[ntr"\\/u]/.test(leaf)) return null;
  return leaf.replace(JSON_ESCAPE_RE, (m) =>
    m[1] === 'u' ? String.fromCharCode(parseInt(m.slice(2), 16)) : JSON_ESCAPES[m[1]]
  );
}

/**
 * Realtime adapter for detectPii: walks a tool-args value leaf by leaf and
 * returns only the high-signal PII patterns found. Used by the authorize path
 * to gate SSN / Credit Card in tool arguments. Pure.
 *
 * Walks leaves rather than scanning JSON.stringify(args). Stringifying turns
 * a real newline into the two characters backslash + `n`, and `n` is a word
 * character, so a card or SSN that BEGINS A LINE inside a multi-line value
 * (a CSV being written, for instance) had no \b in front of it and was
 * invisible to the realtime gate. Raw leaves keep the real newline.
 */
export function detectArgsPii(args: unknown): PiiPattern[] {
  if (args === null || args === undefined) return [];
  const found = new Set<PiiPattern>();
  let budget = MAX_PII_SCAN_BYTES;
  try {
    for (const [leaf, key] of stringLeaves(args)) {
      if (budget <= 0) break;
      const t = leaf.length > budget ? leaf.slice(0, budget) : leaf;
      budget -= t.length;
      const destination = isIbanDestination(t, key);
      for (const view of [t, jsonUnescapedView(t)]) {
        if (view === null) continue;
        for (const p of detectPii(view)) {
          if (p === 'IBAN' && destination) continue;
          if (REALTIME_PII_PATTERNS.includes(p)) found.add(p);
        }
      }
    }
  } catch {
    // A getter that throws, or similar. Tool args from hook payloads are
    // JSON-origin so this is defensive; fail open to "no PII found",
    // consistent with the previous behaviour.
    return [];
  }
  return [...found];
}
