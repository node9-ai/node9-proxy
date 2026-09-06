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
// This file is part of the extractor-version hash set
// (scripts/check-extractor-version.mjs): editing it changes detector output.

import { validateLuhn } from './checksums';

const PII_EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const PII_SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/;
const PII_PHONE_RE = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/;

// Card regexes are REGEX LITERALS, not strings: a literal is syntax-checked at
// parse time, whereas `new RegExp('\b...')` in a plain string compiles to a
// backspace and silently matches nothing. The global copies used for scanning
// are derived from `.source` per call — see hasValidCard for why they are
// never held at module level.
//
// 16 digits, 4-4-4-4: Visa (4), Mastercard (51-55), Discover (6). The Amex
// prefixes are deliberately NOT here: Amex is 15 digits, so any 16-digit run
// starting 34/37 is by construction not a card.
const PII_CC16_RE = /\b(?:4\d{3}|5[1-5]\d{2}|6\d{3})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/;
// 15 digits, 4-6-5: American Express (34, 37).
const PII_CC15_RE = /\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b/;

/**
 * True if `text` contains at least one card-shaped run that also passes Luhn.
 *
 * Two properties matter here and both were found by adversarial review:
 *
 * 1. OVERLAPPING search. On a Luhn failure the scan resumes at m.index + 1,
 *    not after the failed match. Otherwise a decoy 4-digit token directly in
 *    front of a real card ("4000 <valid visa>") is consumed together with the
 *    card's first three groups, fails Luhn, and the real card is never seen.
 *    The leading \b means the retry only lands on the next word boundary, so
 *    the cost is one extra exec per failed window, not one per character.
 *
 * 2. NO module-level /g regex. A shared global regex carries lastIndex across
 *    calls and the repo's house style is `.test()` on module-level regexes,
 *    which would reintroduce alternating results. A fresh RegExp per call is
 *    ~70 ns (V8 caches compiled patterns by source+flags) and cannot be
 *    misused.
 */
function hasValidCard(text: string): boolean {
  for (const base of [PII_CC16_RE, PII_CC15_RE]) {
    const re = new RegExp(base.source, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (validateLuhn(m[0].replace(/\D/g, ''))) return true;
      re.lastIndex = m.index + 1;
    }
  }
  return false;
}

export type PiiPattern = 'Email' | 'SSN' | 'Phone' | 'Credit Card';

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
  return [...found];
}

// High-signal PII worth gating in REAL TIME. Email and Phone are deliberately
// excluded — they appear constantly in normal dev work (commit author emails,
// configs, fixtures) and would make realtime enforcement too noisy. They are
// still surfaced by the offline scan via detectPii(). SSN and Credit Card
// require structural delimiters and are rarely legitimate in agent tool args.
export const REALTIME_PII_PATTERNS: readonly PiiPattern[] = ['SSN', 'Credit Card'];

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
function* stringLeaves(v: unknown, depth = 0): Generator<string> {
  if (depth > 6) return;
  if (typeof v === 'string') {
    if (v.length > 0) yield v;
    return;
  }
  if (typeof v === 'number') {
    if (Number.isFinite(v)) yield String(v);
    return;
  }
  if (!v || typeof v !== 'object') return;
  if (Array.isArray(v)) {
    for (const x of v) yield* stringLeaves(x, depth + 1);
    return;
  }
  for (const x of Object.values(v)) yield* stringLeaves(x, depth + 1);
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
    for (const leaf of stringLeaves(args)) {
      if (budget <= 0) break;
      const t = leaf.length > budget ? leaf.slice(0, budget) : leaf;
      budget -= t.length;
      for (const p of detectPii(t)) {
        if (REALTIME_PII_PATTERNS.includes(p)) found.add(p);
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
