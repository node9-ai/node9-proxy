// PII detection. Pure regex over a string. Used by the canonical extractor
// (and historically by the daemon watermark) to flag email / SSN / phone /
// credit-card values that leak through tool output or assistant text.
//
// Each regex requires structural delimiters that real PII has:
//   - Email needs `@` plus a TLD-like suffix
//   - SSN needs the dash-delimited 3-2-4 layout
//   - Phone (US) needs 3-3-4 with separators
//   - Credit card needs 16 digits in groups of 4 with a valid IIN prefix
//
// Without these anchors the FP rate would explode. PII in non-standard
// layouts (no dashes for SSN, etc.) won't fire — known and acceptable gap.

const PII_EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const PII_SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/;
const PII_PHONE_RE = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/;
// IIN prefixes: Visa (4), Mastercard (51-55), Amex (34/37), Discover (6).
const PII_CC_RE = /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6\d{3})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/;

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
  if (PII_CC_RE.test(text)) found.add('Credit Card');
  return [...found];
}

// High-signal PII worth gating in REAL TIME. Email and Phone are deliberately
// excluded — they appear constantly in normal dev work (commit author emails,
// configs, fixtures) and would make realtime enforcement too noisy. They are
// still surfaced by the offline scan via detectPii(). SSN and Credit Card
// require structural delimiters and are rarely legitimate in agent tool args.
export const REALTIME_PII_PATTERNS: readonly PiiPattern[] = ['SSN', 'Credit Card'];

// Don't scan more than 100 KB of stringified args — mirrors the DLP scanner's
// MAX_STRING_BYTES bound so a huge tool payload can't stall the regexes.
const MAX_PII_SCAN_BYTES = 100_000;

/**
 * Realtime adapter for detectPii: walks a tool-args value (stringifying
 * objects/arrays) and returns only the high-signal PII patterns found. Used by
 * the authorize path to gate SSN / Credit Card in tool arguments. Pure.
 */
export function detectArgsPii(args: unknown): PiiPattern[] {
  if (args === null || args === undefined) return [];
  let text: string | undefined;
  try {
    text = typeof args === 'string' ? args : JSON.stringify(args);
  } catch {
    // Circular reference or otherwise non-serializable value. Tool args from
    // hook payloads are JSON-origin (never circular), so this is defensive for
    // other callers — fail open to "no PII found", consistent with detectPii.
    return [];
  }
  if (typeof text !== 'string') return [];
  if (text.length > MAX_PII_SCAN_BYTES) text = text.slice(0, MAX_PII_SCAN_BYTES);
  return detectPii(text).filter((p) => REALTIME_PII_PATTERNS.includes(p));
}
