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
