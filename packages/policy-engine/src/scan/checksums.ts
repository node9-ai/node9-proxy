// Checksum validators for structured identifiers. Pure functions, no I/O.
//
// A regex says "this LOOKS like a card number". A checksum says "this IS
// one" (to the precision of the check digit). Applying the checksum after
// the regex match removes the false-positive class structurally instead of
// suppressing it with a stopword list.
//
// This file is part of the extractor-version hash set
// (scripts/check-extractor-version.mjs): editing it changes detector output.

/**
 * Luhn (mod 10) check for payment card numbers.
 *
 * Contract: DIGITS ONLY. The caller strips separators. Any non-digit input
 * returns false rather than being cleaned here, so a caller that forgets to
 * strip fails loudly on the first separated fixture instead of silently
 * accepting everything.
 *
 * Degenerate inputs are rejected explicitly: fewer than 12 digits (no card
 * network issues those), and all-zeros (sums to 0, which a naive Luhn
 * accepts). Both are unreachable through the card regexes in pii.ts, which
 * only ever produce 15- or 16-digit runs with a non-zero lead, but this
 * function may gain other callers.
 */
export function validateLuhn(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  if (digits.length < 12) return false;
  if (!/[1-9]/.test(digits)) return false;

  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}
