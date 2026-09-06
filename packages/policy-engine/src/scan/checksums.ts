import { createHash } from 'crypto';

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

// ─────────────────────────────────────────────────────────────────────────────
// IBAN — ISO 13616. Country code -> required total length, from the SWIFT
// IBAN Registry (Release 101, Dec 2025), https://www.swift.com/resource/iban-registry-pdf.
// Applied as a MINIMUM: a human-formatted IBAN followed by more text would
// otherwise over-match under the grouped regex and be lost, so validation runs
// on the first N characters for the country. A length-only registry cannot
// know per-country BBAN character classes (German BBAN is 18 digits), which is
// the documented residual false-positive class.
// ─────────────────────────────────────────────────────────────────────────────
export const IBAN_LENGTH: Readonly<Record<string, number>> = {
  AD: 24,
  AE: 23,
  AL: 28,
  AT: 20,
  AZ: 28,
  BA: 20,
  BE: 16,
  BG: 22,
  BH: 22,
  BI: 27,
  BR: 29,
  BY: 28,
  CH: 21,
  CR: 22,
  CY: 28,
  CZ: 24,
  DE: 22,
  DJ: 27,
  DK: 18,
  DO: 28,
  EE: 20,
  EG: 29,
  ES: 24,
  FI: 18,
  FK: 18,
  FO: 18,
  FR: 27,
  GB: 22,
  GE: 22,
  GI: 23,
  GL: 18,
  GR: 27,
  GT: 28,
  HN: 28,
  HR: 21,
  HU: 28,
  IE: 22,
  IL: 23,
  IQ: 23,
  IS: 26,
  IT: 27,
  JO: 30,
  KW: 30,
  KZ: 20,
  LB: 28,
  LC: 32,
  LI: 21,
  LT: 20,
  LU: 20,
  LV: 21,
  LY: 25,
  MC: 27,
  MD: 24,
  ME: 22,
  MK: 19,
  MN: 20,
  MR: 27,
  MT: 31,
  MU: 30,
  NI: 28,
  NL: 18,
  NO: 15,
  OM: 23,
  PK: 24,
  PL: 28,
  PS: 29,
  PT: 25,
  QA: 29,
  RO: 24,
  RS: 22,
  RU: 33,
  SA: 24,
  SC: 31,
  SD: 18,
  SE: 24,
  SI: 19,
  SK: 24,
  SM: 27,
  SN: 28,
  SO: 23,
  ST: 25,
  SV: 28,
  TL: 23,
  TN: 24,
  TR: 26,
  UA: 29,
  VA: 22,
  VG: 24,
  XK: 20,
  YE: 30,
};

/**
 * IBAN (ISO 13616). Contract: accepts human formatting (spaces, dashes, any
 * case), so the CALLER does not strip. Rejects an unregistered country, a
 * value shorter than the country's length, and a failing mod-97. The
 * registry length is a MINIMUM: validation runs on the first N characters,
 * so an IBAN followed by more text (a BIC, a reference) is still recognised.
 */
export function validateIban(raw: string): boolean {
  const s = raw.replace(/[ -]/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}/.test(s)) return false;
  const want = IBAN_LENGTH[s.slice(0, 2)];
  if (want === undefined || s.length < want) return false;
  const iban = s.slice(0, want);
  if (!/^[A-Z0-9]+$/.test(iban)) return false;
  // Move the first four characters to the end, map A..Z -> 10..35, take mod 97
  // as a stream so no big-integer is needed.
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let mod = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const digits = code >= 65 ? String(code - 55) : ch;
    for (const d of digits) mod = (mod * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return mod === 1;
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_INDEX: Readonly<Record<string, number>> = Object.fromEntries(
  [...B58].map((c, i) => [c, i])
);

/**
 * Base58Check. Returns the decoded payload (version byte included, checksum
 * removed) when the trailing 4 bytes equal the first 4 of SHA256(SHA256(body)),
 * else null. Any character outside the alphabet, or fewer than 5 decoded
 * bytes, is null. Leading '1's are leading 0x00 bytes.
 */
export function validateBase58Check(s: string): Buffer | null {
  if (!s) return null;
  let n = 0n;
  for (const c of s) {
    const v = B58_INDEX[c];
    if (v === undefined) return null;
    n = n * 58n + BigInt(v);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let zeros = 0;
  for (const c of s) {
    if (c !== '1') break;
    zeros++;
  }
  const bytes = Buffer.concat([
    Buffer.alloc(zeros),
    n === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex'),
  ]);
  if (bytes.length < 5) return null;
  const body = bytes.subarray(0, bytes.length - 4);
  const check = bytes.subarray(bytes.length - 4);
  const h = createHash('sha256').update(createHash('sha256').update(body).digest()).digest();
  return h.subarray(0, 4).equals(check) ? body : null;
}

/** Bitcoin WIF, mainnet only: version 0x80, 32-byte key, optional 0x01 compression flag. */
export function validateWif(s: string): boolean {
  const p = validateBase58Check(s);
  if (!p || p[0] !== 0x80) return false;
  return p.length === 33 || (p.length === 34 && p[33] === 0x01);
}

// BIP-32 / SLIP-132 mainnet PRIVATE extended-key versions: xprv, yprv, zprv.
// Testnet (tprv 0x04358394) is deliberately excluded, consistent with WIF.
const XPRV_VERSIONS = new Set([0x0488ade4, 0x049d7878, 0x04b2430c]);

/** BIP-32 extended private key: 78-byte payload, mainnet private version, 0x00 key marker. */
export function validateXprv(s: string): boolean {
  const p = validateBase58Check(s);
  if (!p || p.length !== 78) return false;
  const version = p.readUInt32BE(0);
  return XPRV_VERSIONS.has(version) && p[45] === 0x00;
}
