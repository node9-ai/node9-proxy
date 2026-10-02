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

// ─────────────────────────────────────────────────────────────────────────────
// GitHub tokens — https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
// `gh[pousr]_` + 30 random base62 characters + 6 characters of checksum. The
// checksum is CRC32 over the 30 random characters (the prefix is NOT covered),
// Base62-encoded with the digits-first alphabet and zero-padded to 6. Verified
// against a live token before this landed: random-only matched, prefix-inclusive
// did not. Fine-grained PATs (`github_pat_`) are NOT validated here: their
// checksum scope is undocumented, so they keep the regex-only path.
// ─────────────────────────────────────────────────────────────────────────────
const B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

let CRC32_TABLE: Int32Array | null = null;

/** Plain CRC-32 (IEEE 802.3, reflected, 0xEDB88320), as unsigned. */
export function crc32(input: string | Uint8Array): number {
  if (!CRC32_TABLE) {
    CRC32_TABLE = new Int32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC32_TABLE[i] = c;
    }
  }
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  let c = -1;
  for (let i = 0; i < bytes.length; i++) c = CRC32_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

/** Base62 (0-9A-Za-z) of a 32-bit value, left-padded with '0' to 6 characters. */
export function base62Checksum(value: number): string {
  let n = value >>> 0;
  let s = '';
  while (n > 0) {
    s = B62[n % 62] + s;
    n = Math.floor(n / 62);
  }
  return s.padStart(6, '0');
}

const GITHUB_TOKEN_RE = /^gh[pousr]_([A-Za-z0-9]{30})([A-Za-z0-9]{6})$/;

/**
 * GitHub classic token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`): true when the
 * trailing 6 characters equal base62(crc32(random30)). A lookalike (a test
 * fixture, a hash, sample text) fails with probability 1 - 1/62^6.
 */
export function validateGithubToken(raw: string): boolean {
  const m = GITHUB_TOKEN_RE.exec(raw);
  if (!m) return false;
  return base62Checksum(crc32(m[1])) === m[2];
}

// ─────────────────────────────────────────────────────────────────────────────
// Microsoft Common Annotated Security Key (CASK) —
// https://github.com/microsoft/cask/blob/main/docs/CaskSecret.md
// The documented format carries NO checksum; what it publishes is a fixed
// layout: a `QJJQ` signature at a fixed offset after the sensitive data, size
// and provider fields with restricted alphabets, zero-valued reserved
// characters, and a timestamp whose six characters each have a bounded range.
// The validator checks every one of those positions, so a random base64url
// blob that happens to contain `QJJQ` is rejected unless the whole layout fits.
// ─────────────────────────────────────────────────────────────────────────────
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_INDEX: Readonly<Record<string, number>> = Object.fromEntries(
  [...B64URL].map((c, i) => [c, i])
);
const CASK_TWO_ZERO_SUFFIX = new Set([...'AEIMQUYcgkosw048']);
const CASK_FOUR_ZERO_SUFFIX = new Set([...'AQgw']);

function b64urlIndex(ch: string | undefined): number {
  return ch === undefined ? -1 : (B64URL_INDEX[ch] ?? -1);
}

/**
 * CASK secret layout check. `raw` may carry ONE leading and ONE trailing
 * delimiter (the pattern's regex consumes them, the way the Azure pattern
 * does), which are stripped before the layout is read.
 */
export function validateCask(raw: string): boolean {
  const s = raw.replace(/^[^A-Za-z0-9_-]/, '').replace(/[^A-Za-z0-9_-]$/, '');
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return false;
  // Sensitive-data block: 256-bit (42 + suffix + 'A' = 44) or 512-bit
  // (85 + suffix + 'AA' = 88). The size character after the signature must
  // agree with the block length.
  let sigAt: number;
  if (s.slice(44, 48) === 'QJJQ' && s[49] === 'B') {
    if (!CASK_TWO_ZERO_SUFFIX.has(s[42]) || s[43] !== 'A') return false;
    sigAt = 44;
  } else if (s.slice(88, 92) === 'QJJQ' && s[93] === 'C') {
    if (!CASK_FOUR_ZERO_SUFFIX.has(s[85]) || s.slice(86, 88) !== 'AA') return false;
    sigAt = 88;
  } else {
    return false;
  }
  if (s[sigAt + 4] !== 'A') return false; // 6 reserved bits
  const segments = b64urlIndex(s[sigAt + 6]); // provider-data segments, 'A'..'K'
  if (segments < 0 || segments > 10) return false;
  // sigAt+7: provider kind (any base64url); sigAt+8..+12: provider signature.
  const tsAt = sigAt + 12 + segments * 4 + 2;
  if (s.slice(tsAt - 2, tsAt) !== 'AA') return false; // 12 reserved bits
  if (s.length !== tsAt + 6) return false;
  const month = b64urlIndex(s[tsAt + 1]);
  const day = b64urlIndex(s[tsAt + 2]);
  const hour = b64urlIndex(s[tsAt + 3]);
  const minute = b64urlIndex(s[tsAt + 4]);
  const second = b64urlIndex(s[tsAt + 5]);
  return month <= 11 && day <= 30 && hour <= 23 && minute <= 59 && second <= 59;
}
