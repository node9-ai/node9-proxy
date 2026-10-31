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

/**
 * ABA routing transit number (US bank): nine digits, weights 3-7-1 repeating,
 * sum 0 mod 10, and a first pair in a range the Federal Reserve assigns
 * (00-12 banks, 21-32 thrifts, 61-72 electronic, 80 traveller's cheques).
 * Digits only, like validateLuhn.
 */
export function validateAbaRouting(digits: string): boolean {
  if (!/^\d{9}$/.test(digits)) return false;
  const prefix = Number(digits.slice(0, 2));
  const assigned =
    prefix <= 12 ||
    (prefix >= 21 && prefix <= 32) ||
    (prefix >= 61 && prefix <= 72) ||
    prefix === 80;
  if (!assigned) return false;
  const weights = [3, 7, 1, 3, 7, 1, 3, 7, 1];
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += (digits.charCodeAt(i) - 48) * weights[i];
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
 * BBAN shapes from the SWIFT registry for the countries whose format is fixed
 * and common in practice. A country not listed keeps the length-only rule.
 */
const IBAN_BBAN_SHAPE: Readonly<Record<string, RegExp>> = {
  AT: /^\d{16}$/,
  BE: /^\d{12}$/,
  CH: /^\d{5}[A-Z0-9]{12}$/,
  CZ: /^\d{20}$/,
  DE: /^\d{18}$/,
  DK: /^\d{14}$/,
  ES: /^\d{20}$/,
  FI: /^\d{14}$/,
  FR: /^\d{10}[A-Z0-9]{11}\d{2}$/,
  GB: /^[A-Z]{4}\d{14}$/,
  HU: /^\d{24}$/,
  IE: /^[A-Z]{4}\d{14}$/,
  IL: /^\d{19}$/,
  IT: /^[A-Z]\d{10}[A-Z0-9]{12}$/,
  LU: /^\d{3}[A-Z0-9]{13}$/,
  NL: /^[A-Z]{4}\d{10}$/,
  NO: /^\d{11}$/,
  PL: /^\d{24}$/,
  PT: /^\d{21}$/,
  RO: /^[A-Z]{4}[A-Z0-9]{16}$/,
  SE: /^\d{20}$/,
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
  // The country's BBAN shape, where the registry fixes one (fw#372 X5): a
  // German BBAN is 18 digits, so a hex-looking token that happens to pass
  // mod-97 under a DE prefix is not an IBAN.
  const shape = IBAN_BBAN_SHAPE[iban.slice(0, 2)];
  if (shape && !shape.test(iban.slice(4))) return false;
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

// ─────────────────────────────────────────────────────────────────────────────
// National identifiers with a check digit (fw#372 B2). Each validator takes
// the identifier as written (separators allowed where the format has them)
// and answers only "does its own check digit hold", plus the date and range
// rules the issuing authority publishes. The regex in pii.ts chooses the
// shape; nothing here guesses.
// ─────────────────────────────────────────────────────────────────────────────

/** A plausible calendar day: month 1-12, day 1-31. Two-digit fields. */
function plausibleDate(mm: string, dd: string): boolean {
  const m = Number(mm);
  const d = Number(dd);
  return m >= 1 && m <= 12 && d >= 1 && d <= 31;
}

const CF_ODD: Record<string, number> = {};
const CF_EVEN: Record<string, number> = {};
{
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const odd = [
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8,
    12, 14, 16, 10, 22, 25, 24, 23,
  ];
  for (let i = 0; i < alphabet.length; i++) {
    const c = alphabet[i];
    CF_ODD[c] = odd[i];
    CF_EVEN[c] = i < 10 ? i : i - 10;
  }
}

/** Italian codice fiscale: 15 characters and a check letter (odd/even tables, mod 26). */
export function validateCodiceFiscale(raw: string): boolean {
  const s = raw.toUpperCase();
  if (!/^[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]$/.test(s)) return false;
  let sum = 0;
  for (let i = 0; i < 15; i++) sum += (i % 2 === 0 ? CF_ODD : CF_EVEN)[s[i]];
  return s[15] === String.fromCharCode(65 + (sum % 26));
}

const SPANISH_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';

/** Spanish DNI (8 digits + letter) or NIE (X/Y/Z + 7 digits + letter), mod 23. */
export function validateSpanishId(raw: string): boolean {
  const s = raw.toUpperCase();
  const m = /^([XYZ]?)(\d{7,8})([A-Z])$/.exec(s);
  if (!m) return false;
  if ((m[1] === '' && m[2].length !== 8) || (m[1] !== '' && m[2].length !== 7)) return false;
  const digits = (m[1] === '' ? '' : String('XYZ'.indexOf(m[1]))) + m[2];
  return SPANISH_LETTERS[Number(digits) % 23] === m[3];
}

/** Polish PESEL: 11 digits, a coded birth date, weights 1-3-7-9. */
export function validatePesel(raw: string): boolean {
  if (!/^\d{11}$/.test(raw)) return false;
  // The month carries the century: 01-12 1900s, 21-32 2000s, 41-52 2100s,
  // 61-72 2200s, 81-92 1800s.
  const month = Number(raw.slice(2, 4)) % 20;
  if (!plausibleDate(String(month).padStart(2, '0'), raw.slice(4, 6))) return false;
  const weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
  let sum = 0;
  for (let i = 0; i < 10; i++) sum += (raw.charCodeAt(i) - 48) * weights[i];
  return (10 - (sum % 10)) % 10 === raw.charCodeAt(10) - 48;
}

/** Romanian CNP: S YYMMDD JJ NNN C, county 01-52 (or 70/71 for records abroad), key 279146358279. */
export function validateCnp(raw: string): boolean {
  if (!/^[1-9]\d{12}$/.test(raw)) return false;
  if (!plausibleDate(raw.slice(3, 5), raw.slice(5, 7))) return false;
  const county = Number(raw.slice(7, 9));
  if (!((county >= 1 && county <= 52) || county === 70 || county === 71)) return false;
  const key = '279146358279';
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += (raw.charCodeAt(i) - 48) * (key.charCodeAt(i) - 48);
  const r = sum % 11;
  return (r === 10 ? 1 : r) === raw.charCodeAt(12) - 48;
}

/** French NIR (numéro de sécurité sociale): 13 digits (Corsica 2A/2B) and a 2-digit key, 97 - n mod 97. */
export function validateNir(raw: string): boolean {
  const s = raw.replace(/\s+/g, '').toUpperCase();
  const m = /^([12]\d{2}(0[1-9]|1[0-2]|[2-9]\d)(\d{2}|2A|2B)\d{6})(\d{2})$/.exec(s);
  if (!m) return false;
  const body = m[1].replace('2A', '19').replace('2B', '18');
  const key = Number(m[4]);
  return key >= 1 && key <= 97 && 97 - (Number(body) % 97) === key;
}

/** Swiss AHV number 756.XXXX.XXXX.XX: an EAN-13 check digit. */
export function validateSwissAhv(raw: string): boolean {
  const m = /^756\.(\d{4})\.(\d{4})\.(\d{2})$/.exec(raw);
  if (!m) return false;
  const digits = '756' + m[1] + m[2] + m[3];
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += (digits.charCodeAt(i) - 48) * (i % 2 === 0 ? 1 : 3);
  return (10 - (sum % 10)) % 10 === digits.charCodeAt(12) - 48;
}

/** Swiss enterprise identifier CHE-XXX.XXX.XXX: mod 11 with weights 5-4-3-2-7-6-5-4. */
export function validateSwissUid(raw: string): boolean {
  const m = /^CHE-(\d{3})\.(\d{3})\.(\d{3})$/i.exec(raw);
  if (!m) return false;
  const digits = m[1] + m[2] + m[3];
  const weights = [5, 4, 3, 2, 7, 6, 5, 4];
  let sum = 0;
  for (let i = 0; i < 8; i++) sum += (digits.charCodeAt(i) - 48) * weights[i];
  const check = 11 - (sum % 11);
  if (check === 10) return false;
  return (check === 11 ? 0 : check) === digits.charCodeAt(8) - 48;
}

/** Swedish personnummer YYMMDD-XXXX (or +): Luhn over the ten digits. */
export function validateSwedishPersonnummer(raw: string): boolean {
  const m = /^(\d{2})(\d{2})(\d{2})[-+](\d{4})$/.exec(raw);
  if (!m) return false;
  if (!plausibleDate(m[2], m[3])) return false;
  const digits = m[1] + m[2] + m[3] + m[4];
  let sum = 0;
  for (let i = 0; i < 10; i++) {
    let d = digits.charCodeAt(i) - 48;
    if (i % 2 === 0) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/** Norwegian fødselsnummer: DDMMYY, three digits, two mod-11 control digits. */
export function validateNorwegianFnr(raw: string): boolean {
  if (!/^\d{11}$/.test(raw)) return false;
  if (!plausibleDate(raw.slice(2, 4), raw.slice(0, 2))) return false;
  const control = (weights: number[], upto: number): number => {
    let sum = 0;
    for (let i = 0; i < upto; i++) sum += (raw.charCodeAt(i) - 48) * weights[i];
    const k = 11 - (sum % 11);
    return k === 11 ? 0 : k;
  };
  const k1 = control([3, 7, 6, 1, 8, 9, 4, 5, 2], 9);
  const k2 = control([5, 4, 3, 2, 7, 6, 5, 4, 3, 2], 10);
  return k1 < 10 && k2 < 10 && k1 === raw.charCodeAt(9) - 48 && k2 === raw.charCodeAt(10) - 48;
}

const HETU_CHARS = '0123456789ABCDEFHJKLMNPRSTUVWXY';

/** Finnish henkilötunnus DDMMYYCZZZQ: the control character is (DDMMYYZZZ mod 31) in a 31-character alphabet. */
export function validateFinnishHetu(raw: string): boolean {
  const m = /^(\d{2})(\d{2})(\d{2})[-+A-FU-Y](\d{3})([0-9A-Y])$/.exec(raw.toUpperCase());
  if (!m) return false;
  if (!plausibleDate(m[2], m[1])) return false;
  const n = Number(m[1] + m[2] + m[3] + m[4]);
  return HETU_CHARS[n % 31] === m[5];
}

// ─────────────────────────────────────────────────────────────────────────────
// National and tax identifiers, second round (node9Firewall#385, step 5 of
// #416). Same contract as above: the identifier as written, the issuing
// authority's own check digit and range rules, nothing guessed.
// ─────────────────────────────────────────────────────────────────────────────

/** Israeli identity number: 9 digits, weights 1,2 alternating, digit sums, mod 10. */
export function validateIsraeliId(raw: string): boolean {
  if (!/^\d{9}$/.test(raw)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    let n = (raw.charCodeAt(i) - 48) * (i % 2 === 0 ? 1 : 2);
    if (n > 9) n -= 9;
    sum += n;
  }
  return sum % 10 === 0;
}

/** Dutch BSN: 9 digits, the 11-proof (weights 9..2, the last digit counted negative). */
export function validateBsn(raw: string): boolean {
  if (!/^\d{9}$/.test(raw)) return false;
  let sum = 0;
  for (let i = 0; i < 8; i++) sum += (raw.charCodeAt(i) - 48) * (9 - i);
  sum -= raw.charCodeAt(8) - 48;
  return sum % 11 === 0;
}

/**
 * German Steuer-ID (IdNr): 11 digits, first not 0; among the first ten,
 * exactly one digit appears two or three times and the others at most once;
 * the eleventh is the ISO 7064 mod 11,10 check digit.
 */
export function validateSteuerId(raw: string): boolean {
  if (!/^[1-9]\d{10}$/.test(raw)) return false;
  const counts = new Array<number>(10).fill(0);
  for (let i = 0; i < 10; i++) counts[raw.charCodeAt(i) - 48]++;
  const repeated = counts.filter((c) => c > 1);
  if (repeated.length !== 1 || repeated[0] > 3) return false;
  let product = 10;
  for (let i = 0; i < 10; i++) {
    let sum = (raw.charCodeAt(i) - 48 + product) % 10;
    if (sum === 0) sum = 10;
    product = (2 * sum) % 11;
  }
  let check = 11 - product;
  if (check === 10) check = 0;
  return check === raw.charCodeAt(10) - 48;
}

/** Brazilian CPF: 11 digits (###.###.###-## or bare), two mod-11 check digits; not all one digit. */
export function validateCpf(raw: string): boolean {
  const d = raw.replace(/[.-]/g, '');
  if (!/^\d{11}$/.test(d) || /^(\d)\1{10}$/.test(d)) return false;
  for (const n of [9, 10]) {
    let sum = 0;
    for (let i = 0; i < n; i++) sum += (d.charCodeAt(i) - 48) * (n + 1 - i);
    let r = (sum * 10) % 11;
    if (r === 10) r = 0;
    if (r !== d.charCodeAt(n) - 48) return false;
  }
  return true;
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/** The Verhoeff check over a digit string (the last digit is the check digit). */
export function validateVerhoeff(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let c = 0;
  const n = digits.length;
  for (let i = 0; i < n; i++) {
    const d = digits.charCodeAt(n - 1 - i) - 48;
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][d]];
  }
  return c === 0;
}

/** Indian Aadhaar: 12 digits (#### #### #### or bare), first digit 2-9, Verhoeff. */
export function validateAadhaar(raw: string): boolean {
  const d = raw.replace(/ /g, '');
  if (!/^[2-9]\d{11}$/.test(d)) return false;
  return validateVerhoeff(d);
}

/** Canadian SIN: 9 digits (### ### ### or bare), Luhn (its own sum: validateLuhn is card-length only), first digit not 8. */
export function validateSin(raw: string): boolean {
  const d = raw.replace(/[ -]/g, '');
  if (!/^[0-79]\d{8}$/.test(d)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    let n = (d.charCodeAt(i) - 48) * (i % 2 === 1 ? 2 : 1);
    if (n > 9) n -= 9;
    sum += n;
  }
  return sum % 10 === 0;
}

/** Australian TFN: 9 digits (### ### ### or bare) with weights 1,4,3,7,5,8,6,9,10, mod 11. */
export function validateTfn(raw: string): boolean {
  const d = raw.replace(/ /g, '');
  if (!/^\d{9}$/.test(d)) return false;
  const weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += (d.charCodeAt(i) - 48) * weights[i];
  return sum % 11 === 0;
}

/** Chinese resident identity number: 17 digits with a YYYYMMDD birth date, then an ISO 7064 mod 11-2 check character. */
export function validateChineseId(raw: string): boolean {
  const s = raw.toUpperCase();
  const m = /^\d{6}(\d{4})(\d{2})(\d{2})\d{3}([0-9X])$/.exec(s);
  if (!m) return false;
  const year = Number(m[1]);
  if (year < 1900 || year > 2100 || !plausibleDate(m[2], m[3])) return false;
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += (s.charCodeAt(i) - 48) * weights[i];
  return '10X98765432'[sum % 11] === m[4];
}

/** Portuguese NIF: 9 digits, weights 9..2, mod 11 (10 and 11 read as 0). */
export function validatePortugueseNif(raw: string): boolean {
  if (!/^[1-9]\d{8}$/.test(raw)) return false;
  let sum = 0;
  for (let i = 0; i < 8; i++) sum += (raw.charCodeAt(i) - 48) * (9 - i);
  let check = 11 - (sum % 11);
  if (check >= 10) check = 0;
  return check === raw.charCodeAt(8) - 48;
}

/** Belgian national number: YY.MM.DD-XXX.YY or 11 digits; 97 minus (the first nine mod 97), with a 2 prefix for births from 2000. */
export function validateBelgianNationalNumber(raw: string): boolean {
  const d = raw.replace(/[.-]/g, '');
  if (!/^\d{11}$/.test(d)) return false;
  // A date is encoded unless the month is unknown (00) or shifted (+20/+40 for bis numbers).
  const month = Number(d.slice(2, 4)) % 20;
  if (month !== 0 && !plausibleDate(String(month).padStart(2, '0'), d.slice(4, 6))) return false;
  const base = Number(d.slice(0, 9));
  const check = Number(d.slice(9, 11));
  return 97 - (base % 97) === check || 97 - ((2_000_000_000 + base) % 97) === check;
}

/** Argentine CUIT / CUIL: ##-########-# or 11 digits, weights 5,4,3,2,7,6,5,4,3,2, mod 11. */
export function validateCuit(raw: string): boolean {
  const d = raw.replace(/-/g, '');
  if (!/^\d{11}$/.test(d)) return false;
  // Type prefixes in use: 20, 23, 24, 27 (persons), 30, 33, 34 (companies).
  if (!/^(?:2[0347]|3[034])/.test(d)) return false;
  const weights = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 10; i++) sum += (d.charCodeAt(i) - 48) * weights[i];
  let check = 11 - (sum % 11);
  if (check === 11) check = 0;
  if (check === 10) check = 9;
  return check === d.charCodeAt(10) - 48;
}

/** Turkish TCKN: 11 digits, first not 0; two check digits over the first nine and ten. */
export function validateTckn(raw: string): boolean {
  if (!/^[1-9]\d{10}$/.test(raw)) return false;
  const a = Array.from(raw, (c) => c.charCodeAt(0) - 48);
  const odd = a[0] + a[2] + a[4] + a[6] + a[8];
  const even = a[1] + a[3] + a[5] + a[7];
  const tenth = (odd * 7 - even) % 10;
  if ((tenth + 10) % 10 !== a[9]) return false;
  const eleventh = a.slice(0, 10).reduce((s, n) => s + n, 0) % 10;
  return eleventh === a[10];
}
