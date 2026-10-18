// Personal data in what node9 stores and ships (fw#318 review fixes, F4/P1).
//
// A destination ('email:x@y', 'iban:GB82...', 'account:..', 'host:h') is
// kept in full only on the developer's machine: the gate compares full
// values, the approval prompt names them. Everywhere else (the audit log, the
// shipper, the held card on the dashboard, the snapshot) an address or an
// account number is MASKED for display and carried with a SHA-256 of its
// normalised value, so a trusted-recipient list can still match it. A host is
// not personal data and stays in full.
//
// The backend carries a mirror of the destination functions
// (node9Firewall be/src/firewall/personal-data.ts). Both test suites assert
// the same vectors (personal-data.vectors.json beside this file, a copy of
// node9Firewall contract/personal-data.vectors.json), so they cannot drift.
// Design: docs/roadmap/active/untrusted-content-review-fixes-plan.md, 3.1.
//
// Pure, never throws.

import { createHash } from 'crypto';
import { validateIban, validateLuhn } from '../scan/checksums';

const MASKED_KINDS = new Set(['email', 'iban', 'account']);
const ENTRY_RE =
  /^(email|iban|account):([^#\s]{1,200}(?: [^#\s]{1,40}){0,4})#sha256:([0-9a-f]{64})$/;

function split(dest: string): { kind: string; value: string } | null {
  const i = dest.indexOf(':');
  if (i <= 0) return null;
  return { kind: dest.slice(0, i).toLowerCase(), value: dest.slice(i + 1) };
}

/** The value as the gate compares it: email lower-cased, IBAN and account
 *  upper-cased without spaces, host lower-cased. */
export function normalizeDestination(dest: string): string {
  const p = split(dest.trim());
  if (!p) return dest.trim();
  if (p.kind === 'iban' || p.kind === 'account')
    return `${p.kind}:${p.value.replace(/\s+/g, '').toUpperCase()}`;
  return `${p.kind}:${p.value.toLowerCase()}`;
}

function maskEmailValue(address: string): string {
  const at = address.lastIndexOf('@');
  if (at <= 0) return '***';
  return `${address[0]}***@${address.slice(at + 1)}`;
}

/** 'iban:GB82 **** **** 5432', 'account:****5432', 'email:d***@acme.example';
 *  a host (or anything else) is returned normalised and otherwise unchanged. */
export function maskDestination(dest: string): string {
  const n = normalizeDestination(dest);
  const p = split(n);
  if (!p || !MASKED_KINDS.has(p.kind)) return n;
  if (p.kind === 'iban') return `iban:${p.value.slice(0, 4)} **** **** ${p.value.slice(-4)}`;
  if (p.kind === 'account') return `account:****${p.value.slice(-4)}`;
  return `email:${maskEmailValue(p.value)}`;
}

/** Whether a destination's kind is masked outside the machine. */
export function isMaskedKind(dest: string): boolean {
  const p = split(dest);
  return !!p && MASKED_KINDS.has(p.kind);
}

/** SHA-256 (hex) of the normalised destination, kind prefix included. */
export function hashDestination(dest: string): string {
  return createHash('sha256').update(normalizeDestination(dest), 'utf8').digest('hex');
}

/** Whether `entry` is a stored masked entry ('<masked>#sha256:<hex>'). */
export function isHashedEntry(entry: string): boolean {
  return ENTRY_RE.test(entry);
}

/** A full destination as it is stored on a trusted list outside the machine:
 *  a masked kind becomes '<masked>#sha256:<hex>', a host stays as it is. */
export function trustedEntryOf(dest: string): string {
  const n = normalizeDestination(dest);
  if (!isMaskedKind(n)) return n;
  return `${maskDestination(n)}#sha256:${hashDestination(n)}`;
}

/** Does a full destination match a stored entry (a hashed one, or a plain
 *  value as the local list and older managed lists hold)? */
export function matchesTrustedEntry(dest: string, entry: string): boolean {
  const m = ENTRY_RE.exec(entry);
  if (m) return hashDestination(dest) === m[3];
  return normalizeDestination(dest) === normalizeDestination(entry);
}

/** What a person reads for an entry: the masked part, without the hash. */
export function entryDisplay(entry: string): string {
  const i = entry.indexOf('#sha256:');
  return i > 0 ? entry.slice(0, i) : entry;
}

// ── Free text (tool arguments) ──────────────────────────────────────────────

// IBAN-shaped, with optional single spaces or dashes between groups; kept
// only when the mod-97 checksum holds.
const IBAN_TEXT_RE = /\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?\b/g;
// Card numbers as the PII detector reads them, kept only when Luhn holds.
const CARD16_RE = /\b(?:4\d{3}|5[1-5]\d{2}|6\d{3})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;
const CARD15_RE = /\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b/g;
const EMAIL_TEXT_RE =
  /[\p{L}\p{N}._%+-]+@[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?)*\.\p{L}{2,}/gu;
// A JSON string value under a key that names an account: the number is a
// destination even when no checksum holds (a sandbox account).
const ACCOUNT_KEY_RE =
  /("(?:iban|account|account_number|accountNumber)"\s*:\s*")([A-Za-z0-9 .-]{6,40})(")/g;
// A JSON string value that is IBAN-shaped as a whole: the gate reads it as an
// account (a sandbox account) even when the checksum fails, so it is masked
// under any key and inside arrays.
const ACCOUNT_VALUE_RE = /"([A-Z]{2}\d{2}[A-Z0-9]{11,30})"/g;

/**
 * IBANs (mod-97), card numbers (Luhn), account numbers (a whole IBAN-shaped
 * value, or a number under an account key) and email addresses inside a text, masked the way destinations are. Runs on
 * JSON-stringified arguments too: every replacement keeps the JSON valid
 * (no quote, no backslash is introduced or removed).
 */
export function maskPersonalData(text: string): string {
  if (!text) return text;
  try {
    let out = text;
    out = out.replace(IBAN_TEXT_RE, (m) => {
      const v = m.replace(/[ -]/g, '');
      return validateIban(v) ? `${v.slice(0, 4)} **** **** ${v.slice(-4)}` : m;
    });
    const card = (m: string) => {
      const digits = m.replace(/[-\s]/g, '');
      return validateLuhn(digits) ? `**** **** **** ${digits.slice(-4)}` : m;
    };
    out = out.replace(CARD16_RE, card).replace(CARD15_RE, card);
    out = out.replace(ACCOUNT_VALUE_RE, (_m, v: string) => `"****${v.slice(-4)}"`);
    // A name under the key ("account": "billing") is not a number: kept.
    out = out.replace(ACCOUNT_KEY_RE, (m, a: string, v: string, b: string) =>
      v.replace(/\D/g, '').length < 4 ? m : `${a}****${v.replace(/[ .-]/g, '').slice(-4)}${b}`
    );
    if (out.includes('@')) out = out.replace(EMAIL_TEXT_RE, (m) => maskEmailValue(m));
    return out;
  } catch {
    return text;
  }
}
