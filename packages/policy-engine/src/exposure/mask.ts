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
import { IBAN_LENGTH, validateIban } from '../scan/checksums';
import { replaceValidCards } from '../scan/pii';
import { extractArgDestinations } from './destinations';

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

/** Does a full destination match any entry of a list? Hashes it once. */
export function matchesTrustedList(dest: string, entries: readonly string[]): boolean {
  if (entries.length === 0) return false;
  const plain = normalizeDestination(dest);
  let hash: string | undefined;
  for (const entry of entries) {
    const m = ENTRY_RE.exec(entry);
    if (m) {
      hash ??= hashDestination(dest);
      if (hash === m[3]) return true;
    } else if (plain === normalizeDestination(entry)) return true;
  }
  return false;
}

/**
 * A recipient as a person types it, in the stored destination form: an
 * address becomes `email:`, an IBAN `iban:`, a URL or hostname `host:`, and
 * `account:<number>` keeps its kind. A value that carries its kind is checked
 * against it. Null for anything else (a bare word, two values in one).
 */
export function normalizeRecipient(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const v = raw.trim();
  if (!v || v.length > 512) return null;
  const acct = /^account:([A-Za-z0-9 ]{8,40})$/i.exec(v);
  if (acct) {
    const n = acct[1].replace(/\s+/g, '').toUpperCase();
    return n.length >= 8 && n.length <= 34 ? `account:${n}` : null;
  }
  if (/^(email|host|iban):/i.test(v)) {
    const i = v.indexOf(':');
    const kind = v.slice(0, i).toLowerCase();
    const inner = normalizeRecipient(v.slice(i + 1));
    return inner && inner.startsWith(`${kind}:`) ? inner : null;
  }
  const found = extractArgDestinations({ to: v });
  return found.length === 1 ? found[0] : null;
}

/**
 * One entry of a trusted list outside the machine (the dashboard's workspace
 * list, the snapshot's personal list): a host in full; an address, IBAN or
 * account as '<masked>#sha256:<hex>'. A value already in that form passes
 * with its hash lower-cased; a full value is turned into it. Null when it is
 * neither. The backend mirror asserts the same vectors.
 */
export function normalizeTrustedEntry(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const v = raw
    .trim()
    .replace(/#sha256:([0-9A-Fa-f]{64})$/, (_m, h: string) => `#sha256:${h.toLowerCase()}`);
  if (v.includes('#')) return isHashedEntry(v) ? v : null;
  const full = normalizeRecipient(v);
  return full === null ? null : trustedEntryOf(full);
}

/** What a person reads for an entry: the masked part, without the hash. */
export function entryDisplay(entry: string): string {
  const i = entry.indexOf('#sha256:');
  return i > 0 ? entry.slice(0, i) : entry;
}

// ── Free text (tool arguments) ──────────────────────────────────────────────

// IBAN-shaped in either case, with optional single spaces or dashes between
// groups; kept only when the mod-97 checksum holds.
const IBAN_TEXT_RE = /\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?\b/gi;
const EMAIL_TEXT_RE =
  /[\p{L}\p{N}._%+-]+@[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?)*\.\p{L}{2,}/gu;
// A JSON string value under a key that names an account: the number is a
// destination even when no checksum holds (a sandbox account).
const ACCOUNT_KEY_RE =
  /("(?:iban|account|account_number|accountNumber)"\s*:\s*")([A-Za-z0-9 .-]{6,40})(")/g;
// A JSON string value that is IBAN-shaped as a whole: the gate reads it as an
// account (a sandbox account) even when the checksum fails, so it is masked
// under any key and inside arrays, when its country is a registered one and
// its length is that country's. Uppercase only: with no checksum to hold,
// a lowercase hex id of the right length ("be12...", 16 characters) would
// otherwise be masked as an account.
const ACCOUNT_VALUE_RE = /"([A-Z]{2}\d{2}[A-Z0-9]{11,30})"/g;

/**
 * IBANs (mod-97), card numbers (exactly what detectPii reports, so not the
 * fractional part of a number), account numbers (a whole IBAN-shaped value,
 * or a number under an account key) and email addresses inside a text,
 * masked the way destinations are. No quote or backslash is introduced or
 * removed, so a JSON string stays a JSON string; a card written as a bare
 * JSON number does not stay a number, so arguments go through
 * maskPersonalValue instead.
 */
export function maskPersonalData(text: string): string {
  if (!text) return text;
  try {
    let out = text;
    out = out.replace(IBAN_TEXT_RE, (m) => {
      const v = m.replace(/[ -]/g, '').toUpperCase();
      return validateIban(v) ? `${v.slice(0, 4)} **** **** ${v.slice(-4)}` : m;
    });
    out = replaceValidCards(out, (digits) => `**** **** **** ${digits.slice(-4)}`);
    out = out.replace(ACCOUNT_VALUE_RE, (m, v: string) =>
      IBAN_LENGTH[v.slice(0, 2).toUpperCase()] === v.length ? `"****${v.slice(-4)}"` : m
    );
    // Only a number is masked under the key: a name ("billing") or a profile
    // ("prod-2024-eu") is kept. A number is six digits or more, and mostly digits.
    out = out.replace(ACCOUNT_KEY_RE, (m, a: string, v: string, b: string) => {
      const compact = v.replace(/[ .-]/g, '');
      const digits = compact.replace(/\D/g, '').length;
      return digits >= 6 && digits * 2 >= compact.length ? `${a}****${compact.slice(-4)}${b}` : m;
    });
    if (out.includes('@')) out = out.replace(EMAIL_TEXT_RE, (m) => maskEmailValue(m));
    return out;
  } catch {
    return text;
  }
}

const MAX_MASK_DEPTH = 64;

/**
 * maskPersonalData over a JSON-shaped value (tool arguments), leaf by leaf, so
 * the result is always a value: a string leaf is masked in its JSON form under
 * its own key (the account-key and whole-value rules still see both), an
 * object key is masked as text, and a number whose text holds personal data (a
 * card passed as a number) becomes the masked string. Anything deeper than 64
 * levels is replaced by '[REDACTED]'. Pure, never throws.
 */
export function maskPersonalValue(value: unknown): unknown {
  return maskLeaf(value, '', 0);
}

function maskLeaf(value: unknown, key: string, depth: number): unknown {
  if (depth > MAX_MASK_DEPTH) return '[REDACTED]';
  if (typeof value === 'string') {
    try {
      const wrapped = JSON.parse(maskPersonalData(JSON.stringify({ [key]: value }))) as Record<
        string,
        unknown
      >;
      return Object.values(wrapped)[0];
    } catch {
      return '[REDACTED]';
    }
  }
  if (typeof value === 'number') {
    const text = String(value);
    const masked = maskPersonalData(text);
    return masked === text ? value : masked;
  }
  if (Array.isArray(value)) return value.map((v) => maskLeaf(v, key, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    // defineProperty, not assignment: a parsed `__proto__` key must stay a
    // plain property, never become the copy's prototype.
    for (const [k, v] of Object.entries(value))
      Object.defineProperty(out, maskPersonalData(k), {
        value: maskLeaf(v, k, depth + 1),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    return out;
  }
  return value;
}
