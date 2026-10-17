// Destinations in content and in tool arguments, for the exposure gate.
//
// A session that read outside content (an email, a web page) is exposed; a
// later call that SENDS is judged by where it sends. "Where" is one of three
// kinds, each normalised to a comparable string so a value seen in the
// content read can be matched against a value in a call's arguments:
//
//   email:<address>   lower-cased
//   host:<hostname>   lower-cased, no port, no brackets
//   iban:<IBAN>       upper-cased, no spaces, checksum-valid
//   account:<number>  an IBAN-shaped number whose checksum does not hold (a
//                     sandbox or test account), only under a recipient key
//
// Pure, bounded, never throws. Values are compared on the machine and shown
// only in the local approval prompt; audit rows carry the kind and a count.
// Design: docs/roadmap/active/untrusted-content-proxy-code-design.md, 4.2.

import { validateIban } from '../scan/checksums';

export type DestinationKind = 'email' | 'host' | 'iban' | 'account';

/** Upper bound on values kept from one text or one call. */
export const MAX_DESTINATIONS = 200;
/** Upper bound on the text scanned, in UTF-16 units (the DLP scan bound). */
export const MAX_SCAN_CHARS = 100_000;

// Letters of any script: an attacker registers an IDN domain and a modern
// mail server accepts it; the address is still compared as written.
const EMAIL_RE =
  /[\p{L}\p{N}._%+-]+@[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:\.[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?)*\.\p{L}{2,}/gu;
// A URL with a scheme, or a www. host: a bare "node.js" or "file.txt" in prose
// must not become a destination. Trailing punctuation is trimmed below.
const URL_RE = /\b(?:[a-z][a-z0-9+.-]*:\/\/|www\.)[^\s<>"'`){}]+/gi;
// IBAN-shaped: country, check digits, then groups that may carry spaces or dashes.
const IBAN_RE = /\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,4})?\b/g;

// Argument keys whose string value is a recipient even without a scheme
// (an email tool's `to`, a transfer's `recipient`).
const RECIPIENT_KEYS = new Set([
  'to',
  'cc',
  'bcc',
  'recipient',
  'recipients',
  'email',
  'participants',
  'attendees',
  'destination',
  'iban',
  'account',
  // Where a request goes, when the value is a bare host or a scheme-less URL.
  'url',
  'uri',
  'host',
  'hostname',
  'endpoint',
  'server',
  'domain',
  'address',
  'webhook',
  'webhook_url',
  'callback',
  'callback_url',
  'target',
]);

function normalizeHost(raw: string): string | null {
  let h = raw.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (!h || h === 'localhost') return null;
  // An IPv6 literal has no dot; everything else needs one.
  if (/^[0-9a-f:]+$/.test(h) && h.includes(':')) return h;
  if (!h.includes('.') || !/^[\p{L}\p{N}.-]+$/u.test(h)) return null;
  return h;
}

function hostOfUrl(value: string): string | null {
  const v = value.replace(/[.,;:!?)\]}>'"`]+$/, '');
  try {
    const u = new URL(v.toLowerCase().startsWith('www.') ? `http://${v}` : v);
    return normalizeHost(u.hostname);
  } catch {
    return null;
  }
}

function addIbans(text: string, out: Set<string>): void {
  for (const m of text.toUpperCase().matchAll(IBAN_RE)) {
    const compact = m[0].replace(/[ -]/g, '');
    if (validateIban(compact)) out.add(`iban:${compact}`);
    // The same shape with a failing checksum is kept as an account number so
    // a transfer to it can be matched; it is never reported as an IBAN.
    else if (/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) out.add(`account:${compact}`);
    if (out.size >= MAX_DESTINATIONS) return;
  }
}

function addEmails(text: string, out: Set<string>): void {
  for (const m of text.matchAll(EMAIL_RE)) {
    out.add(`email:${m[0].toLowerCase()}`);
    if (out.size >= MAX_DESTINATIONS) return;
  }
}

function addUrlHosts(text: string, out: Set<string>): void {
  for (const m of text.matchAll(URL_RE)) {
    const h = hostOfUrl(m[0]);
    if (h) out.add(`host:${h}`);
    if (out.size >= MAX_DESTINATIONS) return;
  }
}

/**
 * Every destination-like value in a text a tool returned (or a prompt the
 * user typed). Emails anywhere; hosts only from URLs with a scheme or a
 * `www.` prefix; IBANs only when the checksum holds.
 */
export function extractContentDestinations(text: string): string[] {
  const out = new Set<string>();
  try {
    const t = text.length > MAX_SCAN_CHARS ? text.slice(0, MAX_SCAN_CHARS) : text;
    if (t.includes('@')) addEmails(t, out);
    if (out.size < MAX_DESTINATIONS) addUrlHosts(t, out);
    if (out.size < MAX_DESTINATIONS) addIbans(t, out);
  } catch {
    /* a destination scan must never fail a hook */
  }
  return [...out];
}

/**
 * Every destination-like value in a tool call's arguments. Like the content
 * extractor, plus: a string under a recipient key (`to`, `recipient`, ...)
 * counts as a host when it is a bare hostname, so `send_money {recipient:
 * "US12..."}` and `send_email {to: "x@y.z"}` both yield their destination.
 */
export function extractArgDestinations(args: unknown): string[] {
  const out = new Set<string>();
  try {
    walk(args, undefined, out, 0);
  } catch {
    /* never throw on the hook path */
  }
  return [...out];
}

function walk(value: unknown, key: string | undefined, out: Set<string>, depth: number): void {
  if (out.size >= MAX_DESTINATIONS || depth > 12) return;
  if (typeof value === 'string') {
    const s = value.length > MAX_SCAN_CHARS ? value.slice(0, MAX_SCAN_CHARS) : value;
    if (s.includes('@')) addEmails(s, out);
    addUrlHosts(s, out);
    addIbans(s, out);
    if (key && RECIPIENT_KEYS.has(key.toLowerCase()) && !/[\s@]/.test(s)) {
      // A scheme-less `evil.example/collect` or a bare host under a key that
      // names a destination: the host part, as a fetch-style tool reads it.
      const h = normalizeHost(
        s
          .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
          .replace(/^\/\//, '')
          .split(/[/?#]/)[0]
          .replace(/:\d+$/, '')
      );
      if (h && (h.includes(':') || /\.\p{L}{2,}$/u.test(h))) out.add(`host:${h}`);
      // An account number that is IBAN-shaped but fails the checksum (a
      // sandbox account, a fictional bank): still the place the money goes.
      const acct = s.replace(/[ .-]/g, '').toUpperCase();
      if (/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(acct) && !validateIban(acct))
        out.add(`account:${acct}`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) walk(v, key, out, depth + 1);
    return;
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>))
      walk(v, k, out, depth + 1);
  }
}

/** `email:a@b.c` -> `b.c`; other kinds have no domain. */
export function destinationDomain(dest: string): string | null {
  if (!dest.startsWith('email:')) return null;
  const at = dest.lastIndexOf('@');
  return at > 0 ? dest.slice(at + 1) : null;
}

/** The kind prefix of a normalised destination. */
export function destinationKind(dest: string): DestinationKind | null {
  const i = dest.indexOf(':');
  const k = i > 0 ? dest.slice(0, i) : '';
  return k === 'email' || k === 'host' || k === 'iban' || k === 'account' ? k : null;
}

/** The value a person reads, without the kind prefix. */
export function destinationValue(dest: string): string {
  const i = dest.indexOf(':');
  return i > 0 ? dest.slice(i + 1) : dest;
}

/** A loopback host: the machine itself (`localhost`, `*.localhost`,
 *  127.0.0.0/8, `::1`, `0.0.0.0`). A send there never leaves the machine. */
export function isLoopbackHost(host: string): boolean {
  let h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  return (
    h === 'localhost' ||
    h.endsWith('.localhost') ||
    /^127(?:\.\d{1,3}){3}$/.test(h) ||
    h === '::1' ||
    h === '0:0:0:0:0:0:0:1' ||
    h === '0.0.0.0'
  );
}

/**
 * The repository a git url names, as `host/owner/name` lower-cased with
 * `.git` and slashes trimmed: https, ssh://, scp-like `git@host:owner/name`.
 * Null for a local path or a url without a path.
 */
export function gitRepoPath(url: string): string | null {
  const u = url.trim();
  if (!u) return null;
  let host: string;
  let p: string;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) {
    try {
      const parsed = new URL(u);
      host = parsed.hostname.toLowerCase();
      p = decodeURIComponent(parsed.pathname);
    } catch {
      return null;
    }
  } else {
    const scp = /^(?:[^@/\s]+@)?([A-Za-z0-9.-]+):(?!\/\/)(.+)$/.exec(u);
    if (!scp || !scp[1].includes('.')) return null;
    host = scp[1].toLowerCase();
    p = scp[2];
  }
  // Trim slashes with indices: `/\/+$/` backtracks quadratically on a long
  // run of slashes that does not end the string.
  let start = 0;
  let end = p.length;
  while (start < end && p[start] === '/') start++;
  while (end > start && p[end - 1] === '/') end--;
  const tail = p
    .slice(start, end)
    .replace(/\.git$/i, '')
    .toLowerCase();
  if (!host || !tail.includes('/')) return null;
  return `${host}/${tail}`;
}

/**
 * A tool whose bare name says it destroys or moves something: after
 * exposure, such a call is held even when it names no destination. Bounded
 * and deliberately short; a name heuristic, used only where no annotation
 * says otherwise. Design 5.2.
 */
const DESTRUCTIVE_VERB_RE =
  /^(?:delete|remove|drop|destroy|purge|wipe|erase|transfer|pay|send_money|withdraw|change_password|update_password|reset_password|set_permission|grant|revoke|share)(?:_|$)/i;

export function isDestructiveToolName(bareTool: string): boolean {
  return DESTRUCTIVE_VERB_RE.test(bareTool);
}
