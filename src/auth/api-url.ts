// The single gate between `apiUrl` as it sits on disk and any request that
// carries the device key.
//
// Confirmed by repro on 2026-09-14: a governed agent can rewrite
// ~/.node9/credentials.json through Bash (the credential jail covers reads and
// the file-tool door, not a shell redirect), and every shipper then sends
// `Authorization: Bearer <device key>` to whatever host that file names. The
// key and the audit stream both follow. Measured end to end: the bearer token
// arrived at an attacker-controlled listener.
//
// The old guard checked scheme and userinfo only, so `https://evil.example/`
// passed it, and it guarded 2 of the 12 places apiUrl becomes a destination.
// Rather than patch twelve call sites — the "floor keyed on one seam" shape
// this codebase keeps getting bitten by — this runs once in getCredentials,
// where an untrusted file becomes program data. A consumer can no longer
// receive a hostile apiUrl at all.

/** Where node9 ships to when nothing overrides it. */
export const DEFAULT_API_URL = 'https://api.node9.ai/api/v1/intercept';

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]', '0.0.0.0']);

/**
 * Extra host suffixes an operator accepts, comma-separated. For self-hosted and
 * staging. Env rather than config on purpose: config is a file an agent can
 * write, and this is the control that decides where a key may go.
 */
export const HOST_ALLOW_ENV = 'NODE9_API_HOST_ALLOW';

/**
 * The default endpoint's host, and its parent when that parent is not a public
 * suffix. `api.node9.ai` yields both `api.node9.ai` and `node9.ai`, so
 * `dev-api.node9.ai` and `staging.node9.ai` are accepted without a list.
 *
 * Deliberately NOT "the last two labels": that reads `api.node9.co.uk` as
 * `co.uk` and would accept every host in the TLD. Only one label is dropped,
 * and only when what remains still has a dot, so the widest this can ever get
 * is one registrable domain.
 */
function defaultHostSuffixes(): string[] {
  const host = new URL(DEFAULT_API_URL).hostname.toLowerCase();
  const parent = host.split('.').slice(1).join('.');
  return parent.includes('.') ? [host, parent] : [host];
}

function allowedSuffixes(): string[] {
  const extra = (process.env[HOST_ALLOW_ENV] ?? '')
    .split(',')
    .map((s) =>
      s
        .trim()
        .toLowerCase()
        .replace(/^\*?\./, '')
    )
    .filter(Boolean);
  return [...defaultHostSuffixes(), ...extra];
}

/**
 * Returns the URL when it is a destination this machine may send its device key
 * to, and null otherwise.
 *
 * Accepted: https on the default endpoint's registrable domain (so
 * `dev-api.node9.ai` and `staging.node9.ai` work without a list), http or https
 * on loopback (local development and the test suite), and anything under a
 * suffix named in NODE9_API_HOST_ALLOW.
 *
 * Rejected: every other host, any non-http(s) scheme, and userinfo — the key
 * already travels in the Authorization header, so `https://x@real.host` is only
 * ever an attempt to confuse a reader.
 *
 * ⚠️ LOOPBACK IS NOT CLOSED, and the limit is deliberate. An agent that can
 * rewrite credentials.json can also start a listener on 127.0.0.1 and have the
 * key delivered there, then forward it. That is the exact shape of the original
 * repro. Loopback stays accepted because local development and the test suite
 * need it (`https://localhost:1`, `http://127.0.0.1:9`), so this closes the
 * REMOTE redirect and not the local relay. The local relay is a smaller win for
 * an attacker who already has shell — it can read the file directly — but it is
 * open, and the gap belongs in the doc rather than in a claim that it is shut.
 */
export function validateApiUrl(raw: unknown): URL | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.username || u.password) return null;
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;

  const host = u.hostname.toLowerCase();
  if (LOOPBACK.has(host)) return u;
  // Non-loopback must be https: a plaintext bearer token is a leak by itself.
  if (u.protocol !== 'https:') return null;

  const suffixes = allowedSuffixes();
  const ok = suffixes.some((s) => host === s || host.endsWith('.' + s));
  return ok ? u : null;
}

/**
 * The apiUrl a caller may safely use. A rejected value falls back to the real
 * endpoint rather than disabling the cloud: the attack is "redirect the key",
 * and sending it to the correct place defeats that while leaving a tampered
 * machine working. `onReject` lets the caller record it.
 */
export function safeApiUrl(raw: unknown, onReject?: (raw: unknown) => void): string {
  const ok = validateApiUrl(raw);
  if (ok) return typeof raw === 'string' ? raw : ok.toString();
  onReject?.(raw);
  return DEFAULT_API_URL;
}

/**
 * Derive a sibling endpoint without losing the guard. Null when the base fails,
 * and null when the suffix walks off the host.
 *
 * The result is re-validated rather than trusted: `new URL('//evil.test/x',
 * base)` is protocol-relative and REPLACES the host, so validating only the
 * base would have handed a caller an attacker's origin. Caught by its own test.
 */
export function apiEndpoint(raw: unknown, pathSuffix: string): URL | null {
  const base = validateApiUrl(raw);
  if (!base) return null;
  let derived: URL;
  try {
    derived = new URL(pathSuffix, base);
  } catch {
    return null;
  }
  if (derived.origin !== base.origin) return null;
  return validateApiUrl(derived.toString());
}
