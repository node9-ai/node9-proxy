// src/audit/hasher.ts
// Privacy-safe audit hashing: replaces raw tool arguments with a deterministic
// SHA-256 digest so audit logs are correlation-capable but not secret-leaking.
//
// The hash is:
//   SHA-256( JSON.stringify(canonicalise(args)) )  →  first 32 hex chars
//
// 32 hex chars = 128-bit prefix of a SHA-256 digest.
// Note: SHA-256 produces 64 hex chars total; we truncate to 32 (128 bits).
// This is NOT MD5. Collision probability for 128 bits is negligible for audit
// log volumes (birthday bound: ~2^64 entries for 50% collision chance).
//
// Canonicalisation sorts object keys so that {"b":1,"a":2} and {"a":2,"b":1}
// produce the same hash. Arrays are left in order (order matters for commands).
// Non-plain objects (Date, RegExp, Buffer) are converted to their string/JSON
// representation so they produce meaningful, stable hashes rather than {}.
import { createHash } from 'crypto';

/**
 * Recursively sort object keys for a stable JSON representation.
 * Arrays are left in insertion order; primitives are returned as-is.
 * Non-plain objects (Date, RegExp, Buffer, etc.) are coerced to a stable
 * string form so they hash meaningfully rather than collapsing to {}.
 *
 * Cycle detection: circular references are replaced with the sentinel string
 * "[Circular]" instead of stack-overflowing — important because tool args
 * can come from untrusted MCP servers that may send self-referencing payloads.
 * The WeakSet is internal and not exposed to callers.
 */
export function canonicalise(value: unknown): unknown {
  return _canonicalise(value, new WeakSet());
}

function _canonicalise(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null || typeof value !== 'object') return value;
  // Non-plain objects: coerce to a stable primitive before any seen check —
  // Date/RegExp/Buffer are leaf nodes (no children, can't form cycles).
  if (value instanceof Date) return value.toISOString();
  if (value instanceof RegExp) return value.toString();
  if (Buffer.isBuffer(value)) return value.toString('base64');
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  let result: unknown;
  if (Array.isArray(value)) {
    result = value.map((v) => _canonicalise(v, seen));
  } else {
    const obj = value as Record<string, unknown>;
    result = Object.fromEntries(
      Object.keys(obj)
        .sort()
        .map((k) => [k, _canonicalise(obj[k], seen)])
    );
  }
  seen.delete(value);
  return result;
}

/**
 * Return a 32-char hex string (128-bit prefix of SHA-256) of the tool arguments.
 * Identical args always produce the same digest — useful for deduplication
 * and correlation without exposing the original content.
 *
 * Uses SHA-256 (not MD5). 32 hex chars = 128 bits = first half of a SHA-256 digest.
 * Collision probability: negligible for audit log volumes
 * (birthday bound ~2^64 entries for 50% collision chance).
 *
 * null and undefined both produce the same hash (both canonicalise to JSON null).
 * This is intentional: both represent "no args" and are equivalent for correlation.
 */
export function hashArgs(args: unknown): string {
  const canonical = JSON.stringify(canonicalise(args) ?? null);
  return createHash('sha256').update(canonical).digest('hex').slice(0, 32);
}
