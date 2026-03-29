// src/audit/hasher.ts
// Privacy-safe audit hashing: replaces raw tool arguments with a deterministic
// SHA-256 digest so audit logs are correlation-capable but not secret-leaking.
//
// The hash is:
//   SHA-256( JSON.stringify(canonicalise(args)) )  →  hex string (first 32 chars)
//
// 32 hex chars = 128 bits. Collision probability is negligible for audit log
// volumes (birthday bound: ~2^64 entries for 50% collision chance).
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
 */
export function canonicalise(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonicalise);
  // Non-plain objects: coerce to a stable primitive representation
  if (value instanceof Date) return value.toISOString();
  if (value instanceof RegExp) return value.toString();
  if (Buffer.isBuffer(value)) return value.toString('base64');
  const obj = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(obj)
      .sort()
      .map((k) => [k, canonicalise(obj[k])])
  );
}

/**
 * Return a 32-char hex digest (128-bit prefix of SHA-256) of the tool arguments.
 * Identical args always produce the same digest — useful for deduplication
 * and correlation without exposing the original content.
 *
 * 128 bits: negligible collision probability for audit log volumes
 * (birthday bound ~2^64 entries for 50% collision chance).
 */
export function hashArgs(args: unknown): string {
  const canonical = JSON.stringify(canonicalise(args) ?? null);
  return createHash('sha256').update(canonical).digest('hex').slice(0, 32);
}
