// src/audit/hasher.ts
// Privacy-safe audit hashing: replaces raw tool arguments with a deterministic
// SHA-256 digest so audit logs are correlation-capable but not secret-leaking.
//
// The hash is:
//   SHA-256( JSON.stringify(canonicalise(args)) )  →  hex string (first 16 chars)
//
// Canonicalisation sorts object keys so that {"b":1,"a":2} and {"a":2,"b":1}
// produce the same hash. Arrays are left in order (order matters for commands).
import { createHash } from 'crypto';

/**
 * Recursively sort object keys for a stable JSON representation.
 * Arrays are left in insertion order; primitives are returned as-is.
 */
export function canonicalise(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonicalise);
  const obj = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(obj)
      .sort()
      .map((k) => [k, canonicalise(obj[k])])
  );
}

/**
 * Return a short (16-char) hex digest of the tool arguments.
 * Identical args always produce the same digest — useful for deduplication
 * and correlation without exposing the original content.
 */
export function hashArgs(args: unknown): string {
  const canonical = JSON.stringify(canonicalise(args) ?? null);
  return createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}
