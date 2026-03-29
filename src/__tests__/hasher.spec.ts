// src/__tests__/hasher.spec.ts
// Unit tests for audit/hasher.ts: canonicalise and hashArgs.
import { describe, it, expect } from 'vitest';
import { canonicalise, hashArgs } from '../audit/hasher.js';

describe('canonicalise', () => {
  it('returns primitives unchanged', () => {
    expect(canonicalise(42)).toBe(42);
    expect(canonicalise('hello')).toBe('hello');
    expect(canonicalise(null)).toBeNull();
    expect(canonicalise(true)).toBe(true);
  });

  it('sorts object keys alphabetically', () => {
    const result = canonicalise({ z: 1, a: 2, m: 3 }) as Record<string, number>;
    expect(Object.keys(result)).toEqual(['a', 'm', 'z']);
  });

  it('sorts nested object keys recursively', () => {
    const result = canonicalise({ b: { z: 1, a: 2 }, a: 'x' }) as Record<string, unknown>;
    expect(Object.keys(result)).toEqual(['a', 'b']);
    expect(Object.keys(result.b as object)).toEqual(['a', 'z']);
  });

  it('preserves array order', () => {
    const result = canonicalise([3, 1, 2]);
    expect(result).toEqual([3, 1, 2]);
  });

  it('sorts objects inside arrays', () => {
    const result = canonicalise([{ b: 2, a: 1 }]) as Array<Record<string, number>>;
    expect(Object.keys(result[0])).toEqual(['a', 'b']);
  });

  it('coerces Date to ISO string — not {} which would cause all dates to collide', () => {
    const d = new Date('2026-01-01T00:00:00.000Z');
    expect(canonicalise(d)).toBe('2026-01-01T00:00:00.000Z');
    // Two different dates must produce different hashes
    const d2 = new Date('2026-06-01T00:00:00.000Z');
    expect(hashArgs({ ts: d })).not.toBe(hashArgs({ ts: d2 }));
  });

  it('coerces RegExp to string', () => {
    expect(canonicalise(/foo/gi)).toBe('/foo/gi');
  });

  it('coerces Buffer to base64', () => {
    const buf = Buffer.from('hello');
    expect(canonicalise(buf)).toBe(buf.toString('base64'));
  });

  it('circular object reference — returns [Circular] instead of throwing', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj['self'] = obj; // circular reference
    expect(() => canonicalise(obj)).not.toThrow();
    const result = canonicalise(obj) as Record<string, unknown>;
    expect(result['self']).toBe('[Circular]');
  });

  it('circular array reference — returns [Circular] instead of throwing', () => {
    const arr: unknown[] = [1, 2];
    arr.push(arr); // circular reference
    expect(() => canonicalise(arr)).not.toThrow();
    const result = canonicalise(arr) as unknown[];
    expect(result[2]).toBe('[Circular]');
  });

  it('deeply nested circular reference — cycle inside nested object does not throw', () => {
    // Cycle is several levels deep — tests that the WeakSet is threaded through
    // recursion, not just checked at the top level.
    const inner: Record<string, unknown> = { value: 42 };
    const outer = { level1: { level2: inner } };
    inner['back'] = outer; // outer → level1 → level2 → back → outer (cycle)
    expect(() => canonicalise(outer)).not.toThrow();
    const result = canonicalise(outer) as Record<string, unknown>;
    const level2 = (result['level1'] as Record<string, unknown>)['level2'] as Record<
      string,
      unknown
    >;
    expect(level2['back']).toBe('[Circular]');
  });
});

describe('hashArgs', () => {
  it('returns a 32-character hex string', () => {
    const h = hashArgs({ file_path: '/tmp/foo.txt', content: 'hello' });
    expect(h).toMatch(/^[0-9a-f]{32}$/);
  });

  it('is deterministic — same args produce the same hash', () => {
    const args = { command: 'ls -la /home', cwd: '/tmp' };
    expect(hashArgs(args)).toBe(hashArgs(args));
  });

  it('is key-order independent — {a,b} === {b,a}', () => {
    const h1 = hashArgs({ b: 2, a: 1 });
    const h2 = hashArgs({ a: 1, b: 2 });
    expect(h1).toBe(h2);
  });

  it('different args produce different hashes', () => {
    const h1 = hashArgs({ command: 'ls' });
    const h2 = hashArgs({ command: 'rm -rf /' });
    expect(h1).not.toBe(h2);
  });

  it('handles null args', () => {
    expect(() => hashArgs(null)).not.toThrow();
    expect(hashArgs(null)).toMatch(/^[0-9a-f]{32}$/);
  });

  it('handles undefined args — returns valid hex string', () => {
    expect(() => hashArgs(undefined)).not.toThrow();
    expect(hashArgs(undefined)).toMatch(/^[0-9a-f]{32}$/);
  });

  it('array arg order matters', () => {
    const h1 = hashArgs(['a', 'b', 'c']);
    const h2 = hashArgs(['c', 'b', 'a']);
    expect(h1).not.toBe(h2);
  });

  it('string "1" and number 1 produce different hashes — JSON type is preserved', () => {
    // canonicalise must not collapse { a: "1" } and { a: 1 } to the same hash.
    // Both serialise differently in JSON so this should hold trivially, but
    // explicitly asserting it prevents regressions if serialisation ever changes.
    expect(hashArgs({ a: '1' })).not.toBe(hashArgs({ a: 1 }));
  });
});

describe('hashArgs contract: used by appendLocalAudit when auditHashArgs is enabled', () => {
  it('hash is a 32-char hex string that does not contain the original secret content', async () => {
    // When auditHashArgsEnabled=true, appendLocalAudit stores argsHash (not args).
    // Verify the hash contract: 32 hex chars, no plaintext leakage.
    const args = { file_path: '/tmp/secret.env', content: 'API_KEY=supersecret' };
    const hash = hashArgs(args);
    expect(hash).toMatch(/^[0-9a-f]{32}$/);
    // The hash must NOT contain the original content
    expect(hash).not.toContain('supersecret');
    expect(hash).not.toContain('API_KEY');
  });
});
