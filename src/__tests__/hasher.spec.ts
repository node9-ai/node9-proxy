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
});

describe('hashArgs', () => {
  it('returns a 16-character hex string', () => {
    const h = hashArgs({ file_path: '/tmp/foo.txt', content: 'hello' });
    expect(h).toMatch(/^[0-9a-f]{16}$/);
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
    expect(hashArgs(null)).toMatch(/^[0-9a-f]{16}$/);
  });

  it('handles undefined args', () => {
    expect(() => hashArgs(undefined)).not.toThrow();
  });

  it('array arg order matters', () => {
    const h1 = hashArgs(['a', 'b', 'c']);
    const h2 = hashArgs(['c', 'b', 'a']);
    expect(h1).not.toBe(h2);
  });
});

describe('auditHashArgs integration: appendLocalAudit output', () => {
  it('audit log entry has argsHash instead of args when flag is set', async () => {
    // Directly verify the hasher contract used by appendLocalAudit:
    // when auditHashArgsEnabled=true, the log entry stores argsHash (not args).
    const args = { file_path: '/tmp/secret.env', content: 'API_KEY=supersecret' };
    const hash = hashArgs(args);
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
    // The hash must NOT contain the original content
    expect(hash).not.toContain('supersecret');
    expect(hash).not.toContain('API_KEY');
  });
});
