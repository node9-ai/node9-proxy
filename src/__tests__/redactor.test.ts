import { describe, it, expect } from 'vitest';
import { redactSecrets } from '../core';

describe('redactSecrets', () => {
  it('masks authorization bearer headers but keeps prefix', () => {
    const input = 'curl -H "Authorization: Bearer sk-1234567890abcdef"';
    const output = redactSecrets(input);
    expect(output).toContain('Authorization: Bearer ********');
    expect(output).not.toContain('sk-1234567890abcdef');
  });

  it('masks api keys but keeps labels', () => {
    expect(redactSecrets('api_key="ABCDEFGHIJ1234567890"')).toContain('api_key="********');
    expect(redactSecrets('apikey: KEY_VALUE_9876543210')).toContain('apikey: ********');
    expect(redactSecrets('API-KEY=SOME_SECRET_VALUE_HERE')).toContain('API-KEY=********');
  });

  it('masks tokens and passwords', () => {
    expect(redactSecrets('GITHUB_TOKEN=token_1234567890abcdefghijk')).toContain(
      'GITHUB_TOKEN=********'
    );
    expect(redactSecrets('password: "password_example_123"')).toContain('password: "********');
  });

  it('does NOT mask bare long strings without a secret prefix — avoids redacting SHAs, paths, IDs', () => {
    // Pattern 3 was removed: bare long alphanumeric strings like git SHAs should NOT be redacted.
    // Only strings with a recognised prefix (api_key=, token=, Authorization: Bearer) are redacted.
    const input = 'The hash is a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2';
    const output = redactSecrets(input);
    expect(output).toBe(input); // unchanged — no recognised prefix
  });

  it('does not mask short, safe words', () => {
    const input = 'npm install express';
    const output = redactSecrets(input);
    expect(output).toBe(input);
  });

  it('handles JSON strings correctly', () => {
    const obj = { command: 'curl -H "Authorization: Bearer 12345678901234567890"' };
    const input = JSON.stringify(obj);
    const output = redactSecrets(input);
    expect(output).toContain('Bearer ********');
  });

  it('keeps JSON-escaped text PARSEABLE after redaction (audit-gap regression)', () => {
    // log.ts does JSON.parse(redactSecrets(JSON.stringify(rawInput))). The old
    // token class included `\\`, so it consumed the escaping backslash of a
    // trailing `\"` — the parse threw and the ENTIRE audit row was skipped for
    // any executed call carrying an Authorization header. The round-trip is
    // the contract, not just the masking.
    const obj = {
      command:
        'curl -H "Authorization: Bearer Xm7Kp3Qn9Bt2Vc6Wr1Ys4Zh8Pq5Nv3M" https://api.example.com',
    };
    const output = redactSecrets(JSON.stringify(obj));
    const parsed = JSON.parse(output) as { command: string }; // must not throw
    expect(parsed.command).toContain('Bearer ********');
    expect(parsed.command).toContain('https://api.example.com'); // tail survives
    expect(output).not.toContain('Xm7Kp3Qn9Bt2Vc6');
  });
});
