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
    expect(redactSecrets('GITHUB_TOKEN=token_1234567890abcdefghijk')).toContain('GITHUB_TOKEN=********');
    expect(redactSecrets('password: "password_example_123"')).toContain('password: "********');
  });

  it('masks generic long entropy strings', () => {
    const input = 'The hash is a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2';
    const output = redactSecrets(input);
    expect(output).toContain('********');
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
});
