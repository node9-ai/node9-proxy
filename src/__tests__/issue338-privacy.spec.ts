import { describe, expect, it } from 'vitest';
import { redactArgs } from '../daemon/state';

describe('encoded credentials in daemon display and audit arguments', () => {
  it('withholds encoded credentials under non-secret field names', () => {
    const encoded = Buffer.from(['AKIA', 'ZBCDEFGH', 'JKLM2345'].join('')).toString('base64');
    const result = JSON.stringify(redactArgs({ body: encoded }));
    expect(result).not.toContain(encoded);
    expect(result).toContain('REDACTED');
  });
  it('withholds values whose inspection is incomplete', () => {
    const deep = JSON.parse('{"a":'.repeat(14) + '"sensitive-tail"' + '}'.repeat(14));
    expect(JSON.stringify(redactArgs({ body: deep }))).not.toContain('sensitive-tail');
  });
  it('shows a large ordinary value whose raw text was fully inspected', () => {
    const value = ' '.repeat(100_001) + 'ordinary-tail';
    expect(JSON.stringify(redactArgs({ body: value }))).toContain('ordinary-tail');
  });
  it('preserves ordinary arguments and field-name redaction', () => {
    expect(redactArgs({ body: 'hello', password: 'short' })).toEqual({
      body: 'hello',
      password: '[REDACTED]',
    });
  });
});
