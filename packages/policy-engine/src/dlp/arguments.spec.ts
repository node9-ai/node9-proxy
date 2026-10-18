import { describe, expect, it } from 'vitest';
import { inspectArgumentSecrets, scanArgumentSecrets } from './arguments';
import { scanArgs } from './index';

const token = ['AKIA', 'ZBCDEFGH', 'JKLM2345'].join('');
const encode = (s: string) => Buffer.from(s).toString('base64');

describe('bounded argument secret inspection', () => {
  it('finds a base32 credential and a hex credential split across hostname labels', () => {
    const base32 = 'IFFUSQK2IJBUIRKGI5EEUS2MJUZDGNBV';
    const hex = Buffer.from(token).toString('hex');
    for (const host of [base32, hex.slice(0, 16) + '.' + hex.slice(16)]) {
      expect(scanArgumentSecrets({ url: `https://${host}.fixture.invalid/` })).toMatchObject({
        patternName: 'AWS Access Key ID',
        severity: 'block',
      });
    }
  });
  it('decodes individual URL path segments without including the path slash', () => {
    expect(
      scanArgumentSecrets({ url: 'https://fixture.invalid/' + encode(token) + '/send' })
    ).toMatchObject({ patternName: 'AWS Access Key ID', severity: 'block' });
  });
  it('keeps output and legacy raw scanners separate', () => {
    const args = { value: encode(token) };
    expect(scanArgs(args)).toBeNull();
    expect(scanArgumentSecrets(args)).toMatchObject({
      severity: 'block',
      redactedSample: '[encoded secret]',
    });
  });
  it('handles JSON strings and a short encoded token at nested depth', () => {
    expect(
      scanArgumentSecrets({ a: { b: { c: { d: JSON.stringify({ token: encode(token) }) } } } })
    ).toMatchObject({ patternName: 'AWS Access Key ID' });
  });
  it('does not manufacture tokens through homoglyph folding', () => {
    expect(scanArgumentSecrets({ value: token.replace('A', '\u0410') })).toBeNull();
  });
  it('checks valid percent runs beside malformed escapes and preserves base64 plus signs', () => {
    const percent = [...token].map((c) => '%' + c.charCodeAt(0).toString(16)).join('');
    expect(
      scanArgumentSecrets({ url: 'https://fixture.invalid/?x=%ZZ&key=' + percent })?.severity
    ).toBe('block');
  });
  it('accepts byte-delimited hex without stripping unrelated prose separators', () => {
    const hex = Buffer.from(token).toString('hex').match(/../g)!.join('-');
    expect(scanArgumentSecrets({ value: hex })?.severity).toBe('block');
    expect(scanArgumentSecrets({ one: token.slice(0, 10), two: token.slice(10) })).toBeNull();
  });
  it('does not decode an image or a random identifier into a credential', () => {
    expect(
      scanArgumentSecrets({
        image: 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2',
        id: 'f13a9db0428c7e01a594dbcca864fa15',
      })
    ).toBeNull();
  });
  it('keeps the strongest match across fields and views', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl';
    expect(scanArgumentSecrets({ first: jwt, second: encode(token) })?.severity).toBe('block');
  });
  it('never exposes a secret supplied as an object key', () => {
    const match = scanArgumentSecrets({ [token]: 'value' });
    expect(match?.severity).toBe('block');
    expect(match?.fieldPath).not.toContain(token);
  });
  it('reports cycles and skipped structure as incomplete rather than clean', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    for (const args of [cyclic, { text: ' '.repeat(5_000_000) }, Array(20_000).fill('small')]) {
      expect(inspectArgumentSecrets(args).coverage).toBe('incomplete');
      expect(scanArgumentSecrets(args)?.severity).toBe('review');
    }
  });
  it('keeps a detected block when another field is incomplete', () => {
    expect(scanArgumentSecrets({ large: ' '.repeat(5_000_000), token })?.severity).toBe('block');
  });
  it('enforces decoding depth and reviews an uninspected layer', () => {
    let value = token;
    for (let i = 0; i < 5; i++) value = encode(value);
    expect(inspectArgumentSecrets(value)).toMatchObject({
      coverage: 'incomplete',
      reasons: ['decode-nested'],
    });
    expect(scanArgumentSecrets(value)?.severity).toBe('review');
  });
});
