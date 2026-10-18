import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { BIP39_ENGLISH } from './bip39-english';
import { findMnemonic, MAX_MNEMONIC_HASHES } from './mnemonic';
import { scanArgumentSecrets } from './arguments';

function fixture(bytes: number, label = 'node9 synthetic mnemonic fixture'): string {
  const entropy = createHash('sha256').update(label).digest().subarray(0, bytes);
  const bits = [...entropy].map((b) => b.toString(2).padStart(8, '0')).join('');
  const checksum = createHash('sha256')
    .update(entropy)
    .digest()[0]
    .toString(2)
    .padStart(8, '0')
    .slice(0, bytes / 4);
  return (bits + checksum)
    .match(/.{11}/g)!
    .map((n) => BIP39_ENGLISH[parseInt(n, 2)])
    .join(' ');
}

describe('English BIP-39 argument detection', () => {
  it.each([16, 20, 24, 28, 32])('detects a checksummed %i-byte synthetic mnemonic', (bytes) => {
    const phrase = fixture(bytes);
    expect(findMnemonic(`wallet: ${phrase}`)).toBe(true);
    for (const value of [
      phrase,
      Buffer.from(phrase).toString('base64'),
      encodeURIComponent(phrase),
    ]) {
      expect(scanArgumentSecrets({ body: value })).toMatchObject({
        patternName: 'BIP-39 Recovery Phrase',
        severity: 'block',
      });
    }
  });
  it('rejects an invalid checksum, ordinary prose, and an incomplete phrase', () => {
    const phrase = fixture(16).split(' ');
    const index = BIP39_ENGLISH.indexOf(phrase[11]);
    phrase[11] = BIP39_ENGLISH[index ^ 1];
    expect(findMnemonic(phrase.join(' '))).toBe(false);
    expect(
      findMnemonic(
        'this documentation explains how to protect a wallet recovery phrase from disclosure'
      )
    ).toBe(false);
    expect(findMnemonic(fixture(16).split(' ').slice(0, 11).join(' '))).toBe(false);
  });
  it('excludes an exact published vector without exempting an adjacent real-shaped phrase', () => {
    const vector = [...Array(11).fill(BIP39_ENGLISH[0]), BIP39_ENGLISH[3]].join(' ');
    expect(findMnemonic(vector)).toBe(false);
    expect(findMnemonic(vector + '\n' + fixture(32))).toBe(true);
  });
  it('does not expose words from a detected mnemonic', () => {
    const phrase = fixture(16);
    const hit = scanArgumentSecrets({ body: phrase });
    expect(hit?.redactedSample).toBe('[recovery phrase]');
    expect(JSON.stringify(hit)).not.toContain(phrase);
  });
  it('reports exhaustion to the argument scanner instead of declaring a clean scan', () => {
    const budget = { hashes: MAX_MNEMONIC_HASHES, reasons: new Set<string>() };
    expect(findMnemonic(fixture(16), budget)).toBe(false);
    expect(budget.reasons.has('mnemonic-budget')).toBe(true);
  });
  // fw#338 review 3 (B5): the word list itself, or any ordered slice of it.
  it('does not read the word list in its own order as a phrase', () => {
    expect(findMnemonic(BIP39_ENGLISH.join('\n'))).toBe(false);
    expect(findMnemonic(BIP39_ENGLISH.slice(100, 140).join(' '))).toBe(false);
    expect(findMnemonic('the words are ' + fixture(16) + ' in a sentence')).toBe(true);
  });
});
