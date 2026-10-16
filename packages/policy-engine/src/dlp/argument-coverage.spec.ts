import { describe, expect, it } from 'vitest';
import { inspectArgumentSecrets, scanArgumentSecrets, ARGUMENT_SCAN_LIMITS } from './arguments';

// Pre-push review of #338: ordinary large documents must not be held for
// approval, and a long alphanumeric run must not take seconds to scan.
const token = ['AKIA', 'ZBCDEFGH', 'JKLM2345'].join('');

describe('raw text is matched in full', () => {
  it('finds a credential beyond the first decoding window', () => {
    const content = 'x'.repeat(150_000) + ' ' + token;
    expect(scanArgumentSecrets({ content })?.severity).toBe('block');
  });
  it('finds a credential straddling a window edge', () => {
    const edge = ARGUMENT_SCAN_LIMITS.maxStringCharacters - 10;
    const content = 'x'.repeat(edge) + ' ' + token + ' tail';
    expect(scanArgumentSecrets({ content })?.severity).toBe('block');
  });
  it('reports a decoding window limit without interrupting the call', () => {
    const result = inspectArgumentSecrets({ content: 'x'.repeat(150_000) });
    expect(result).toMatchObject({
      match: null,
      coverage: 'incomplete',
      reasons: ['decode-window'],
    });
    expect(scanArgumentSecrets({ content: 'x'.repeat(150_000) })).toBeNull();
  });
});

describe('ordinary documents complete their inspection', () => {
  it('a README full of links', () => {
    const content = Array.from(
      { length: 300 },
      (_, i) => `- [page ${i}](https://example.com/docs/page-${i}/section?x=${i}&y=abc)`
    ).join('\n');
    expect(inspectArgumentSecrets({ content })).toMatchObject({
      match: null,
      coverage: 'complete',
    });
  });
  it('a lockfile-sized JSON payload and a long list', () => {
    const packages = Object.fromEntries(
      Array.from({ length: 400 }, (_, i) => [
        `node_modules/pkg-${i}`,
        { version: `1.${i}.0`, integrity: `sha512-${'Qk'.repeat(43)}==` },
      ])
    );
    expect(scanArgumentSecrets({ content: JSON.stringify(packages) })).toBeNull();
    expect(
      scanArgumentSecrets({ rows: Array.from({ length: 5000 }, (_, i) => ({ id: i })) })
    ).toBeNull();
  });
  it('still asks when raw structure was skipped', () => {
    const deep = JSON.parse(
      '{"a":'.repeat(ARGUMENT_SCAN_LIMITS.maxDepth + 2) +
        '1' +
        '}'.repeat(ARGUMENT_SCAN_LIMITS.maxDepth + 2)
    );
    expect(scanArgumentSecrets(deep)?.patternName).toBe('Argument inspection incomplete');
    const beyondTail =
      ARGUMENT_SCAN_LIMITS.maxTailBytes + 2 * ARGUMENT_SCAN_LIMITS.maxStringCharacters;
    expect(scanArgumentSecrets({ content: 'x'.repeat(beyondTail) })?.patternName).toBe(
      'Argument inspection incomplete'
    );
  });
  it('still blocks a credential placed after a padding field', () => {
    for (const pad of [1_100_000, 5_000_000])
      expect(scanArgumentSecrets({ pad: 'x'.repeat(pad), token })?.severity).toBe('block');
    const fields = Object.fromEntries(
      Array.from({ length: 9 }, (_, i) => [`p${i}`, 'x'.repeat(200_000)])
    );
    expect(scanArgumentSecrets({ ...fields, token })?.severity).toBe('block');
  });
});

describe('scan time stays linear', () => {
  it('a 99k alphanumeric run scans in well under a second', () => {
    const started = Date.now();
    inspectArgumentSecrets({ content: 'a'.repeat(99_000) });
    inspectArgumentSecrets({ content: 'https://' + 'a'.repeat(99_000) });
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});
