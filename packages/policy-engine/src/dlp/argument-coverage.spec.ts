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
  it('decodes beyond the first window and completes a large ordinary string', () => {
    const result = inspectArgumentSecrets({ content: 'x'.repeat(150_000) });
    expect(result).toMatchObject({ match: null, coverage: 'complete', reasons: [] });
    expect(scanArgumentSecrets({ content: 'x'.repeat(150_000) })).toBeNull();
    // fw#338 review 3: an encoded credential after 100 KB of padding blocks.
    const encoded = Buffer.from(token).toString('base64');
    expect(scanArgumentSecrets({ content: 'x'.repeat(100_000) + ' ' + encoded })?.severity).toBe(
      'block'
    );
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

// fw#338 stage B, independent review of the build.
describe('decoded fragments and decode segments', () => {
  const b64 = (s: string) => Buffer.from(s).toString('base64');
  const azure = 'abc1Q~' + 'Xy9kLm2Pq7Rs4Tu8Vw3Yz6Ab1Cd5Ef0Gh';
  it('matches a boundary-anchored pattern in any fragment, not only the first', () => {
    const decoy = b64('just some ordinary decoded text here');
    for (const body of [`${b64(azure)} ${decoy}`, `${decoy} ${b64(azure)}`])
      expect(scanArgumentSecrets({ body })).toMatchObject({
        patternName: 'Azure AD Client Secret',
        severity: 'block',
      });
  });
  it('decodes an encoded run that crosses a window edge as one run', () => {
    const filler = 'lorem ipsum dolor sit amet consectetur adipiscing elit sed do. ';
    const run = b64(filler.repeat(40) + 'aws_key=' + token + ' ' + filler.repeat(80));
    for (const offset of [88_003, 95_003, 99_003])
      expect(scanArgumentSecrets({ content: 'x'.repeat(offset) + ' ' + run })?.severity).toBe(
        'block'
      );
    const hex = Buffer.from(filler.repeat(40) + 'aws_key=' + token).toString('hex');
    expect(scanArgumentSecrets({ content: 'x'.repeat(86_001) + ' ' + hex })?.severity).toBe(
      'block'
    );
  });
  it('does not review a large markdown file with an emoji and percent-encoded links', () => {
    const para = 'Some **markdown** text ⚠️ with a [link](https://example.com/a%20b) here. ';
    expect(inspectArgumentSecrets({ content: para.repeat(16_000) })).toMatchObject({
      match: null,
      coverage: 'complete',
    });
  });
  it('unwraps base64 written as one full line and a tail, and indented', () => {
    const value = b64('padding text before the key ' + token + ' and some after it');
    const lines = value.match(/.{1,64}/g)!;
    expect(lines.length).toBe(2);
    expect(scanArgumentSecrets({ content: lines.join('\n') })?.severity).toBe('block');
    expect(
      scanArgumentSecrets({ content: 'data: |\n' + lines.map((l) => '    ' + l).join('\n') })
        ?.severity
    ).toBe('block');
  });
  it('reviews a hostname-label flood instead of decoding it without end', () => {
    // A valid DNS name (251 characters) of 2-character hex labels: every
    // 8-label window joins to 16 characters. A host over 253 characters is
    // not a DNS name and is never joined.
    const host = Array(84).fill('ab').join('.');
    const content = Array.from({ length: 1000 }, () => `https://${host}/`).join('\n');
    expect(inspectArgumentSecrets({ content }).reasons).toContain('decode-labels');
    expect(scanArgumentSecrets({ content })?.severity).toBe('review');
  });
});
