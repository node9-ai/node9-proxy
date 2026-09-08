// SSRF corpus section A (normalizeIpLiteral) and B (tiers).
// Ground-truth rule, binding: every positive expectation is justified by the
// inet_aton rule or an RFC, never by what the implementation returns. The row
// comments carry that justification.
import { describe, it, expect } from 'vitest';
import { normalizeIpLiteral, classifySsrf, ssrfFloor, SSRF_MAX_HOST } from './ssrf';

// [id, input, expected] - expected null means "not an IP literal".
const A: Array<[string, string, string | null]> = [
  // A.1 169.254.169.254, every spelling
  ['A1', '169.254.169.254', '169.254.169.254'],
  ['A2', '2852039166', '169.254.169.254'], // 1 component = whole 32 bits
  ['A3', '0xa9fea9fe', '169.254.169.254'],
  ['A4', '0XA9FEA9FE', '169.254.169.254'], // base-0 is case-insensitive
  ['A5', '0251.0376.0251.0376', '169.254.169.254'], // octal components
  ['A6', '169.254.43518', '169.254.169.254'], // 3 components: last fills 16 bits
  ['A7', '169.16689662', '169.254.169.254'], // 2 components: last fills 24 bits
  ['A8', '0xa9.0376.43518', '169.254.169.254'], // mixed radix
  ['A9', '169.254.169.254.', '169.254.169.254'], // one trailing root dot
  ['A10', '[::ffff:a9fe:a9fe]', '169.254.169.254'], // mapped v4, brackets attached
  ['A11', '::ffff:169.254.169.254', '169.254.169.254'],
  ['A12', 'fe80::1%eth0', 'fe80::1'], // zone id is scope, not address
  ['A13', '[fd00:ec2::254]', 'fd00:ec2::254'],
  ['A14', '[::FFFF:A9FE:A9FE]', '169.254.169.254'],
  // A.2 loopback
  ['A15', '127.0.0.1', '127.0.0.1'],
  ['A16', '2130706433', '127.0.0.1'],
  ['A17', '0x7f000001', '127.0.0.1'],
  ['A18', '017700000001', '127.0.0.1'], // 1-component octal
  ['A19', '127.1', '127.0.0.1'], // 2 components: second fills 24 bits, NOT 127.1.0.0
  ['A20', '127.0.1', '127.0.0.1'],
  ['A21', '0x7f.1', '127.0.0.1'],
  ['A22', '[::1]', '::1'],
  ['A23', '[::ffff:7f00:1]', '127.0.0.1'],
  // A.3 RFC1918
  ['A24', '10.0.0.5', '10.0.0.5'],
  ['A25', '167772165', '10.0.0.5'],
  ['A26', '0x0a000005', '10.0.0.5'],
  ['A27', '10.5', '10.0.0.5'], // never 10.5.0.0
  ['A28', '10.0.5', '10.0.0.5'],
  ['A29', '012.0.0.5', '10.0.0.5'], // leading zero = octal
  // A.4 negatives, each naming its guard
  ['A30', '999.1.1.1', null], // component width
  ['A31', '1.2.3.4.5', null], // component count
  ['A32', '0x1.0x2.0x3.0x4.0x5', null], // count guard fires BEFORE radix parsing
  ['A33', '4294967296', null], // 32-bit range
  ['A34', '0x', null], // hex prefix, no digits
  ['A35', '', null],
  ['A36', 'example.com', null],
  ['A37', 'a'.repeat(253), null],
  ['A38', 'a'.repeat(300), null], // the normalizer bounds its own input
  ['A39', 'example.com.169.254.169.254', null], // no substring search may fire
  ['A40', '169.254.169.254.attacker.com', null],
  ['A41', '169.254.169.254.nip.io', null],
  ['A42', '0.0.0.0', '0.0.0.0'], // the unspecified address IS an address
  ['A43', '0xa9fe.0xa9fe', null], // first component must fit 8 bits
  ['A44', '169.254.169.254 ', '169.254.169.254'], // must not depend on caller trimming
  // Added after the mutation pass: three guards had no witness, because for the
  // corpus's inputs the final 32-bit range check caught them by accident.
  ['A47', '1.256.1.1', null], // INTERIOR component > 255. A30 (999.1.1.1) does
  // not witness this: 999 in position 0 overflows 32 bits and is caught by the
  // range check, while 256 in position 1 does not (total stays under 2^32) and
  // would silently produce 2.0.1.1.
  ['A48', '127.99999999', null], // 2-component: the LAST must fit 24 bits.
  // A33 (4294967296) does not witness it: that overflows 32 bits anyway.
  ['A49', '169.254.16777216', null], // same guard, 3-component: last fits 16 bits
];

describe('A. normalizeIpLiteral', () => {
  it.each(A)('%s %j', (_id, input, expected) => {
    expect(normalizeIpLiteral(input)).toBe(expected);
  });

  it('A45/A46 the instrument pair: only a correct octal-aware parser passes both', () => {
    // 010 octal is 8. A non-folding impl returns the input; a decimal-reading
    // impl returns 10.10.10.10; an always-null stub returns null. 8.8.8.8 is an
    // independently known address unrelated to any tier, so a tier table alone
    // cannot pass this either.
    expect(normalizeIpLiteral('010.010.010.010')).toBe('8.8.8.8');
    // A substring matcher would return non-null here.
    expect(normalizeIpLiteral('169.254.169.254.attacker.com')).toBeNull();
  });

  it('never throws on hostile input', () => {
    const hostile = ['', '.', '..', 'a'.repeat(SSRF_MAX_HOST + 50), '0x.0x', ' '];
    for (const s of hostile) expect(() => normalizeIpLiteral(s)).not.toThrow();
  });
});

// [id, host, tier or null, overridable, kind]
const B: Array<[string, string, string | null, boolean, string]> = [
  ['B1', '169.254.169.254', 'metadata', false, 'address'],
  ['B2', '169.254.170.2', 'metadata', false, 'address'],
  ['B3', '168.63.129.16', 'metadata', false, 'address'],
  ['B4', 'metadata.google.internal', 'metadata', false, 'hostname'],
  ['B5', 'metadata.goog', 'metadata', false, 'hostname'],
  ['B6', 'metadata', 'metadata', false, 'hostname'],
  ['B7', 'fd00:ec2::254', 'metadata', false, 'address'],
  ['B8', '169.253.255.255', null, false, 'address'],
  ['B9', '169.254.0.0', 'link-local', false, 'address'],
  ['B10', '169.254.255.255', 'link-local', false, 'address'],
  ['B11', '169.255.0.0', null, false, 'address'],
  ['B12', 'fe80::1', 'link-local', false, 'address'],
  ['B13', '223.255.255.255', null, false, 'address'],
  ['B14', '224.0.0.1', 'multicast', false, 'address'],
  ['B15', '239.255.255.255', 'multicast', false, 'address'],
  ['B16', '240.0.0.1', null, false, 'address'],
  ['B17', 'ff02::1', 'multicast', false, 'address'],
  ['B18', '0.0.0.0', 'unspecified', false, 'address'],
  ['B19', '::', 'unspecified', false, 'address'],
  ['B20', '100.63.255.255', null, false, 'address'],
  ['B21', '100.64.0.0', 'cgnat', true, 'address'],
  ['B22', '100.127.255.255', 'cgnat', true, 'address'],
  ['B23', '100.128.0.0', null, false, 'address'],
  ['B24', '127.0.0.1', 'private', true, 'address'],
  ['B25', '::1', 'private', true, 'address'],
  ['B26', '10.0.0.5', 'private', true, 'address'],
  ['B27', '192.168.1.1', 'private', true, 'address'],
  ['B28', '172.16.0.1', 'private', true, 'address'],
  ['B29', '172.15.255.255', null, false, 'address'],
  ['B30', '172.32.0.0', null, false, 'address'],
  ['B31', 'fd00::1', null, false, 'address'],
  ['B32', '8.8.8.8', null, false, 'address'],
  ['B33', 'example.com', null, false, 'hostname'],
  ['B34', '169.254.169.254.nip.io', null, false, 'hostname'],
];

describe('B. classifySsrf tiers', () => {
  it.each(B)('%s %s', (_id, host, tier, overridable, kind) => {
    const m = classifySsrf(host);
    if (tier === null) {
      expect(m).toBeNull();
      return;
    }
    expect(m).not.toBeNull();
    expect(m!.tier).toBe(tier);
    expect(m!.overridable).toBe(overridable);
    expect(m!.kind).toBe(kind);
    if (kind === 'hostname') expect(m!.normalized).toBeUndefined();
    else expect(typeof m!.normalized).toBe('string');
  });

  it('every alternative spelling of the metadata address classifies identically', () => {
    const spellings = ['2852039166', '0xa9fea9fe', '0251.0376.0251.0376', '169.254.43518'];
    for (const s of spellings) {
      const m = classifySsrf(s);
      expect(m?.tier, s).toBe('metadata');
      expect(m?.normalized, s).toBe('169.254.169.254');
    }
  });

  it('never throws', () => {
    for (const s of ['', '.', 'a'.repeat(300)]) expect(() => classifySsrf(s)).not.toThrow();
  });

  it('C-floor a tier-1 address in ssrfAllow is NOT exempted (the floor itself refuses)', () => {
    const tokens = [{ token: '169.254.169.254', binary: 'curl' }];
    expect(ssrfFloor(tokens, { ssrfAllow: ['169.254.169.254'] })?.tier).toBe('metadata');
    // Any spelling of it, not just the one the operator typed.
    expect(
      ssrfFloor([{ token: '2852039166', binary: 'curl' }], { ssrfAllow: ['2852039166'] })?.tier
    ).toBe('metadata');
    // The config layer ALSO drops such an entry at load; these are two
    // independent guards and this row witnesses the one in the floor.
  });

  it('C-floor2 an OVERRIDABLE tier is exempted, in any spelling', () => {
    expect(ssrfFloor([{ token: '100.64.0.1', binary: 'curl' }], {})?.tier).toBe('cgnat');
    expect(
      ssrfFloor([{ token: '100.64.0.1', binary: 'curl' }], { ssrfAllow: ['100.64.0.1'] })
    ).toBeNull();
    // exemption is by canonical address, so a different spelling of the same
    // address is exempt too.
    expect(
      ssrfFloor([{ token: '1678033921', binary: 'curl' }], { ssrfAllow: ['100.64.0.1'] })
    ).toBeNull();
  });

  it('C-floor3 tier 3 is opt-in and exemptable', () => {
    const lo = [{ token: '127.0.0.1', binary: 'curl' }];
    expect(ssrfFloor(lo, {})).toBeNull();
    expect(ssrfFloor(lo, { ssrfStrict: true })?.tier).toBe('private');
    expect(ssrfFloor(lo, { ssrfStrict: true, ssrfAllow: ['127.0.0.1'] })).toBeNull();
  });
});
