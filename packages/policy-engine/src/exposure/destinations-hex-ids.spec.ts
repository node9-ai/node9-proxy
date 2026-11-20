// A lower-case hex id is not an account (node9Firewall#369). `addIbans`
// upper-cased the whole text before matching, and kept any IBAN-shaped run
// with a failing checksum as an `account:` destination. About 5% of 16- and
// 22-character hex ids (a trace id, a request id, a hash prefix) start with
// two of a-f and two digits, which is that shape. After a session read
// outside content, a send carrying such an id was held as a transfer to an
// unknown account.
import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import { extractContentDestinations, extractArgDestinations } from './destinations';

// A checksum-valid IBAN (the GB example from the IBAN registry), and a sandbox
// account that is IBAN-shaped with no registered country. Assembled so no
// account-shaped literal sits in the source.
const IBAN = ['GB82', 'WEST', '1234', '5698', '7654', '32'].join('');
const SANDBOX = ['US13', '3000', '0001', '2121', '2121', '212'].join('');
const SANDBOX_GB = ['GB82', 'WEST', '1234', '5698', '7654', '99'].join(''); // failing checksum
const HEX16 = ['be12', 'a1b2', 'c3d4', 'e5f6'].join('');

describe('the three rows from the issue: no destination', () => {
  it('a hex id under an id key', () => {
    expect(extractArgDestinations({ trace_id: HEX16 })).toEqual([]);
  });
  it('a hex id in free text, with a word after it', () => {
    expect(extractArgDestinations({ note: `request ${HEX16} failed` })).toEqual([]);
  });
  it('the first 22 characters of a hash that start like a country code', () => {
    const id = ['de12', '9f3a', '7c41', 'b85e', '06d2', 'aa'].join('');
    expect(extractArgDestinations({ id })).toEqual([]);
    expect(extractContentDestinations(`build ${id} passed`)).toEqual([]);
  });
});

describe('a lower-case id under a key that names a destination is still an id', () => {
  it.each(['account', 'target', 'destination', 'to'])('%s', (key) => {
    expect(
      extractArgDestinations({ [key]: HEX16 }).filter((d) => d.startsWith('account:'))
    ).toEqual([]);
  });
});

describe('a real IBAN is an iban in either case and in print format', () => {
  it.each([
    ['upper case', IBAN],
    ['lower case', IBAN.toLowerCase()],
    ['print format', IBAN.replace(/(.{4})/g, '$1 ').trim()],
    [
      'lower case, print format',
      IBAN.toLowerCase()
        .replace(/(.{4})/g, '$1 ')
        .trim(),
    ],
    ['dashes', IBAN.replace(/(.{4})/g, '$1-').replace(/-$/, '')],
  ])('%s', (_name, written) => {
    expect(extractContentDestinations(`Pay to ${written} today.`)).toEqual([`iban:${IBAN}`]);
    expect(extractArgDestinations({ recipient: written })).toEqual([`iban:${IBAN}`]);
    expect(extractArgDestinations({ memo: `ref ${written}` })).toEqual([`iban:${IBAN}`]);
  });
});

describe('a sandbox account written in upper case is still an account', () => {
  it('in content, under a recipient key, and in a free-text argument', () => {
    expect(extractContentDestinations(`Pay to ${SANDBOX}.`)).toEqual([`account:${SANDBOX}`]);
    expect(extractArgDestinations({ recipient: SANDBOX })).toEqual([`account:${SANDBOX}`]);
    expect(extractArgDestinations({ to: SANDBOX })).toEqual([`account:${SANDBOX}`]);
    expect(extractArgDestinations({ subject: SANDBOX })).toEqual([`account:${SANDBOX}`]);
  });

  it('with a registered country and a failing checksum', () => {
    expect(extractContentDestinations(`or ${SANDBOX_GB} (sandbox)`)).toEqual([
      `account:${SANDBOX_GB}`,
    ]);
  });

  it('in print format', () => {
    const printed = SANDBOX_GB.replace(/(.{4})/g, '$1 ').trim();
    expect(extractContentDestinations(`Pay ${printed} now`)).toEqual([`account:${SANDBOX_GB}`]);
  });
});

describe('an account does not run into the next word', () => {
  it('a 24-character account followed by an upper-case word', () => {
    const account = `${SANDBOX}9`; // 24 characters: ends on a group of four
    expect(account).toHaveLength(24);
    expect(extractContentDestinations(`Sent ${account} OKAY`)).toEqual([`account:${account}`]);
    expect(extractArgDestinations({ note: `${account} DONE` })).toEqual([`account:${account}`]);
  });
  it('what the content says and what the call sends are the same string', () => {
    const account = `${SANDBOX}9`;
    const seen = extractContentDestinations(`Transfer to ${account} PLEASE`);
    const sent = extractArgDestinations({ recipient: account });
    expect(sent).toEqual(seen);
  });
});

describe('sweep: hex ids are never an account', () => {
  it.each([16, 20, 22, 24, 32, 40])('100,000 lower-case hex ids of %i characters', (length) => {
    let accounts = 0;
    let ibans = 0;
    for (let i = 0; i < 100_000; i++) {
      const id = createHash('sha256').update(`n9-sweep-${i}`).digest('hex').slice(0, length);
      for (const d of extractArgDestinations({ id })) {
        if (d.startsWith('account:')) accounts++;
        if (d.startsWith('iban:')) ibans++;
      }
    }
    expect(accounts).toBe(0);
    // A hex id that is also a checksum-valid IBAN of a registered country is
    // possible in principle; none occurs in this sweep.
    expect(ibans).toBe(0);
  });
});
