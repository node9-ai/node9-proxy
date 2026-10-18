// fw#318 review F4/P1: masked destinations, their hashes and the trusted-entry
// form match the shared vectors the backend mirror asserts too; personal data
// inside tool arguments is masked without breaking the JSON it sits in. IBANs
// and card numbers are assembled from parts: none is written whole here.
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import {
  entryDisplay,
  hashDestination,
  isHashedEntry,
  maskDestination,
  maskPersonalData,
  matchesTrustedEntry,
  trustedEntryOf,
} from './mask';

type Vector = {
  dest?: string;
  iban?: { country: string; bban: string };
  spaced?: boolean;
  masked: string;
  hash: string;
  entry: string;
};

/** ISO 13616 check digits: the country and '00' moved to the end, letters to
 *  numbers, 98 minus the remainder mod 97. */
function ibanOf(country: string, bban: string): string {
  const digits = [...`${bban}${country}00`].map((c) => parseInt(c, 36).toString()).join('');
  let rem = 0;
  for (const d of digits) rem = (rem * 10 + Number(d)) % 97;
  return `${country}${String(98 - rem).padStart(2, '0')}${bban}`;
}

function destOf(v: Vector): string {
  if (v.dest) return v.dest;
  const full = ibanOf(v.iban!.country, v.iban!.bban);
  return v.spaced
    ? `iban:${(full.match(/.{1,4}/g) ?? []).join(' ').toLowerCase()}`
    : `iban:${full}`;
}

const VECTORS = (
  JSON.parse(fs.readFileSync(path.join(__dirname, 'personal-data.vectors.json'), 'utf-8')) as {
    vectors: Vector[];
  }
).vectors;

const IBAN = ibanOf('GB', 'NODE' + '000000' + '12345678');
const OTHER_IBAN = ibanOf('GB', 'NODE' + '000001' + '12345678');
const CARD = '4242'.repeat(4);

describe('destinations: the shared vectors', () => {
  it.each(VECTORS.map((v, i) => [i, v] as const))('vector %i', (_i, v) => {
    const dest = destOf(v);
    expect(maskDestination(dest)).toBe(v.masked);
    expect(hashDestination(dest)).toBe(v.hash);
    expect(trustedEntryOf(dest)).toBe(v.entry);
    expect(matchesTrustedEntry(dest, v.entry)).toBe(true);
    expect(entryDisplay(v.entry)).toBe(v.masked);
  });

  it('a different IBAN with the same last four does not match', () => {
    expect(maskDestination(`iban:${OTHER_IBAN}`).slice(-4)).toBe(IBAN.slice(-4));
    expect(matchesTrustedEntry(`iban:${OTHER_IBAN}`, trustedEntryOf(`iban:${IBAN}`))).toBe(false);
  });

  it('a host stays a plain value and matches as one', () => {
    expect(trustedEntryOf('host:Drop.Example')).toBe('host:drop.example');
    expect(isHashedEntry('host:drop.example')).toBe(false);
    expect(matchesTrustedEntry('host:drop.example', 'host:drop.example')).toBe(true);
  });

  it('a plain full value (the local list, an older managed list) still matches', () => {
    expect(matchesTrustedEntry('email:dana@acme.example', 'email:Dana@acme.example')).toBe(true);
  });

  it('a malformed hash is not an entry', () => {
    expect(isHashedEntry('email:d***@acme.example#sha256:xyz')).toBe(false);
  });
});

describe('maskPersonalData: tool arguments', () => {
  const masked = (args: unknown) => JSON.parse(maskPersonalData(JSON.stringify(args)));

  it('masks an IBAN, a card number and an email, and keeps the JSON valid', () => {
    const out = masked({
      recipient: IBAN,
      note: `card ${CARD} for dana@acme.example`,
      to: ['Dana <dana@acme.example>'],
    });
    expect(out.recipient).toBe(`${IBAN.slice(0, 4)} **** **** ${IBAN.slice(-4)}`);
    expect(out.note).toBe('card **** **** **** 4242 for d***@acme.example');
    expect(out.to[0]).toBe('Dana <d***@acme.example>');
    expect(JSON.stringify(out)).not.toContain(IBAN.slice(4, 12));
  });

  it('masks a spaced IBAN', () => {
    const spaced = (IBAN.match(/.{1,4}/g) ?? []).join(' ');
    expect(maskPersonalData(`pay ${spaced} now`)).toBe(
      `pay ${IBAN.slice(0, 4)} **** **** ${IBAN.slice(-4)} now`
    );
  });

  it('masks a sandbox account (failing checksum) as a whole value, in arrays too', () => {
    const sandbox = 'GB00' + 'NODE' + '000000' + '12345678';
    expect(masked({ recipient: sandbox }).recipient).toBe('****5678');
    expect(masked({ recipients: ['x', sandbox, sandbox] }).recipients).toEqual([
      'x',
      '****5678',
      '****5678',
    ]);
    expect(masked({ to: 'api.example.com' }).to).toBe('api.example.com');
  });

  it('masks an account number under an account key, keeps a name there', () => {
    expect(masked({ account: 'TEST00012345678' }).account).toBe('****5678');
    expect(masked({ account: 'billing' }).account).toBe('billing');
  });

  it('leaves what is not personal data alone', () => {
    const text = JSON.stringify({
      command: 'git log -n 4242 && echo GB12ABCD',
      url: 'https://x.example',
    });
    expect(maskPersonalData(text)).toBe(text);
    // A card-shaped number that fails Luhn is not a card.
    expect(maskPersonalData('4242424242424241')).toBe('4242424242424241');
  });

  it('is idempotent', () => {
    const once = maskPersonalData(`dana@acme.example ${IBAN} ${CARD}`);
    expect(maskPersonalData(once)).toBe(once);
  });
});
