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
  maskPersonalValue,
  matchesTrustedEntry,
  matchesTrustedList,
  normalizeTrustedEntry,
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

type EntryVector = {
  raw?: string;
  iban?: { country: string; bban: string };
  spaced?: boolean;
  entry: string | null;
};

const FILE = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'personal-data.vectors.json'), 'utf-8')
) as { vectors: Vector[]; entries: EntryVector[] };
const VECTORS = FILE.vectors;

function rawOf(e: EntryVector): string {
  if (e.raw !== undefined) return e.raw;
  const full = ibanOf(e.iban!.country, e.iban!.bban);
  return e.spaced ? (full.match(/.{1,4}/g) ?? []).join(' ') : full;
}

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

  it.each(FILE.entries.map((e, i) => [i, e] as const))('entry vector %i', (_i, e) => {
    expect(normalizeTrustedEntry(rawOf(e))).toBe(e.entry);
  });

  it('matches a list with one hash, plain and hashed entries alike', () => {
    const list = ['host:drop.example', trustedEntryOf(`iban:${IBAN}`)];
    expect(matchesTrustedList(`iban:${IBAN}`, list)).toBe(true);
    expect(matchesTrustedList('host:Drop.Example', list)).toBe(true);
    expect(matchesTrustedList(`iban:${OTHER_IBAN}`, list)).toBe(false);
    expect(matchesTrustedList('host:x.example', [])).toBe(false);
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

  // Review: the checksum upper-cases, so the pattern reads either case.
  it('masks a lower-case IBAN', () => {
    expect(maskPersonalData(`pay ${IBAN.toLowerCase()} now`)).toBe(
      `pay ${IBAN.slice(0, 4)} **** **** ${IBAN.slice(-4)} now`
    );
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
    // Review: an uppercase code with no registered country, or the wrong
    // length for its country, is not an account.
    expect(masked({ ref: 'QQ12ABCDEFGHIJKLM' }).ref).toBe('QQ12ABCDEFGHIJKLM');
    expect(masked({ ref: 'GB12ABCDEFGHIJKLM' }).ref).toBe('GB12ABCDEFGHIJKLM');
  });

  it('masks an account number under an account key, keeps a name there', () => {
    expect(masked({ account: 'TEST00012345678' }).account).toBe('****5678');
    expect(masked({ account: 'billing' }).account).toBe('billing');
    // Review: a profile name with a year in it is not an account number.
    expect(masked({ account: 'prod-2024-eu' }).account).toBe('prod-2024-eu');
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

// Code review of the fw#318 fixes: masking shares the detector's card
// patterns and Luhn check, but not its decimal-fraction exemption (second
// review, finding 2): in text a card after "1." or "0," is masked, and so is
// a Luhn-valid fractional part; a fraction passed as a number stays a number
// (maskPersonalValue). Values are computed at run time.
describe('maskPersonalData: stricter than the detector', () => {
  const FRACTIONS: number[] = [];
  for (let n = 2; n <= 100; n++) for (let k = 1; k < n; k++) FRACTIONS.push(k / n);

  it('instrument: 46/96 has a card-shaped, Luhn-valid fractional part', () => {
    const frac = String(46 / 96).split('.')[1];
    expect(maskPersonalData(frac)).not.toBe(frac);
  });
  it('masks a card after a digit and a dot, a leading dot, or a lone 0 and a comma', () => {
    for (const lead of ['ref 1.', 'x .', 'rate 0,'])
      expect(maskPersonalData(lead + CARD)).toBe(lead + '**** **** **** 4242');
  });
  it('in text, a Luhn-valid fractional part is masked too (pinned trade-off)', () => {
    const changed = FRACTIONS.filter((x) => maskPersonalData(`rate ${x}`) !== `rate ${x}`);
    expect(changed.length).toBe(82); // 70 before the 13-, 14- and 19-digit card shapes (fw#372 B1)
  });
  it('as a value, every fraction k/n (n <= 100) stays the same number', () => {
    const changed = FRACTIONS.filter(
      (x) => (maskPersonalValue({ rate: x }) as { rate: unknown }).rate !== x
    );
    expect(changed.length).toBe(0);
  });
  it('still masks a card in the same JSON shape', () => {
    expect(JSON.parse(maskPersonalData(JSON.stringify({ rate: CARD }))).rate).toBe(
      '**** **** **** 4242'
    );
  });
  it('a lowercase hex id of an account length is not an account', () => {
    const hexId = 'be12' + 'a1b2c3d4e5f6';
    expect(maskPersonalData(JSON.stringify({ trace: hexId }))).toBe(
      JSON.stringify({ trace: hexId })
    );
    // The same value upper-cased is account-shaped for its country (BE, 16).
    expect(JSON.parse(maskPersonalData(JSON.stringify({ trace: hexId.toUpperCase() }))).trace).toBe(
      '****E5F6'
    );
  });
});

describe('maskPersonalValue: arguments as a value', () => {
  it('a fraction stays the same number', () => {
    expect(maskPersonalValue({ rate: 46 / 96, n: 3 })).toEqual({ rate: 46 / 96, n: 3 });
  });
  it('a card passed as a number becomes the masked string, and the value stays JSON', () => {
    const out = maskPersonalValue({ card: Number(CARD), list: [Number(CARD), 1] });
    expect(out).toEqual({ card: '**** **** **** 4242', list: ['**** **** **** 4242', 1] });
    expect(JSON.parse(JSON.stringify(out))).toEqual(out);
  });
  it('applies the account-key and whole-value rules to nested leaves', () => {
    const sandbox = 'GB00' + 'NODE' + '000000' + '12345678';
    expect(
      maskPersonalValue({
        pay: { account: 'TEST00012345678', to: ['x', sandbox], note: 'billing' },
      })
    ).toEqual({ pay: { account: '****5678', to: ['x', '****5678'], note: 'billing' } });
  });
  it('masks an object key as text', () => {
    expect(maskPersonalValue({ ['dana@acme.example']: 1 })).toEqual({ 'd***@acme.example': 1 });
  });
  it('keeps a parsed __proto__ key a plain property', () => {
    const out = maskPersonalValue(JSON.parse('{"__proto__":{"to":"dana@acme.example"}}')) as object;
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(Object.getOwnPropertyDescriptor(out, '__proto__')?.value).toEqual({
      to: 'd***@acme.example',
    });
  });
  it('replaces what is deeper than 64 levels', () => {
    let deep: unknown = 'dana@acme.example';
    for (let i = 0; i < 70; i++) deep = { d: deep };
    expect(JSON.stringify(maskPersonalValue(deep))).toContain('"[REDACTED]"');
    expect(JSON.stringify(maskPersonalValue(deep))).not.toContain('dana@');
  });
  it('passes null, booleans and plain strings through', () => {
    expect(maskPersonalValue(null)).toBe(null);
    expect(maskPersonalValue(true)).toBe(true);
    expect(maskPersonalValue('hi dana@acme.example')).toBe('hi d***@acme.example');
  });
});

// Second code review: a string leaf is masked as raw text before its JSON
// form, so a card or IBAN that begins a line (or follows a tab) is masked
// (finding 1); keys that mask alike keep every entry (finding 3).
describe('maskPersonalValue: line starts and key collisions', () => {
  it('masks a card and an IBAN that begin a line inside a string', () => {
    const csv = ['name,card', 'alice,x', CARD, 'bob', IBAN, ''].join('\n');
    const out = (maskPersonalValue({ content: csv }) as { content: string }).content;
    expect(out).not.toContain(CARD);
    expect(out).not.toContain(IBAN);
    expect(out).toContain('\n**** **** **** 4242\n');
    expect(out).toContain(`\n${IBAN.slice(0, 4)} **** **** ${IBAN.slice(-4)}\n`);
  });
  it('masks a card after a tab', () => {
    expect((maskPersonalValue({ c: 'a\t' + CARD }) as { c: string }).c).toBe(
      'a\t**** **** **** 4242'
    );
  });
  it('keeps both entries when two keys mask to the same text', () => {
    expect(
      maskPersonalValue({ 'dana@acme.example': 'approve', 'dave@acme.example': 'deny' })
    ).toEqual({
      'd***@acme.example': 'approve',
      'd***@acme.example#2': 'deny',
    });
  });
});
