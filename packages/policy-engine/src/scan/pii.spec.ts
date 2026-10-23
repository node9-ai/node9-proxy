// detectArgsPii / detectPii — PII detection, realtime and offline paths.
//
// detectPii is the offline detector (canonical extractor, daemon watermark).
// detectArgsPii adapts it for the realtime authorize path: walks a tool-args
// value and returns only the HIGH-SIGNAL patterns worth gating in real time
// (SSN, Credit Card). Email/Phone are intentionally excluded — they appear
// constantly in normal dev work and would make realtime enforcement too noisy.
//
// Card rows are driven by pii.fixtures.ts (split parts, see that file). The
// SSN fixture is split for the same reason. Every assertion below is on a
// boolean or on a PiiPattern[]; no assembled value is ever interpolated into
// a title or message, so a failure cannot print PII into CI logs.

import { describe, it, expect } from 'vitest';
import { detectArgsPii, detectPii, REALTIME_PII_PATTERNS } from './pii';
import {
  asm,
  VALID_16,
  VALID_15,
  INVALID_16,
  INVALID_15,
  NON_CARD_16,
  NON_CARD_LUHN_VALID,
  COMPOSITE,
  MULTILINE_CSV,
  ROW_COUNTS,
  VALID_OTHER_NETWORKS,
  NOT_A_NETWORK,
} from './pii.fixtures';

const SSN = ['123', '45', '6789'].join('-');
const hasCard = (s: string) => detectPii(s).includes('Credit Card');
const argsHasCard = (v: unknown) => detectArgsPii(v).includes('Credit Card');

describe('fixture module proves it loaded (instrument self-check)', () => {
  it('row counts match the hard-coded expectation', () => {
    expect(VALID_16.length).toBe(ROW_COUNTS.VALID_16);
    expect(VALID_15.length).toBe(ROW_COUNTS.VALID_15);
    expect(INVALID_16.length).toBe(ROW_COUNTS.INVALID_16);
    expect(INVALID_15.length).toBe(ROW_COUNTS.INVALID_15);
    expect(NON_CARD_16.length).toBe(ROW_COUNTS.NON_CARD_16);
    expect(COMPOSITE.length).toBe(ROW_COUNTS.COMPOSITE);
    expect(VALID_OTHER_NETWORKS.length).toBe(ROW_COUNTS.VALID_OTHER_NETWORKS);
    expect(NOT_A_NETWORK.length).toBe(ROW_COUNTS.NOT_A_NETWORK);
  });
  it('R1 known-true canary: an SSN is detected (independent of the card change)', () => {
    expect(detectArgsPii({ command: 'echo ' + SSN })).toEqual(['SSN']);
  });
});

describe('detectPii — credit cards (offline path)', () => {
  it('V: every Luhn-valid 16-digit fixture is detected', () => {
    for (const r of VALID_16) expect(hasCard(asm(r.parts)), r.id).toBe(true);
  });
  it('V7/V8: 15-digit Amex is detected (was a complete false negative)', () => {
    for (const r of VALID_15) expect(hasCard(asm(r.parts)), r.id).toBe(true);
  });
  it('F: same shape with one digit changed is NOT detected', () => {
    for (const r of INVALID_16) expect(hasCard(asm(r.parts)), r.id).toBe(false);
    for (const r of INVALID_15) expect(hasCard(asm(r.parts)), r.id).toBe(false);
  });
  it('N: non-card 16-digit identifiers are NOT detected', () => {
    for (const r of NON_CARD_16) expect(hasCard(asm(r.parts)), r.id).toBe(false);
  });
  it('N6: a Luhn-valid non-card still IS detected — honest limitation, pinned', () => {
    expect(hasCard(asm(NON_CARD_LUHN_VALID.parts))).toBe(true);
  });
  it('composite rows: separators, boundaries, ordering, the decoy attack', () => {
    for (const c of COMPOSITE) expect(hasCard(c.build()), c.id).toBe(c.expectCard);
  });
  it('X4: two consecutive calls on the same input agree (no shared lastIndex)', () => {
    const decoy = COMPOSITE.find((c) => c.id === 'decoy-then-valid')!;
    const s = decoy.build();
    expect(hasCard(s)).toBe(true);
    expect(hasCard(s)).toBe(true);
    const bad = asm(INVALID_16[0].parts);
    expect(hasCard(bad)).toBe(false);
    expect(hasCard(bad)).toBe(false);
  });
  it('R6: exact result set for a lone card is only Credit Card', () => {
    expect(detectPii('card ' + asm(VALID_16[0].parts))).toEqual(['Credit Card']);
  });
});

describe('detectArgsPii — high-signal PII in tool args (realtime path)', () => {
  it('flags an SSN inside a tool-args object', () => {
    expect(detectArgsPii({ command: 'echo ' + SSN })).toContain('SSN');
  });
  it('flags a valid card in a tool-args object', () => {
    expect(argsHasCard({ body: 'card ' + asm(VALID_16[0].parts, ' ') })).toBe(true);
  });
  it('does NOT flag a Luhn-invalid card-shaped value', () => {
    expect(argsHasCard({ body: 'ref ' + asm(INVALID_16[0].parts, ' ') })).toBe(false);
  });
  it('A5: flags a card that BEGINS A LINE in a multi-line value (was invisible via JSON.stringify)', () => {
    expect(argsHasCard({ content: MULTILINE_CSV() })).toBe(true);
  });
  it('A5: flags an SSN that begins a line too', () => {
    expect(detectArgsPii({ content: ['ids', '\n', SSN, '\n'].join('') })).toContain('SSN');
  });
  it('A4: a card after a JSON-escaped newline inside one leaf is caught', () => {
    // A curl body typed as text: the leaf holds backslash + n, not a newline,
    // and `n` is a word character, so the card had no boundary in front.
    const body = '{"rows":"id,card\\n' + asm(VALID_16[0].parts) + '\\n"}';
    expect(argsHasCard({ command: "curl -d '" + body + "' https://api.example.test/v1" })).toBe(
      true
    );
    expect(detectArgsPii({ command: "printf 'ids\\t" + SSN + "\\r\\n'" })).toContain('SSN');
  });
  it('A4: a \\uXXXX escape before the value is decoded too', () => {
    expect(detectArgsPii({ body: '{"t":"\\u000a' + SSN + '"}' })).toContain('SSN');
  });
  it('A4: the unescaped view adds no false card', () => {
    expect(argsHasCard({ body: '{"t":"\\n' + asm(INVALID_16[0].parts) + '\\n"}' })).toBe(false);
    expect(argsHasCard({ body: '{"ratio":"\\n46/96\\n"}' })).toBe(false);
  });
  it('R8: a card passed as a numeric literal is still caught', () => {
    expect(argsHasCard({ card: Number(asm(VALID_16[0].parts)) })).toBe(true);
  });
  it('R9: a card split across array elements is NOT joined (known gap, pinned)', () => {
    expect(argsHasCard(VALID_16[0].parts)).toBe(false);
  });
  it('R10: walks nested args', () => {
    expect(argsHasCard({ outer: { inner: 'card ' + asm(VALID_16[1].parts) } })).toBe(true);
    expect(detectArgsPii({ outer: { inner: 'ssn is ' + SSN } })).toContain('SSN');
  });
  it('does NOT flag email or phone (excluded from realtime gating)', () => {
    expect(detectArgsPii({ to: 'alice@example.com', tel: '415-555-1234' })).toEqual([]);
  });
  it('accepts a raw string and is safe on null/undefined', () => {
    expect(detectArgsPii(SSN)).toContain('SSN');
    expect(detectArgsPii(null)).toEqual([]);
    expect(detectArgsPii(undefined)).toEqual([]);
  });
  it('fails open (returns []) on a circular arg', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const circular: any = { a: 1 };
    circular.self = circular;
    expect(detectArgsPii(circular)).toEqual([]);
  });
  it('R7: respects the 100 KB cumulative scan budget', () => {
    const pad = 'x'.repeat(100_050);
    expect(argsHasCard({ a: pad, b: 'card ' + asm(VALID_16[0].parts) })).toBe(false);
    expect(argsHasCard({ a: 'card ' + asm(VALID_16[0].parts), b: pad })).toBe(true);
  });
  it('REALTIME_PII_PATTERNS is the high-signal subset only', () => {
    expect(REALTIME_PII_PATTERNS).toContain('SSN');
    expect(REALTIME_PII_PATTERNS).toContain('Credit Card');
    expect(REALTIME_PII_PATTERNS).not.toContain('Email');
    expect(REALTIME_PII_PATTERNS).not.toContain('Phone');
  });
});

// ── decimal fractions (node9Firewall#333) ──────────────────────────────────
// A float printed at full precision has 16 or 17 digits after `0.`, and the
// `.` is a word boundary, so the fractional part used to read as a card.
// Values are computed at run time: the literals are exactly what the realtime
// gate blocked, so they cannot appear in source or in a tool call.

/** Every simple fraction k/n with 2 <= n <= 100 (4,950 values). */
const FRACTIONS: number[] = [];
for (let n = 2; n <= 100; n++) for (let k = 1; k < n; k++) FRACTIONS.push(k / n);
const fractionDigits = (x: number) => String(x).split('.')[1] ?? '';

describe('detectPii — decimal fractions are not cards (#333)', () => {
  // 70 under the 15- and 16-digit shapes; 82 since the 13-, 14- and 19-digit
  // shapes joined (fw#372 B1). The exemption below keeps every one of them out.
  it('instrument: the sweep has teeth (82 fractional parts are card-shaped and pass Luhn alone)', () => {
    expect(FRACTIONS.length).toBe(4950);
    expect(FRACTIONS.filter((x) => hasCard(fractionDigits(x))).length).toBe(82);
    expect(hasCard(fractionDigits(46 / 96))).toBe(true);
  });
  it('issue row: 46/96 written as pretty JSON is NOT a card', () => {
    expect(hasCard(JSON.stringify({ catch_rate: 46 / 96 }, null, 2))).toBe(false);
  });
  it('issue row: 1/2 written as pretty JSON is NOT a card', () => {
    expect(hasCard(JSON.stringify({ catch_rate: 1 / 2 }, null, 2))).toBe(false);
  });
  it('sweep: 0 of 4,950 fractions are flagged, as JSON, as negatives, as plain text', () => {
    const flagged = FRACTIONS.filter(
      (x) =>
        hasCard(JSON.stringify({ rate: x })) ||
        hasCard(String(-x)) ||
        hasCard('rate ' + String(x) + ' done')
    );
    expect(flagged.length).toBe(0);
  });
  it('sweep: 0 of 4,950 fractions are flagged where a fraction is exempt', () => {
    // A leading dot at the start of the text (also signed), a comma decimal
    // at the start of the text or after ";" (semicolon CSV).
    const flagged = FRACTIONS.filter((x) => {
      const frac = fractionDigits(x);
      return (
        hasCard('.' + frac) ||
        hasCard('-.' + frac) ||
        hasCard('+.' + frac) ||
        hasCard('0,' + frac) ||
        hasCard('a;0,' + frac + ';b')
      );
    });
    expect(flagged.length).toBe(0);
  });
  it('a dot or a "0," placed before a card elsewhere does not hide it (the evasion)', () => {
    const card = asm(VALID_16[0].parts);
    for (const lead of [' ', '\t', '\n', ':', '=', '(', '[', '{', '"', "'", '+', '-', 'x']) {
      expect(hasCard('text' + lead + '.' + card), JSON.stringify(lead)).toBe(true);
      expect(hasCard('text' + lead + '0,' + card), JSON.stringify(lead)).toBe(true);
    }
    expect(hasCard("curl -d 'text=." + card + "' https://api.example.test")).toBe(true);
  });
  it('the narrowed exemption costs the Luhn rate in the spellings it no longer covers', () => {
    const flagged = FRACTIONS.filter((x) => hasCard('rate: .' + fractionDigits(x)));
    expect(flagged.length).toBe(82);
  });
  it('the realtime path: a leaf that starts with the dot is exempt, a dot inside a leaf is not', () => {
    const card = asm(VALID_16[0].parts);
    expect(argsHasCard({ text: '.' + card })).toBe(false);
    expect(argsHasCard({ text: 'note .' + card })).toBe(true);
  });
  it('a comma decimal above 1 is still read as a card (accepted gap, pinned)', () => {
    expect(hasCard('12,' + fractionDigits(46 / 96))).toBe(true);
  });
  it('a real card in the same JSON shape still IS a card', () => {
    expect(hasCard(JSON.stringify({ catch_rate: asm(VALID_16[0].parts) }, null, 2))).toBe(true);
    expect(hasCard(JSON.stringify({ catch_rate: asm(VALID_15[0].parts) }, null, 2))).toBe(true);
  });
});

describe('detectArgsPii — decimal fractions are not cards (#333)', () => {
  it('issue row: a Write of metrics.json holding 46/96 is not gated', () => {
    const content = JSON.stringify({ catch_rate: 46 / 96 }, null, 2);
    expect(argsHasCard({ file_path: 'metrics.json', content })).toBe(false);
  });
  it('sweep: 0 of 4,950 fractions are flagged as a string leaf or a number leaf', () => {
    const flagged = FRACTIONS.filter(
      (x) => argsHasCard({ content: JSON.stringify({ rate: x }) }) || argsHasCard({ rate: x })
    );
    expect(flagged.length).toBe(0);
  });
  it('a real card in the same Write shape is still gated', () => {
    const content = JSON.stringify({ catch_rate: asm(VALID_16[0].parts) }, null, 2);
    expect(argsHasCard({ file_path: 'metrics.json', content })).toBe(true);
  });
});

// ── IBAN (commit B) ─────────────────────────────────────────────────────────
import { IBAN_VALID, IBAN_INVALID, IBAN_REGISTRY, asm as asmB } from '../dlp/checksum.fixtures';

const ib = (id: string, rows = IBAN_VALID) => {
  const r = rows.find((x) => x.id === id);
  if (!r) throw new Error(`fixture ${id} missing`);
  return r.parts;
};
const hasIban = (s: string) => detectPii(s).includes('IBAN');
const argsHasIban = (v: unknown) => detectArgsPii(v).includes('IBAN');

describe('detectPii — IBAN (offline path)', () => {
  it('every published vector is detected, unspaced and spaced', () => {
    for (const r of IBAN_VALID) {
      expect(hasIban(asmB(r.parts)), r.id).toBe(true);
      expect(hasIban(asmB(r.parts, ' ')), r.id + ' spaced').toBe(true);
    }
  });
  it('a mod-97 failure is not detected', () => {
    for (const r of IBAN_INVALID) expect(hasIban(asmB(r.parts)), r.id).toBe(false);
  });
  it('registry rows follow the validator (unknown country / too short rejected, long prefix accepted)', () => {
    for (const r of IBAN_REGISTRY) expect(hasIban(asmB(r.parts)), r.id).toBe(r.expect);
  });
  it('lowercase is NOT detected (uppercase-only regex, pinned: lowercase hex-hash shapes would leak through mod-97 at 1/97)', () => {
    expect(hasIban(asmB(ib('de-1')).toLowerCase())).toBe(false);
  });
  it('an IBAN followed by a BIC on the same line is still detected (length-as-minimum, F1)', () => {
    expect(hasIban('IBAN: ' + asmB(ib('gb-1'), ' ') + ' BIC: NWBKGB2L')).toBe(true);
  });
  it('glued to a word it is not detected (leading \\b), pinned', () => {
    expect(hasIban('ref' + asmB(ib('de-1')))).toBe(false);
  });
  it('R6: exact result set for a lone IBAN is only IBAN', () => {
    expect(detectPii('acct ' + asmB(ib('de-1')))).toEqual(['IBAN']);
  });
});

describe('detectArgsPii — IBAN is realtime-gated', () => {
  it('rt-realtime-list: IBAN is in REALTIME_PII_PATTERNS', () => {
    expect(REALTIME_PII_PATTERNS).toContain('IBAN');
  });
  it('rt-nested: found two levels deep', () => {
    expect(argsHasIban({ a: { b: ['iban: ' + asmB(ib('de-1'))] } })).toBe(true);
  });
  it('rt-invalid: a mod-97 failure is not flagged', () => {
    expect(argsHasIban({ a: 'iban: ' + asmB(ib('de-1-bad', IBAN_INVALID)) })).toBe(false);
  });
  it('rt-registry: mod-97 passes but the country is unregistered → not flagged', () => {
    expect(argsHasIban({ a: asmB(ib('reg-unknown-cc', IBAN_REGISTRY)) })).toBe(false);
  });
  it('rt-overlap: an IBAN-shaped token that fails the validator, then a valid one → flagged', () => {
    expect(argsHasIban({ a: 'XX12 ' + asmB(ib('gb-1'), ' ') })).toBe(true);
  });
  it('rt-multiline-a5: IBAN at line start inside a CSV value is flagged', () => {
    const csv = [
      'name,iban',
      '\n',
      'alice,',
      asmB(ib('de-1')),
      '\n',
      'bob,',
      asmB(ib('gb-1')),
      '\n',
    ].join('');
    expect(argsHasIban({ content: csv })).toBe(true);
  });
  it('rt-line-start-spaced: a spaced IBAN alone on a line is flagged', () => {
    expect(argsHasIban({ content: '\n' + asmB(ib('gb-1'), ' ') + '\n' })).toBe(true);
  });
});

describe('card networks beyond Visa/Mastercard/Discover/Amex (fw#372 B1)', () => {
  it.each(VALID_OTHER_NETWORKS.map((r) => [r.id, r] as const))(
    '%s is a card, spaced, dashed, dotted and unspaced',
    (_id, row) => {
      for (const sep of [' ', '-', '.', '']) {
        expect(
          hasCard('card ' + asm(row.parts, sep) + ' end'),
          `${_id} sep=${JSON.stringify(sep)}`
        ).toBe(true);
        expect(argsHasCard({ body: asm(row.parts, sep) }), _id).toBe(true);
      }
    }
  );
  it.each(NOT_A_NETWORK.map((r) => [r.id, r] as const))(
    '%s passes Luhn but is no network: not a card',
    (_id, row) => {
      expect(hasCard('card ' + asm(row.parts, ' ') + ' end'), _id).toBe(false);
      expect(hasCard(asm(row.parts)), _id).toBe(false);
    }
  );
  it('a digit mutation of a 2-series or Diners card fails Luhn and is not a card', () => {
    const mc = [...VALID_OTHER_NETWORKS[0].parts];
    mc[3] = mc[3].slice(0, 3) + ((Number(mc[3][3]) + 1) % 10);
    expect(hasCard(asm(mc, ' '))).toBe(false);
    const dc = [...VALID_OTHER_NETWORKS[3].parts];
    dc[2] = dc[2].slice(0, 3) + ((Number(dc[2][3]) + 1) % 10);
    expect(hasCard(asm(dc, ' '))).toBe(false);
  });
  it('the dot separator does not read a version or an IP as a card', () => {
    expect(hasCard('1.2.3.4 10.0.0.1 2024.10.23 4.1.2.3')).toBe(false);
  });
});

describe('bank routing number with its label (fw#372 B3)', () => {
  // Public institutional routing numbers (Federal Reserve Bank of Boston, JPMorgan Chase).
  const RTN = ['011', '000', '015'].join('');
  const RTN2 = ['021', '000', '021'].join('');
  const BAD = ['011', '000', '016'].join(''); // one digit off: fails the 3-7-1 check
  it('is found with a label before or after it, in text and in tool arguments', () => {
    expect(detectPii(`routing number: ${RTN}`)).toContain('Bank Routing Number');
    expect(detectPii(`ABA ${RTN2}, account 9876`)).toContain('Bank Routing Number');
    expect(detectPii(`${RTN} (RTN)`)).toContain('Bank Routing Number');
    expect(
      detectArgsPii({ body: JSON.stringify({ routing: RTN, account: '12345678' }) })
    ).toContain('Bank Routing Number');
    expect(REALTIME_PII_PATTERNS).toContain('Bank Routing Number');
  });
  it('needs both the checksum and the label', () => {
    expect(detectPii(`routing number: ${BAD}`)).not.toContain('Bank Routing Number');
    expect(detectPii(`order ${RTN} shipped`)).not.toContain('Bank Routing Number');
    expect(detectPii(`id=${RTN}`)).not.toContain('Bank Routing Number');
    // The label is more than 24 characters away.
    expect(detectPii(`routing ${'x'.repeat(30)} ${RTN}`)).not.toContain('Bank Routing Number');
  });
  it('a nine-digit number in an unassigned range is not a routing number even with a label', () => {
    expect(detectPii('routing 987654321')).not.toContain('Bank Routing Number');
  });
});

describe('national identifiers with a check digit (fw#372 B2)', () => {
  // Synthetic values; every check digit was computed by hand in Python at
  // authoring time, independently of the validators under test.
  const valid: Array<[string, string]> = [
    ['codice fiscale', 'RSSMRA85T10A562S'],
    ['DNI', '12345678Z'],
    ['NIE', 'X1234567L'],
    ['NIR', '185057512345673'],
    ['NIR spaced', '1 85 05 75 123 456 73'],
    ['NIR abroad', '290019900011194'],
    ['AHV', '756.1234.5678.97'],
    ['UID', 'CHE-109.671.514'],
  ];
  it.each(valid)('%s is found, in text and in tool arguments', (_label, value) => {
    expect(detectPii(`id: ${value} end`)).toContain('National ID');
    expect(detectArgsPii({ customer: { id: value } })).toContain('National ID');
  });
  it('the Nordic numbers, PESEL and CNP need their name within 32 characters before them', () => {
    const rows: Array<[string, string]> = [
      ['personnummer', '811218-9876'],
      ['fødselsnummer', '15067545602'],
      ['fodselsnummer', '15067545602'],
      ['hetu', '131052-308T'],
      ['henkilötunnus', '010100A123D'],
      ['PESEL', '90041501239'],
      ['numer PESEL', '02212804566'],
      ['CNP', '1860415123457'],
      ['cod numeric personal', '2980507234563'],
    ];
    for (const [label, value] of rows) {
      expect(detectPii(`${label}: ${value}`), label).toContain('National ID');
      expect(detectPii(`value ${value}`), label).not.toContain('National ID');
      expect(detectPii(`${label} ${'x'.repeat(40)} ${value}`), label).not.toContain('National ID');
    }
  });
  it('a wrong check digit, an impossible date or an unassigned range is not an ID', () => {
    for (const bad of [
      'RSSMRA85T10A562T', // check letter off by one
      '12345678A', // DNI letter does not match
      'PESEL 90041501238', // PESEL check digit off
      'PESEL 90131501239', // PESEL month 13
      'CNP 1860415123458', // CNP check off
      'CNP 1860415993457', // CNP county 99
      '185057512345674', // NIR key off
      '756.1234.5678.98', // AHV check off
      'CHE-109.671.515', // UID check off
      'personnummer 811218-9877', // Luhn off
    ]) {
      expect(detectPii(`id: ${bad}`), bad).not.toContain('National ID');
    }
  });
  it('timestamps, phone numbers and hashes are not IDs', () => {
    for (const t of [
      '1729700000000',
      '1700612345678',
      '1712345678901',
      '15551234567',
      '48123456789',
      'd41d8cd98f00b204e9800998ecf8427e',
      '20240101T120000Z',
      'commit 3f2a9c1b7e6d5a4f',
    ]) {
      expect(detectPii(t), t).not.toContain('National ID');
    }
  });
  it('is realtime-gated', () => {
    expect(REALTIME_PII_PATTERNS).toContain('National ID');
  });
  it('millisecond timestamps and 11-digit ids with no label are not IDs (review finding)', () => {
    // Values that pass the CNP and PESEL rules by chance, as a JSON body carries them.
    expect(detectPii('{"createdAt":1860415123457,"order":90041501239}')).not.toContain(
      'National ID'
    );
  });
});

describe('an IBAN that IS the recipient is a destination, not leaked PII (fw#372 X1)', () => {
  const IBAN = asmB(ib('de-1'), ' ');
  it('the whole value under a recipient-like key is not flagged; elsewhere it is', () => {
    for (const key of [
      'recipient',
      'iban',
      'account',
      'payee',
      'to',
      'beneficiary',
      'account_number',
    ]) {
      expect(argsHasIban({ [key]: IBAN }), key).toBe(false);
      expect(argsHasIban({ transfer: { [key]: IBAN, amount: 10 } }), key).toBe(false);
    }
    expect(argsHasIban({ note: IBAN })).toBe(true);
    expect(argsHasIban({ body: 'please pay ' + IBAN })).toBe(true);
    expect(argsHasIban({ recipient: 'pay ' + IBAN + ' today' })).toBe(true);
  });
  it('the offline detector is unchanged: the value is still an IBAN in text', () => {
    expect(hasIban('recipient: ' + IBAN)).toBe(true);
  });
});

describe('IBAN: the country fixes the BBAN shape (fw#372 X5)', () => {
  // Every value here passes mod-97; the check digits were computed in Python.
  it('letters inside a German BBAN are not an IBAN', () => {
    expect(hasIban('DE24370400440532ABCD00')).toBe(false);
    expect(hasIban('DE24 3704 0044 0532 ABCD 00')).toBe(false);
  });
  it.each([
    'NL91ABNA0417164300',
    'ES9121000418450200051332',
    'IT60X0542811101000000123456',
    'CH9300762011623852957',
    'PL61109010140000071219812874',
    'IL620108000000099999999',
  ])('%s keeps its country shape and is an IBAN', (iban) => {
    expect(hasIban('acct ' + iban)).toBe(true);
  });
});
