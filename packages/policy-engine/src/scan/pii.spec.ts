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
  it('instrument: the sweep has teeth (70 fractional parts are card-shaped and pass Luhn alone)', () => {
    expect(FRACTIONS.length).toBe(4950);
    expect(FRACTIONS.filter((x) => hasCard(fractionDigits(x))).length).toBe(70);
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
    expect(flagged.length).toBe(70);
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
