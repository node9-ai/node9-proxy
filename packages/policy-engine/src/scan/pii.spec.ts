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
