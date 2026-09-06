import { describe, it, expect } from 'vitest';
import { validateLuhn } from './checksums';
import { asm, VALID_16, VALID_15, INVALID_16, INVALID_15 } from './pii.fixtures';

// Fixture values are split parts; see pii.fixtures.ts for why. Assertions are
// on booleans only so a failure never prints an assembled number.

const row = (rows: typeof VALID_16, id: string) => {
  const r = rows.find((x) => x.id === id);
  if (!r) throw new Error(`fixture ${id} missing`);
  return r;
};

describe('validateLuhn', () => {
  it('L1 accepts a valid visa', () => {
    expect(validateLuhn(asm(row(VALID_16, 'visa-1').parts))).toBe(true);
  });
  it('L2 rejects the same number with the check digit changed', () => {
    expect(validateLuhn(asm(row(INVALID_16, 'visa-1-bad').parts))).toBe(false);
  });
  it('L3 accepts a 15-digit amex — odd-length parity witness (M7)', () => {
    expect(validateLuhn(asm(row(VALID_15, 'amex-1').parts))).toBe(true);
  });
  it('L4 accepts a mastercard — the -9 correction witness (M6)', () => {
    expect(validateLuhn(asm(row(VALID_16, 'mc-1').parts))).toBe(true);
  });
  it('L5 rejects empty', () => {
    expect(validateLuhn('')).toBe(false);
  });
  it('L6 rejects a short Luhn-valid run — the min-length guard is the ONLY thing stopping it', () => {
    // '18' sums to 10 under raw Luhn and is non-zero, so neither the digit
    // check nor the all-zeros check rejects it. Sole witness for length < 12.
    expect(validateLuhn('18')).toBe(false);
  });
  it('L7 rejects separators — the digits-only contract', () => {
    expect(validateLuhn(asm(row(VALID_16, 'visa-1').parts, '-'))).toBe(false);
  });
  it('L8 rejects trailing whitespace — no silent trimming', () => {
    expect(validateLuhn(asm(row(VALID_16, 'visa-1').parts) + ' ')).toBe(false);
  });
  it('L9 rejects all-zeros of card length', () => {
    expect(validateLuhn('0'.repeat(16))).toBe(false);
  });
  it('rejects an amex with its check digit changed (M11 witness)', () => {
    expect(validateLuhn(asm(row(INVALID_15, 'amex-1-bad').parts))).toBe(false);
  });
  it('every VALID fixture passes and every INVALID fixture fails', () => {
    for (const r of [...VALID_16, ...VALID_15]) expect(validateLuhn(asm(r.parts))).toBe(true);
    for (const r of [...INVALID_16, ...INVALID_15]) expect(validateLuhn(asm(r.parts))).toBe(false);
  });
});
