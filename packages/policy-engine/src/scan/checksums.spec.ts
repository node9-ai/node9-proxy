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

// ── IBAN / WIF / xprv validators (commit B) ──────────────────────────────────
import {
  validateIban,
  validateBase58Check,
  validateWif,
  validateXprv,
  IBAN_LENGTH,
} from './checksums';
import {
  asm as asmB,
  IBAN_VALID,
  IBAN_INVALID,
  IBAN_REGISTRY,
  WIF_VALID,
  WIF_INVALID,
  WIF_STOPWORD,
  P2PKH_GENESIS,
  XPRV_VALID,
  XPRV_INVALID,
  ROW_COUNTS as B_COUNTS,
} from '../dlp/checksum.fixtures';

const byId = <T extends { id: string }>(rows: T[], id: string): T => {
  const r = rows.find((x) => x.id === id);
  if (!r) throw new Error(`fixture ${id} missing`);
  return r;
};

describe('checksum fixtures prove they loaded (instrument self-check)', () => {
  it('row counts match the hard-coded expectation', () => {
    expect(IBAN_VALID.length).toBe(B_COUNTS.IBAN_VALID);
    expect(IBAN_INVALID.length).toBe(B_COUNTS.IBAN_INVALID);
    expect(IBAN_REGISTRY.length).toBe(B_COUNTS.IBAN_REGISTRY);
    expect(WIF_VALID.length).toBe(B_COUNTS.WIF_VALID);
    expect(WIF_INVALID.length).toBe(B_COUNTS.WIF_INVALID);
    expect(XPRV_VALID.length).toBe(B_COUNTS.XPRV_VALID);
    expect(XPRV_INVALID.length).toBe(B_COUNTS.XPRV_INVALID);
  });
  it('registry has the 90 SWIFT Release 101 entries and the two length extremes', () => {
    expect(Object.keys(IBAN_LENGTH)).toHaveLength(90);
    expect(IBAN_LENGTH.NO).toBe(15);
    expect(IBAN_LENGTH.RU).toBe(33);
  });
});

describe('validateIban', () => {
  it('accepts every published vector, spaced and unspaced', () => {
    for (const r of IBAN_VALID) {
      expect(validateIban(asmB(r.parts)), r.id).toBe(true);
      expect(validateIban(asmB(r.parts, ' ')), r.id + ' spaced').toBe(true);
      expect(validateIban(asmB(r.parts, '-')), r.id + ' dashed').toBe(true);
    }
  });
  it('rejects every one-character mutation (mod-97)', () => {
    for (const r of IBAN_INVALID) expect(validateIban(asmB(r.parts)), r.id).toBe(false);
  });
  it('registry rows: mod-97 passes, only the registry decides', () => {
    for (const r of IBAN_REGISTRY) expect(validateIban(asmB(r.parts)), r.id).toBe(r.expect);
  });
  it('lowercase is accepted by the validator (case is the regex’s job)', () => {
    expect(validateIban(asmB(byId(IBAN_VALID, 'de-1').parts).toLowerCase())).toBe(true);
  });
  it('rejects empty, too short, and non-letter prefix', () => {
    expect(validateIban('')).toBe(false);
    expect(validateIban('GB29NWBK60')).toBe(false);
    expect(validateIban('1234567890123456')).toBe(false);
  });
});

describe('validateBase58Check', () => {
  it('decodes the genesis P2PKH address to a 21-byte payload with version 0x00', () => {
    const p = validateBase58Check(asmB(P2PKH_GENESIS.parts));
    expect(p).not.toBeNull();
    expect(p!.length).toBe(21);
    expect(p![0]).toBe(0x00);
  });
  it('returns null on a corrupted checksum and on non-base58 input', () => {
    expect(validateBase58Check(asmB(byId(WIF_INVALID, 'wif-u-wiki-bad').parts))).toBeNull();
    expect(validateBase58Check('0OIl')).toBeNull();
    expect(validateBase58Check('')).toBeNull();
  });
});

describe('validateWif', () => {
  it('accepts every published vector', () => {
    for (const r of WIF_VALID) expect(validateWif(asmB(r.parts)), r.id).toBe(true);
  });
  it('rejects every negative, each naming its guard', () => {
    for (const r of WIF_INVALID) expect(validateWif(asmB(r.parts)), r.id).toBe(false);
  });
  it('the P2PKH address passes base58check but fails WIF on version', () => {
    expect(validateWif(asmB(P2PKH_GENESIS.parts))).toBe(false);
  });
  it('a real WIF that contains a stopword substring is still valid', () => {
    expect(validateWif(asmB(WIF_STOPWORD.parts))).toBe(true);
  });
});

describe('validateXprv', () => {
  it('accepts every published private-key vector (xprv, zprv)', () => {
    for (const r of XPRV_VALID) expect(validateXprv(asmB(r.parts)), r.id).toBe(true);
  });
  it('rejects a corrupted checksum, an xpub (public), and a tprv (testnet)', () => {
    for (const r of XPRV_INVALID) expect(validateXprv(asmB(r.parts)), r.id).toBe(false);
  });
});
