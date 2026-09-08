// Detector-level rows for the checksum-validated DLP patterns (WIF, xprv) and
// for the `validate` hook itself across all three entrypoints. Validator unit
// rows live in scan/checksums.spec.ts; these prove the wiring.
import { describe, it, expect } from 'vitest';
import { scanArgs, scanText, redactText, DLP_PATTERNS } from './index';
import {
  asm,
  WIF_VALID,
  WIF_INVALID,
  WIF_STOPWORD,
  XPRV_VALID,
  XPRV_INVALID,
} from './checksum.fixtures';

const row = <T extends { id: string }>(rows: T[], id: string): T => {
  const r = rows.find((x) => x.id === id);
  if (!r) throw new Error(`fixture ${id} missing`);
  return r;
};
const WIF_U = asm(row(WIF_VALID, 'wif-u-wiki').parts);
const WIF_C = asm(row(WIF_VALID, 'wif-c-wiki').parts);
const WIF_K1 = asm(row(WIF_VALID, 'wif-u-k1').parts);
const WIF_U_BAD = asm(row(WIF_INVALID, 'wif-u-wiki-bad').parts);
const WIF_C_BAD = asm(row(WIF_INVALID, 'wif-c-wiki-bad').parts);
const WIF_VER81 = asm(row(WIF_INVALID, 'wif-ver81').parts);
const XPRV = asm(row(XPRV_VALID, 'xprv-tv1-m').parts);
const XPRV_BAD = asm(row(XPRV_INVALID, 'xprv-tv1-m-bad').parts);
const XPUB = asm(row(XPRV_INVALID, 'xpub-tv1-m').parts);
const WIF_SW = asm(WIF_STOPWORD.parts);

describe('pattern registration', () => {
  it('both patterns exist, are block severity, and carry a validator', () => {
    for (const name of ['Bitcoin WIF Private Key', 'Extended Private Key']) {
      const p = DLP_PATTERNS.find((x) => x.name === name);
      expect(p, name).toBeDefined();
      expect(p!.severity).toBe('block');
      expect(typeof p!.validate).toBe('function');
    }
  });
  it('the pattern-count floor moves with them', () => {
    expect(DLP_PATTERNS.length).toBeGreaterThanOrEqual(58);
  });
});

describe('c4 validate fires in all three entrypoints — WIF', () => {
  it('scanArgs: valid reported, block, sample masks the key', () => {
    const m = scanArgs({ env: { WIF: WIF_C } });
    expect(m?.patternName).toBe('Bitcoin WIF Private Key');
    expect(m?.severity).toBe('block');
    expect(m?.redactedSample.startsWith(WIF_C.slice(0, 4))).toBe(true);
    expect(m?.redactedSample).not.toContain(WIF_C);
  });
  it('scanArgs: checksum failure not reported', () => {
    expect(scanArgs({ k: WIF_U_BAD })).toBeNull();
  });
  it('scanArgs: wrong version byte (regex-reachable) not reported', () => {
    expect(scanArgs({ k: WIF_VER81 })).toBeNull();
  });
  it('scanText: valid reported with response-text fieldPath, invalid not', () => {
    expect(scanText(WIF_U)?.fieldPath).toBe('response-text');
    expect(scanText(WIF_U_BAD)).toBeNull();
  });
  it('redactText: valid redacted and listed, invalid left intact and not listed', () => {
    const pos = redactText('a ' + WIF_U + ' b');
    expect(pos.result).toContain('[node9-redacted:Bitcoin WIF Private Key]');
    expect(pos.result).not.toContain(WIF_U);
    expect(pos.found).toEqual(['Bitcoin WIF Private Key']);
    const neg = redactText('k=' + WIF_U_BAD);
    expect(neg.result).toBe('k=' + WIF_U_BAD);
    expect(neg.found).toEqual([]);
  });
});

describe('c4 validate fires in all three entrypoints — xprv', () => {
  it('scanArgs / scanText / redactText: private key reported, corrupted and PUBLIC not', () => {
    expect(scanArgs({ k: XPRV })?.patternName).toBe('Extended Private Key');
    expect(scanArgs({ k: XPRV_BAD })).toBeNull();
    expect(scanArgs({ k: XPUB })).toBeNull();
    expect(scanText(XPRV)).not.toBeNull();
    expect(scanText(XPUB)).toBeNull();
    expect(redactText(XPRV).found).toEqual(['Extended Private Key']);
    expect(redactText(XPUB).found).toEqual([]);
  });
  it('keyword prefilter is case-sensitive to the regex: an upper-cased prefix is not reported, pinned', () => {
    expect(scanArgs({ k: 'X' + XPRV.slice(1) })).toBeNull();
  });
});

describe('c5 a passing validator beats the stopword heuristic (F4)', () => {
  it('a real WIF containing a stopword substring is reported by all three', () => {
    expect(scanArgs({ k: WIF_SW })?.patternName).toBe('Bitcoin WIF Private Key');
    expect(scanText(WIF_SW)).not.toBeNull();
    expect(redactText(WIF_SW).found).toEqual(['Bitcoin WIF Private Key']);
  });
});

describe('c6 overlapping search: a failed decoy must not swallow the real key (F3)', () => {
  it('scanArgs reports the real key after a checksum-failing decoy', () => {
    expect(scanArgs({ k: WIF_C_BAD + ' ' + WIF_K1 })?.patternName).toBe('Bitcoin WIF Private Key');
  });
  it('the redacted sample masks the ACCEPTED key, not the decoy', () => {
    const m = scanArgs({ k: WIF_C_BAD + ' ' + WIF_K1 });
    expect(m?.redactedSample.startsWith(WIF_K1.slice(0, 4))).toBe(true);
    expect(m?.redactedSample.startsWith(WIF_C_BAD.slice(0, 4))).toBe(false);
  });
  it('scanText likewise', () => {
    expect(scanText(WIF_C_BAD + ' ' + WIF_K1)).not.toBeNull();
  });
});

describe('anchoring (F2): no match inside a longer base58 blob', () => {
  it('an xprv contains a K/L window that matches the WIF shape; it must not be reported as WIF', () => {
    const m = scanArgs({ k: XPRV_BAD }); // checksum-broken xprv, so xprv itself is not reported either
    expect(m).toBeNull();
  });
  it('a WIF glued to a word character is not reported, pinned', () => {
    expect(scanArgs({ k: 'WIF_' + WIF_U })).toBeNull();
  });
});
