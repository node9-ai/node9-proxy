import { describe, it, expect } from 'vitest';
import { modeRank, resolveManagedMode } from '../config/managed';

describe('managed mode (baseline+lock)', () => {
  it('ranks modes weakest→strictest', () => {
    expect(modeRank('observe')).toBeLessThan(modeRank('audit'));
    expect(modeRank('audit')).toBeLessThan(modeRank('standard'));
    expect(modeRank('standard')).toBeLessThan(modeRank('strict'));
    expect(modeRank('nonsense')).toBe(-1);
  });

  describe('baseline (unlocked) — cloud is a floor a dev can only tighten', () => {
    it('raises a weaker local mode up to the cloud floor', () => {
      // dev=observe, org=standard → bumped to standard
      expect(resolveManagedMode('observe', 'standard', false)).toBe('standard');
    });
    it('keeps a stricter local mode (a careful dev stays safer)', () => {
      // dev=strict, org=standard → keeps strict (the Ben case)
      expect(resolveManagedMode('strict', 'standard', false)).toBe('strict');
    });
    it('equal local stays put', () => {
      expect(resolveManagedMode('standard', 'standard', false)).toBe('standard');
    });
  });

  describe('locked — cloud wins outright', () => {
    it('forces a stricter local mode down to the locked value', () => {
      // dev=strict, org=standard, LOCKED → forced to standard
      expect(resolveManagedMode('strict', 'standard', true)).toBe('standard');
    });
    it('forces a weaker local mode up to the locked value', () => {
      expect(resolveManagedMode('observe', 'standard', true)).toBe('standard');
    });
  });

  it('ignores an unrankable cloud value (never weakens/breaks enforcement)', () => {
    expect(resolveManagedMode('strict', 'garbage', false)).toBe('strict');
    expect(resolveManagedMode('strict', 'garbage', true)).toBe('strict');
  });
});
