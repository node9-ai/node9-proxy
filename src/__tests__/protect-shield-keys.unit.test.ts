// Regression guard for the PROTECTIVE_SHIELD_DISCOUNTS / SHIELDS key drift
// class of bug, documented in doc/roadmap/monitor-phase-2-honest-scoring.md
// Phase 0: a typo'd discount key (`filesystem-jail` vs `filesystem`) caused
// the monitor's RISK score to silently ignore toggling that shield. The typo
// was fixed on 2026-05-12 (see protection.ts:91). This test ensures any
// future entry added to PROTECTIVE_SHIELD_DISCOUNTS must reference a real
// shield in SHIELDS.

import { describe, expect, it } from 'vitest';
import { PROTECTIVE_SHIELD_DISCOUNTS } from '../protection';
import { SHIELDS } from '../shields';

function findUnknownShieldKeys(
  discounts: Record<string, number>,
  shields: Record<string, unknown>
): string[] {
  return Object.keys(discounts).filter((k) => !(k in shields));
}

describe('PROTECTIVE_SHIELD_DISCOUNTS shield-key sanity', () => {
  it('every key references a real shield in SHIELDS', () => {
    expect(findUnknownShieldKeys(PROTECTIVE_SHIELD_DISCOUNTS, SHIELDS)).toEqual([]);
  });

  it('catches the filesystem-jail typo class (regression guard)', () => {
    const fake = { 'filesystem-jail': 0.3, ...PROTECTIVE_SHIELD_DISCOUNTS };
    expect(findUnknownShieldKeys(fake, SHIELDS)).toEqual(['filesystem-jail']);
  });
});
