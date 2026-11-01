// Regression guard for the PROTECTIVE_SHIELDS / SHIELDS key drift
// class of bug, documented in doc/roadmap/monitor-phase-2-honest-scoring.md
// Phase 0: a typo'd discount key (`filesystem-jail` vs `filesystem`) caused
// the monitor's RISK score to silently ignore toggling that shield. The typo
// was fixed on 2026-05-12 (see protection.ts:91). This test ensures any
// future entry added to PROTECTIVE_SHIELDS must reference a real
// shield in SHIELDS.

import { describe, expect, it } from 'vitest';
import { PROTECTIVE_SHIELDS } from '../protection';
import { SHIELDS } from '../shields';

function findUnknownShieldKeys(
  names: Iterable<string>,
  shields: Record<string, unknown>
): string[] {
  return [...names].filter((k) => !(k in shields));
}

describe('PROTECTIVE_SHIELDS shield-key sanity', () => {
  it('every name references a real shield in SHIELDS', () => {
    expect(findUnknownShieldKeys(PROTECTIVE_SHIELDS, SHIELDS)).toEqual([]);
  });

  it('catches the filesystem-jail typo class (regression guard)', () => {
    const fake = new Set(['filesystem-jail', ...PROTECTIVE_SHIELDS]);
    expect(findUnknownShieldKeys(fake, SHIELDS)).toEqual(['filesystem-jail']);
  });
});
