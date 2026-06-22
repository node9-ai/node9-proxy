// Regression: the Isolation finding's fix points at `node9 sandbox run` (the
// posture loop — the report's remediation is now a real node9 command).

import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'fs';
import { checkContainment, ISOLATION_WEIGHT } from '../containment';
import type { CheckContext } from '../types';

const ctx = {} as CheckContext;

describe('checkContainment', () => {
  afterEach(() => vi.restoreAllMocks());

  it('leads the Isolation fix with `node9 sandbox run` when on the bare host', () => {
    // Force "not in a container".
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    vi.spyOn(fs, 'readFileSync').mockReturnValue('0::/\n' as unknown as string);

    const findings = checkContainment(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('Isolation');
    expect(findings[0].fix).toContain('node9 sandbox run');
    // still keeps the without-a-container mitigations
    expect(findings[0].fix).toContain('project-jail');
  });

  it('scores as hardening headroom — weight + gain/cost, and stays OPEN (no cantFix probe)', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    vi.spyOn(fs, 'readFileSync').mockReturnValue('0::/\n' as unknown as string);

    const f = checkContainment(ctx)[0];
    // Deducts the isolation weight while open (the "100-with-issues" fix).
    expect(f.scoreWeight).toBe(ISOLATION_WEIGHT);
    expect(f.gain).toBeTruthy();
    expect(f.cost).toBeTruthy();
    // Must NOT be can't-fix — node9 now fully remedies this, so it has to remain
    // an OPEN, scored finding (a cantFix probe would zero its weight).
    expect(f.coverageProbe).toBeUndefined();
  });

  it('returns no Isolation finding when already inside a container', () => {
    vi.spyOn(fs, 'existsSync').mockImplementation((p) => p === '/.dockerenv');
    expect(checkContainment(ctx)).toEqual([]);
  });
});
