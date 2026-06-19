// Regression: the Isolation finding's fix points at `node9 sandbox run` (the
// posture loop — the report's remediation is now a real node9 command).

import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'fs';
import { checkContainment } from '../containment';
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

  it('returns no Isolation finding when already inside a container', () => {
    vi.spyOn(fs, 'existsSync').mockImplementation((p) => p === '/.dockerenv');
    expect(checkContainment(ctx)).toEqual([]);
  });
});
