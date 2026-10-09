// S.5 calibration — the needs-chain gate judges the upstream job's `if:` per top-level branch
// (design: scanner-gaps-code-design.md §S.5, 2026-10-09). WRITTEN BEFORE THE IMPLEMENTATION.
//
// upstreamJobGates refused any upstream `if:` that contained `||` anywhere, even inside a
// parenthesised group whose every alternative is gated (eeea2222/systemd-clean, hand-verified
// clean, scored medium). S.2 made jobActorGate judge each top-level `||` branch; the needs chain
// now uses the same predicate, so the two can no longer disagree.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'needs-gate');
const rank = (f: string) => {
  const r = analyzeWorkflow(`.github/workflows/${f}`, fs.readFileSync(path.join(FX, f), 'utf8'));
  return r ? SEVERITY_RANK[r.severity] : -1;
};

describe('S.5 — the needs chain', () => {
  it('an upstream job gated on every branch (the `||` sits inside parens) gates the agent job', () => {
    expect(rank('upstream-gated-with-inner-or.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('an upstream job with an ungated top-level branch does not gate it', () => {
    expect(rank('upstream-open-branch.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });
});
