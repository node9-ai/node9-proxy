// S.2 — a gate on one `||` branch must not cover the whole job
// (design: scanner-gaps-code-design.md §S.2, 2026-10-09). WRITTEN BEFORE THE IMPLEMENTATION.
//
// jobActorGate joined the job `if:` into one string and looked for a gate anywhere in it, so
// `(issues opened) || (comment && login == 'owner')` counted as gated by the second branch while
// the first let any issue opener reach the agent (derstrassi/karoofirefly, hand-verified).
// Now every top-level `||` branch of the job `if:` must be gated, or pinned to a trusted event.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'gate-branches');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');
const ci2 = (f: string) => analyzeWorkflow(`.github/workflows/${f}`, read(f));
const rank = (f: string) => {
  const r = ci2(f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};

describe('S.2 — an ungated `||` branch opens the job', () => {
  it('issues:opened branch ungated, comment branch pinned to a login: at least medium', () => {
    const f = ci2('open-issue-branch.yml');
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect((f!.mitigations ?? []).join(' ')).not.toMatch(/actor-gated/i);
  });
});

describe('S.2 — what stays gated', () => {
  it('every branch carries its own association gate (nested fromJSON parens): advisory at most', () => {
    expect(rank('every-branch-gated.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('the only ungated branch is workflow_dispatch: advisory at most', () => {
    expect(rank('gated-or-dispatch.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('a `||` inside a string literal does not split the expression: advisory at most', () => {
    expect(rank('or-inside-string.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });
});
