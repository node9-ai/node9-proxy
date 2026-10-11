// T.4 — content that reaches the agent through an earlier step (2026-10-11). WRITTEN BEFORE THE
// IMPLEMENTATION. A workflow_run handler that downloads the triggering run's artifacts holds
// content a fork PR produced; a prompt passed as `steps.<id>.outputs.*` carries whatever that
// earlier step put in it. Neither reached `promptTakesUntrusted`, which reads `with.prompt` text.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'workflow-run');
const ci2 = (f: string) =>
  analyzeWorkflow(`.github/workflows/${f}`, fs.readFileSync(path.join(FX, f), 'utf8'));
const rank = (f: string) => {
  const r = ci2(f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};
const signals = (f: string) => (ci2(f)?.signals ?? []).join(' ');

describe('T.4 — reach through artifacts and step outputs', () => {
  it("a prompt built from the triggering run's artifacts: medium or more", () => {
    expect(rank('artifact-prompt.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('artifact-prompt.yml')).toMatch(/artifacts of the triggering run/);
  });

  it('a prompt passed as a step output that holds the comment text: medium or more', () => {
    expect(rank('step-output-from-comment.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it("a checkout of a ref taken from the triggering run's artifact is a head checkout", () => {
    expect(signals('artifact-ref-checkout.yml')).toMatch(/checks out the untrusted PR head/);
  });
});

describe('T.4 — what stays as it is', () => {
  it('a workflow_run handler that reads only the conclusion: advisory at most', () => {
    expect(rank('conclusion-only.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('a step output that carries only the issue number is not payload text', () => {
    expect(signals('step-output-number.yml')).not.toMatch(/feeds untrusted PR\/issue text/);
  });
});
