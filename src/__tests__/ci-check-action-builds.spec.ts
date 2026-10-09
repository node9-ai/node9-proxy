// S.4a + S.4b — which builds of claude-code-action check the actor, and on which events
// (design: scanner-gaps-code-design.md §S.4, revised 2026-10-09). WRITTEN BEFORE THE IMPLEMENTATION.
//
// The official action checks the actor's write permission on entity events (issues, comments,
// PRs) in every release, and on `workflow_run` only from v1.0.185 (#1590, 2026-08-04). The scanner
// recognised only `anthropics/claude-code-action` as an agent and credited its write gate on every
// trigger. A third-party build (`<owner>/claude-code-action`) was not an agent at all, so a fork
// running on workflow_run with Bash (facebookincubator/velox, hand-verified) produced no finding.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'action-builds');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');
const ci2 = (f: string) => analyzeWorkflow(`.github/workflows/${f}`, read(f));
const rank = (f: string) => {
  const r = ci2(f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};

describe('S.4a — a third-party build of claude-code-action', () => {
  it('is an agent, and on workflow_run it is not assumed to check the actor: at least medium', () => {
    const f = ci2('fork-workflow-run.yml');
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(f!.signals.join(' ')).toMatch(/third-party build/i);
  });

  it('on an entity event it keeps the write gate, like the official action: advisory at most', () => {
    const f = ci2('fork-issue-comment.yml');
    expect(f).not.toBeNull(); // it IS an agent now
    expect(SEVERITY_RANK[f!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });
});

describe('S.4b — the official action on workflow_run, by release', () => {
  it('@beta predates the workflow_run actor check: at least medium', () => {
    expect(rank('upstream-beta-workflow-run.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('an explicit pin below v1.0.185: at least medium', () => {
    expect(rank('upstream-old-pin-workflow-run.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('@v1 has the check: advisory at most', () => {
    expect(rank('upstream-v1-workflow-run.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('a SHA pin keeps the gate and the finding asks to confirm v1.0.185 or newer', () => {
    const f = ci2('upstream-sha-workflow-run.yml');
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(f!.signals.join(' ')).toMatch(/v1\.0\.185/);
  });
});
