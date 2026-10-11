// T.2a — agents run as a command in a `run:` step (2026-10-11). WRITTEN BEFORE THE
// IMPLEMENTATION. The run-step heuristic needed an agent word AND `github.event` in the run
// text; event text passed through `env:` (step or job), an unrecognised CLI, a tool grant in
// a JSON env value, and a "skip permissions" flag were all invisible.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'run-agents');
const ci2 = (f: string) =>
  analyzeWorkflow(`.github/workflows/${f}`, fs.readFileSync(path.join(FX, f), 'utf8'));
const rank = (f: string) => {
  const r = ci2(f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};
const signals = (f: string) => (ci2(f)?.signals ?? []).join(' ');

describe('T.2a — run-step agents are recognised', () => {
  it('`claude -p` fed through the step env, permissions skipped: high', () => {
    expect(rank('claude-print-env.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
    expect(signals('claude-print-env.yml')).toMatch(/broad\/write-capable tools/);
  });

  it('`opencode run` with a JSON grant allowing any `gh issue` command: medium', () => {
    expect(rank('opencode-permission-json.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('an agent SDK script with the PR text in the job env, on pull_request_target: medium or more', () => {
    expect(rank('sdk-script-job-env.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('`--permission-mode bypassPermissions` in claude_args is a broad grant', () => {
    expect(signals('action-skip-permissions.yml')).toMatch(/broad\/write-capable tools/);
  });
});

describe('T.2a — what stays as it is', () => {
  it('installing the CLI and printing its version is not an agent run', () => {
    expect(ci2('install-only.yml')).toBeNull();
  });

  it('the CLI on workflow_dispatch only: no alert', () => {
    expect(rank('opencode-dispatch-only.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('an agent name next to issue text in a plain shell step: no alert', () => {
    expect(rank('agent-word-not-a-run.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('a label on a newly opened issue is a gate (only triage can label): advisory at most', () => {
    expect(rank('issue-label-gate.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('the CLI behind a write-role gate: advisory at most', () => {
    expect(rank('claude-print-gated.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });
});
