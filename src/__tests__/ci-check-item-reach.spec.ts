// S.1 — untrusted text that reaches the agent through a tool or a prompt file
// (design: scanner-gaps-code-design.md §S.1, 2026-10-09). WRITTEN BEFORE THE IMPLEMENTATION.
//
// CI-2 counted untrusted reach only when `github.event.*.body|title` sat inside the agent
// step's `prompt`. The issue-triage and dedupe templates pass the issue NUMBER (or nothing)
// and let the agent fetch the text itself, or build a prompt file in an earlier step, so a
// workflow any issue opener can drive scored zero and returned no finding at all.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow, analyzeWorkflowSecrets } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'item-reach');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');
const ci2 = (f: string) => analyzeWorkflow(`.github/workflows/${f}`, read(f));
const rank = (f: string) => {
  const r = ci2(f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};

describe('S.1 — the agent fetches the triggering item itself', () => {
  it('the prompt carries only the issue number: a finding, at least medium', () => {
    const f = ci2('base-action-issue-number.yml');
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(f!.signals.join(' ')).toMatch(/itself/i);
  });

  it('the agent reads the issue through GitHub MCP tools: a finding, at least medium', () => {
    const f = ci2('base-action-mcp-read-tools.yml');
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('an earlier step writes the issue body into the prompt file, agent has bare Bash: high', () => {
    const f = ci2('base-action-prompt-file-from-payload.yml');
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('CI-4 sees the same reach: bare Bash + reachable item is exploitable', () => {
    // The prompt-file shape holds only the agent's own key, so CI-4 has nothing extra to
    // report; the point is that it must not crash and must agree there is no extra secret.
    expect(
      analyzeWorkflowSecrets(
        '.github/workflows/base-action-prompt-file-from-payload.yml',
        read('base-action-prompt-file-from-payload.yml')
      )
    ).toBeNull();
  });
});

describe('S.1 — what must not change', () => {
  it('a labeled-only trigger is not stranger-firable: no finding', () => {
    expect(ci2('neg-labeled-only.yml')).toBeNull();
  });

  it('a job gated on a trusted author stays advisory at most', () => {
    expect(rank('neg-gated-get-issue.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('a scheduled sweep has no untrusted trigger: no finding', () => {
    expect(ci2('neg-scheduled-get-issue.yml')).toBeNull();
  });

  it('a reusable template given the issue number stays advisory: the caller decides reach', () => {
    // A/B regression (google-github-actions/run-gemini-cli, hand-verified clean): its gated
    // dispatcher calls these templates, which read the item by number. Item reach applies only
    // to a workflow with its own stranger-firable trigger.
    expect(rank('neg-reusable-item-handle.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('a plain pull_request review (read-only token, no secrets) stays advisory at most', () => {
    expect(rank('neg-pull-request-diff.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });
});
