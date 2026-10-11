// T.2b — agents behind a wrapper action (2026-10-11). WRITTEN BEFORE THE IMPLEMENTATION.
// Only a known agent action (claude-code-action, codex, aider, gemini) or a run-step CLI was
// an agent step. A third-party or local action that is handed a model key, or whose path names
// an agent runtime and takes a prompt, runs an agent too, and it carries no implicit actor gate.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'wrapper-agents');
const ci2 = (f: string) =>
  analyzeWorkflow(`.github/workflows/${f}`, fs.readFileSync(path.join(FX, f), 'utf8'));
const rank = (f: string) => {
  const r = ci2(f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};

describe('T.2b — wrapper actions are agents', () => {
  it('a third-party action given a model key, on pull_request_target over the fork head: medium or more', () => {
    expect(rank('third-party-key-input.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('an action whose path names an agent runtime and takes a prompt: medium or more', () => {
    expect(rank('agent-path-with-prompt.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it("`uses: ./` after checking out the fork's head, with a model key: high", () => {
    expect(rank('local-action-fork-head.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });
});

describe('T.2b — what stays as it is', () => {
  it('the local action after a base checkout on pull_request: advisory at most', () => {
    expect(rank('local-action-base-checkout.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('an action from an agent vendor without a model key is not an agent', () => {
    expect(ci2('non-agent-action.yml')).toBeNull();
  });
});
