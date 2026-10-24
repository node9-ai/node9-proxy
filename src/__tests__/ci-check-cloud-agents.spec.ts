// Gap 2 and gap 3 (2026-10-24). WRITTEN BEFORE THE IMPLEMENTATION.
// Gap 2: a run-step CLI was an agent only with event context or a model key in its env. A CLI
// that reaches its model through Bedrock or Vertex holds neither.
// Gap 3: pr-agent takes no prompt input and reads its model key from names no other agent uses,
// so it was not seen as an agent at all.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow, analyzeWorkflowSecrets } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check');
const read = (dir: string, f: string) => fs.readFileSync(path.join(FX, dir, f), 'utf8');
const ci2 = (dir: string, f: string) => analyzeWorkflow(`.github/workflows/${f}`, read(dir, f));
const rank = (dir: string, f: string) => {
  const r = ci2(dir, f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};

describe('gap 2: a CLI signed in through a cloud provider is an agent', () => {
  it('`CLAUDE_CODE_USE_BEDROCK` over the PR head on pull_request_target: medium or more', () => {
    expect(rank('cloud-agents', 'bedrock-env-head-checkout.yml')).toBeGreaterThanOrEqual(
      SEVERITY_RANK.medium
    );
  });

  it('a cloud sign-in step before the CLI, permissions skipped: high or more', () => {
    expect(rank('cloud-agents', 'cloud-auth-step-before-cli.yml')).toBeGreaterThanOrEqual(
      SEVERITY_RANK.high
    );
  });
});

describe('gap 2: what stays as it is', () => {
  it('a cloud sign-in after the CLI step does not make it an agent', () => {
    expect(ci2('cloud-agents', 'cloud-auth-step-after-cli.yml')).toBeNull();
  });

  it('the Bedrock switch set to off is no credential', () => {
    expect(ci2('cloud-agents', 'bedrock-env-off.yml')).toBeNull();
  });

  it('printing the version with Bedrock on is not an agent run', () => {
    expect(ci2('cloud-agents', 'bedrock-version-only.yml')).toBeNull();
  });
});

describe('gap 3: pr-agent is an agent', () => {
  it('a fork of it on pull_request_target and comments, no gate: medium', () => {
    const r = ci2('pr-agent', 'fork-on-target-and-comment.yml');
    expect(r?.severity).toBe('medium');
    expect(r?.signals.join(' ')).toMatch(/no effective actor gate/);
  });

  it('its model key is its fuel, not an extra secret', () => {
    const f = 'fork-on-target-and-comment.yml';
    expect(analyzeWorkflowSecrets(`.github/workflows/${f}`, read('pr-agent', f))).toBeNull();
  });

  it('the container image form on comments: medium', () => {
    expect(ci2('pr-agent', 'image-on-comment.yml')?.severity).toBe('medium');
  });
});

describe('gap 3: what stays as it is', () => {
  it('on plain pull_request: advisory at most', () => {
    expect(rank('pr-agent', 'on-pull-request.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('an action whose name only starts with pr-agent is not an agent', () => {
    expect(ci2('pr-agent', 'similar-name.yml')).toBeNull();
  });
});
