// T.6 — gate and input semantics (design: scanner-gaps-code-design.md §T.6, 2026-10-10).
// WRITTEN BEFORE THE IMPLEMENTATION. Fixtures are real workflows from the hand-reviewed
// clones (named in each test) plus reduced shapes where one rule has to be isolated.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'gate-semantics');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');
const ci2 = (f: string) => analyzeWorkflow(`.github/workflows/${f}`, read(f));
const rank = (f: string) => {
  const r = ci2(f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};
const mitigations = (f: string) => (ci2(f)?.mitigations ?? []).join(' ');

describe('T.6.1 — a sibling step `if:` does not gate the agent step', () => {
  it('assistant-ui template: the internal step is same-repo gated, the fork step is not (keen0429, hand: high)', () => {
    expect(rank('step-if-sibling.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(mitigations('step-if-sibling.yml')).not.toMatch(/actor-gated/i);
  });
});

describe('T.6.2 — `${{ env.X }}` in the agent step is resolved before the prompt and tool checks', () => {
  it('scores the same as the workflow with the values written inline', () => {
    expect(rank('env-indirection-plain.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(rank('env-indirection.yml')).toBe(rank('env-indirection-plain.yml'));
  });
});

describe('T.6.2 — what resolving `${{ env.X }}` must not change', () => {
  it('a resolved file path `.git/review-policy.diff` is not a `/review` command (block/proto-fleet, hand: clean)', () => {
    expect(rank('env-path-not-review-command.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it("a head ref resolved to `${{ inputs['head-sha'] }}` is still a head checkout (block/proto-fleet template)", () => {
    const f = ci2('env-bracket-head-input.yml');
    expect((f?.signals ?? []).join(' ')).toMatch(/checks out the untrusted PR head/i);
  });
});

describe('T.6.3 — action inputs are case-insensitive', () => {
  it('`GITHUB_TOKEN:` under `with:` arms the "*" bypass (mdn/fred, hand: medium)', () => {
    expect(rank('with-key-case.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(mitigations('with-key-case.yml')).not.toMatch(/keeps its default write gate/i);
  });

  it('"*" with no token in any spelling keeps the gate (HAOCHENYE/ghstack-play, hand: clean CI)', () => {
    expect(rank('star-without-token.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });
});

describe('T.6.4 — an association set that admits a non-write role is not a gate', () => {
  it('CONTRIBUTOR in the set: the job is open', () => {
    expect(rank('association-set-contributor.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('OWNER/MEMBER/COLLABORATOR only: still gated', () => {
    expect(rank('association-set-trusted.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });
});

describe('T.6.5 — allowed_non_write_users bound to the triggering actor acts as "*"', () => {
  it('`${{ github.event.issue.user.login }}` with github_token (ordinary7Zz/my_nnUNet, hand: medium)', () => {
    expect(rank('nonwrite-actor-login.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(mitigations('nonwrite-actor-login.yml')).not.toMatch(/scoped to a list/i);
  });

  it('CONTRIBUTOR set plus the PR author login (frankbria/ralph-claude-code, hand: medium)', () => {
    expect(rank('contributor-and-actor-login.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });
});

describe('T.6.8 — a job that can never run is not scored', () => {
  it('`if: false`', () => {
    expect(ci2('job-if-false.yml')).toBeNull();
  });

  it('`<expr> && false`', () => {
    expect(ci2('job-if-and-false.yml')).toBeNull();
  });
});
