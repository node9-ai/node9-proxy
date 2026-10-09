// Second pre-release review (2026-10-09), findings on 60cbe2e. WRITTEN BEFORE THE FIXES.
//  1. a `pull_request.labels` check was credited as a gate when negated or compared to false
//     (an opt-out label such as `skip-ai` lets every PR in);
//  2. `-v` / `-h` were "informational" for every command (curl -v is verbose, ssh -h a host);
//  3. a trusted-event pin inside a string literal counted;
//  6. the joined step `if:`s were matched with no length cap (quadratic, minutes per file).

import { describe, it, expect } from 'vitest';
import { analyzeWorkflow } from '../ci-check/workflows';
import { gradeBroadGrant } from '../ci-check/agent-config';
import { SEVERITY_RANK } from '../ci-check/types';

/** A pull_request_target agent, any user (`*` + token), reading the PR; `jobIf`/`stepIf` vary. */
function prWorkflow(opts: { jobIf?: string; stepIf?: string }): string {
  const ind = (s: string) => JSON.stringify(s);
  return `on:
  pull_request_target:
    types: [opened, synchronize, labeled]
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
${opts.jobIf ? `    if: ${ind(opts.jobIf)}\n` : ''}    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
${opts.stepIf ? `        if: ${ind(opts.stepIf)}\n` : ''}        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          prompt: "Review: \${{ github.event.pull_request.body }}"
`;
}
const rank = (yml: string) => {
  const f = analyzeWorkflow('.github/workflows/x.yml', yml);
  return f ? SEVERITY_RANK[f.severity] : -1;
};
const MEDIUM = SEVERITY_RANK.medium;
const ADVISORY = SEVERITY_RANK.advisory;

describe('1 — an opt-out label is not a gate', () => {
  for (const stepIf of ["!contains(github.event.pull_request.labels.*.name, 'skip-ai')"])
    it(`step if: ${stepIf}`, () => {
      expect(rank(prWorkflow({ stepIf }))).toBeGreaterThanOrEqual(MEDIUM);
    });
  for (const jobIf of [
    "contains(github.event.pull_request.labels.*.name, 'skip-ai') == false",
    'github.event.pull_request.labels[0] == null',
    "toJSON(github.event.pull_request.labels) == '[]'",
  ])
    it(`job if: ${jobIf}`, () => {
      expect(rank(prWorkflow({ jobIf }))).toBeGreaterThanOrEqual(MEDIUM);
    });
  it('an opt-in label (positive contains) still gates', () => {
    expect(
      rank(prWorkflow({ jobIf: "contains(github.event.pull_request.labels.*.name, 'ai-review')" }))
    ).toBeLessThanOrEqual(ADVISORY);
  });
});

describe('2 — only --version / --help are informational', () => {
  for (const g of ['Bash(curl -v:*)', 'Bash(ssh -v:*)', 'Bash(bash -v:*)', 'Bash(docker run -h:*)'])
    it(`${g} is broad`, () => {
      expect(gradeBroadGrant([g], [])?.broad).toEqual([g]);
    });
  it('Bash(node --version:*) is not broad', () => {
    expect(gradeBroadGrant(['Bash(node --version:*)'], [])).toBeNull();
  });
});

describe('3 — a trusted-event pin inside a string literal does not count', () => {
  it('contains(body, \'github.event_name == "push"\')', () => {
    const yml = `on:
  issue_comment:
    types: [created]
jobs:
  a:
    if: contains(github.event.comment.body, 'github.event_name == "push"')
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: \${{ secrets.K }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          prompt: "Answer \${{ github.event.comment.body }}"
`;
    expect(rank(yml)).toBeGreaterThanOrEqual(MEDIUM);
  });
});

describe('6 — long step if: values are not matched in quadratic time', () => {
  it('a 640 KB step if: scans in well under a second', () => {
    const stepIf = 'steps.a.outputs.' + 'permission'.repeat(64_000);
    const t = Date.now();
    analyzeWorkflow('.github/workflows/x.yml', prWorkflow({ stepIf }));
    expect(Date.now() - t).toBeLessThan(1000);
  });
});
