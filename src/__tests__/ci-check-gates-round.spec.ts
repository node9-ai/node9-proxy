// Gates round (2026-11-22, design: docs roadmap/active/scanner-gates-design.md sections 5-8).
// From a blind hand read of 14 workflows and a sample of 28 more:
//  A. `allowed_non_write_users` that is "*" on some events only (an expression);
//  C. a job `if:` on another repository's name (a copied workflow never runs here);
//  D. an actor check in a step that fails the job before the agent starts;
//  E. the same-repository test in its workflow_run spelling, on every way into the job;
//  B. a gated agent that a maintainer starts on an outsider's item and the outsider steers.
// Shapes only; no repository names.

import { describe, it, expect } from 'vitest';
import { analyzeWorkflow } from '../ci-check/workflows';
import { scanTree } from '../ci-check';
import { SEVERITY_RANK } from '../ci-check/types';
import type { RepoTree } from '../ci-check/types';

const ci2 = (wf: string) => analyzeWorkflow('.github/workflows/w.yml', wf);
const sev = (wf: string) => ci2(wf)?.severity ?? 'none';
const sig = (wf: string) => (ci2(wf)?.signals ?? []).join(' | ');
const rank = (wf: string) => {
  const s = ci2(wf)?.severity;
  return s ? SEVERITY_RANK[s] : -1;
};

// --- A ---
const starWhen = (on: string, value: string) => `
on:
${on}
permissions:
  contents: read
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: ${value}
          prompt: 'Review this pull request: \${{ github.event.pull_request.title }}'
          claude_args: '--allowedTools "Bash"'
`;
const PRT_AND_COMMENT =
  '  pull_request_target:\n    types: [opened, synchronize]\n  issue_comment:\n    types: [created]';
const WHEN_PRT = "${{ github.event_name == 'pull_request_target' && '*' || '' }}";

describe('A: "*" on some events only', () => {
  it('opens the action on the named event a stranger fires', () => {
    expect(rank(starWhen(PRT_AND_COMMENT, WHEN_PRT))).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
    expect(sig(starWhen(PRT_AND_COMMENT, WHEN_PRT))).toMatch(
      /allowed_non_write_users is "\*" on `pull_request_target`/
    );
    expect(sig(starWhen(PRT_AND_COMMENT, WHEN_PRT))).toMatch(/no effective actor gate/);
  });

  it('grades the same as a plain "*" on that event', () => {
    const plain = starWhen('  pull_request_target:\n    types: [opened, synchronize]', '"*"');
    expect(sev(starWhen(PRT_AND_COMMENT, WHEN_PRT))).toBe(sev(plain));
  });

  it("stays closed when the named event is not one of this workflow's triggers", () => {
    const wf = starWhen('  issue_comment:\n    types: [created]', WHEN_PRT);
    expect(sig(wf)).not.toMatch(/any user can trigger|no effective actor gate/);
  });

  it('an expression of another shape is not read as open', () => {
    const wf = starWhen(PRT_AND_COMMENT, '${{ vars.REVIEW_USERS }}');
    expect(sig(wf)).not.toMatch(/any user can trigger|no effective actor gate/);
  });
});

// --- C ---
const guarded = (jobIf: string, extra = '') => `
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
jobs:
  agent:
    if: ${jobIf}
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          prompt: 'Answer: \${{ github.event.comment.body }}'
          claude_args: '--allowedTools "Bash"'
${extra}`;
const tree = (wf: string, owner?: string, repo?: string): RepoTree => ({
  source: owner && repo ? `${owner}/${repo}` : 'fixture',
  ...(owner ? { owner } : {}),
  ...(repo ? { repo } : {}),
  notes: [],
  files: [{ path: '.github/workflows/w.yml', content: wf }],
});
const ci2Of = (t: RepoTree) =>
  scanTree(t).findings.filter((f) => f.rule === 'CI-2.injectable-workflow');

describe("C: a job pinned to another repository's name", () => {
  const IF = "github.repository == 'Upstream/Tool'";

  it('never runs in a copy: no CI-2 finding from it', () => {
    expect(ci2Of(tree(guarded(IF), 'someone', 'tool'))).toEqual([]);
  });

  it('runs in the repository it names (GitHub compares without case)', () => {
    expect(ci2Of(tree(guarded(IF), 'upstream', 'tool')).length).toBe(1);
  });

  it('an unknown repository name changes nothing', () => {
    expect(ci2Of(tree(guarded(IF))).length).toBe(1);
  });

  it('the owner form', () => {
    expect(
      ci2Of(tree(guarded("github.repository_owner == 'upstream'"), 'someone', 'tool'))
    ).toEqual([]);
  });

  it('a way through the if that does not need the name keeps the job', () => {
    const wf = guarded(`${IF} || github.event_name == 'issue_comment'`);
    expect(ci2Of(tree(wf, 'someone', 'tool')).length).toBe(1);
  });

  const dependent = (jobIf: string) =>
    guarded(IF)
      .replace(
        'jobs:\n',
        `jobs:\n  gate:\n    if: ${IF}\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n`
      )
      .replace(
        `  agent:\n    if: ${IF}\n`,
        `  agent:\n    needs: gate\n${jobIf ? `    if: ${jobIf}\n` : ''}`
      );

  it('a job that needs a dropped job is dropped too', () => {
    expect(ci2Of(tree(dependent(''), 'someone', 'tool'))).toEqual([]);
  });

  it('unless it runs after a skipped dependency (always())', () => {
    expect(ci2Of(tree(dependent('always()'), 'someone', 'tool')).length).toBe(1);
  });

  it('the name is not left set for the next scan', () => {
    ci2Of(tree(guarded(IF), 'someone', 'tool'));
    expect(ci2(guarded(IF))).not.toBeNull();
  });
});

// --- D ---
const PERMISSION_CHECK = `PERM=$(gh api "repos/\${{ github.repository }}/collaborators/\${ACTOR}/permission" --jq .permission || echo none)
          case "$PERM" in
            admin|write) ;;
            *) exit 1 ;;
          esac`;
const checked = (
  opts: { on?: string; stepExtra?: string; agentIf?: string; check?: string } = {}
) => `
on:
${opts.on ?? '  issue_comment:\n    types: [created]'}
permissions:
  contents: write
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - name: Verify commenter
${opts.stepExtra ?? ''}        env:
          ACTOR: \${{ github.event.comment.user.login }}
          ASSOC: \${{ github.event.comment.author_association }}
          GH_TOKEN: \${{ github.token }}
        run: |
          ${opts.check ?? PERMISSION_CHECK}
      - uses: anthropics/claude-code-base-action@beta
${opts.agentIf ? `        if: ${opts.agentIf}\n` : ''}        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'Do what this comment asks: \${{ github.event.comment.body }}'
          allowed_tools: Bash
`;

describe('D: an actor check that fails the job before the agent', () => {
  it('a permission check with exit 1 holds the job', () => {
    expect(sev(checked())).toBe('advisory');
    expect(ci2(checked())!.mitigations?.join(' ')).toMatch(/actor-gated/);
  });

  it('the association against the trusted roles, in a case statement', () => {
    const check = `case "$ASSOC" in
            OWNER|MEMBER|COLLABORATOR) ;;
            *) echo "not allowed"; exit 1 ;;
          esac`;
    expect(sev(checked({ check }))).toBe('advisory');
  });

  it('not when its failure is ignored', () => {
    expect(
      rank(checked({ stepExtra: '        continue-on-error: true\n' }))
    ).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('not when the agent runs after a failure', () => {
    expect(rank(checked({ agentIf: 'always()' }))).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('not without a failing exit', () => {
    const check = PERMISSION_CHECK.replace('exit 1', 'echo "no access"');
    expect(rank(checked({ check }))).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('a check pinned to the comment event holds a job whose other trigger needs a maintainer', () => {
    const wf = checked({
      on: '  issue_comment:\n    types: [created]\n  workflow_dispatch:',
      stepExtra: "        if: github.event_name == 'issue_comment'\n",
    });
    expect(sev(wf)).toBe('advisory');
  });

  it('but not one a stranger fires the job on without the check', () => {
    const wf = checked({
      on: '  issue_comment:\n    types: [created]\n  issues:\n    types: [opened]',
      stepExtra: "        if: github.event_name == 'issue_comment'\n",
    });
    expect(rank(wf)).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('not when an earlier step pastes the comment into its script', () => {
    const wf = checked().replace(
      '    steps:\n',
      '    steps:\n      - run: echo "${{ github.event.comment.body }}" > /tmp/c\n'
    );
    expect(rank(wf)).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });
});

// --- E ---
const autofix = (jobIf: string) => `
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  contents: write
  pull-requests: write
jobs:
  fix:
    if: ${jobIf}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.workflow_run.head_sha }}
      - run: npm ci
      - uses: openai/codex-action@v1
        with:
          openai-api-key: \${{ secrets.OPENAI_API_KEY }}
          allow-users: "*"
          sandbox: workspace-write
          prompt: Fix the failing build.
`;

describe('E: the same-repository test on every way into the job', () => {
  it('the workflow_run spelling holds the job', () => {
    const wf = autofix(
      "github.event.workflow_run.conclusion == 'failure' && github.event.workflow_run.head_repository.full_name == github.repository"
    );
    expect(sev(wf)).toMatch(/^(advisory|none)$/);
  });

  it('a way in without the test stays open', () => {
    const wf = autofix(
      "github.event.workflow_run.head_repository.full_name == github.repository || github.event.workflow_run.conclusion == 'failure'"
    );
    expect(rank(wf)).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('`fork == false` is not credited: GitHub reads it as true on events without that payload', () => {
    const wf = guarded('github.event.pull_request.head.repo.fork == false');
    expect(rank(wf)).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });
});

// --- B ---
const gated = (o: {
  on?: string;
  perms?: string;
  prompt?: string | null;
  tools?: string;
  checkout?: string;
  jobIf?: string;
  env?: string;
  token?: string;
}) => `
on:
${o.on ?? '  issue_comment:\n    types: [created]'}
jobs:
  agent:
${o.jobIf ? `    if: ${o.jobIf}\n` : ''}${o.env ? `    environment: ${o.env}\n` : ''}    runs-on: ubuntu-latest
    permissions:
${o.perms ?? '      contents: read\n      issues: write\n      pull-requests: write'}
    steps:
      - uses: actions/checkout@v4
${o.checkout ? `        with:\n          ref: ${o.checkout}\n` : ''}      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
${o.token ? `          github_token: \${{ secrets.${o.token} }}\n` : ''}${o.prompt === null ? '' : `          prompt: '${o.prompt ?? 'Answer the issue: ${{ github.event.issue.body }}'}'\n`}${o.tools ? `          claude_args: '--allowedTools "${o.tools}"'\n` : ''}`;
const CONTENTS_WRITE = '      contents: write\n      issues: write\n      pull-requests: write';

describe('B: a gated agent an outsider steers through a maintainer', () => {
  it('a mention in tag mode with contents: write is high', () => {
    const f = ci2(gated({ prompt: null, perms: CONTENTS_WRITE }))!;
    expect(f.severity).toBe('high');
    expect(f.signals.join(' ')).toMatch(
      /comment command or mention starts the agent.*issue or pull request and its comments/
    );
    expect(f.title).toMatch(/routine action/);
    expect(f.mitigations?.join(' ')).toMatch(/gates the agent to write-access users/);
  });

  it("the outsider's issue body with a shell is high", () => {
    expect(sev(gated({ tools: 'Bash' }))).toBe('high');
  });

  it('with narrow comment tools and a write token it is medium', () => {
    expect(sev(gated({ tools: 'Bash(gh issue comment:*)' }))).toBe('medium');
  });

  it('read-only tools and no write token: unchanged', () => {
    const wf = gated({ tools: 'Read,Grep', perms: '      contents: read' });
    expect(sev(wf)).toMatch(/^(advisory|none)$/);
  });

  it("only the maintainer's own comment in the prompt: unchanged", () => {
    const wf = gated({ prompt: 'Do this: ${{ github.event.comment.body }}', tools: 'Bash' });
    expect(sev(wf)).toBe('advisory');
  });

  it('a label on an outsider pull request with the head checked out and a shell is high', () => {
    const wf = gated({
      on: '  pull_request_target:\n    types: [labeled]',
      checkout: '${{ github.event.pull_request.head.sha }}',
      prompt: 'Review this pull request.',
      tools: 'Bash',
    });
    expect(sev(wf)).toBe('high');
    expect(sig(wf)).toMatch(/label starts the agent.*pull request code/);
  });

  it("a maintainer's push to the branch is not routine: medium", () => {
    const wf = gated({
      on: '  pull_request_target:\n    types: [synchronize]',
      checkout: '${{ github.event.pull_request.head.sha }}',
      prompt: 'Review this pull request.',
      tools: 'Bash',
    });
    expect(sev(wf)).toBe('medium');
    expect(sig(wf)).toMatch(/push to the pull request branch/);
  });

  it('never critical, even with a PAT and a shell', () => {
    expect(sev(gated({ tools: 'Bash', token: 'ADMIN_PAT', perms: CONTENTS_WRITE }))).toBe('high');
  });

  it('plain pull_request (a fork run has a read-only token): unchanged', () => {
    const wf = gated({
      on: '  pull_request:\n    types: [labeled]',
      checkout: '${{ github.event.pull_request.head.sha }}',
      prompt: 'Review this pull request.',
      tools: 'Bash',
    });
    expect(sev(wf)).toMatch(/^(advisory|none)$/);
  });

  it('same-repository pull requests only: unchanged', () => {
    const wf = gated({
      on: '  pull_request_target:\n    types: [labeled]',
      jobIf: 'github.event.pull_request.head.repo.full_name == github.repository',
      checkout: '${{ github.event.pull_request.head.sha }}',
      prompt: 'Review this pull request.',
      tools: 'Bash',
    });
    expect(sev(wf)).toMatch(/^(advisory|none)$/);
  });

  it('a trusted author: unchanged', () => {
    const wf = gated({
      on: '  pull_request_target:\n    types: [labeled]',
      jobIf: "github.event.pull_request.author_association == 'MEMBER'",
      checkout: '${{ github.event.pull_request.head.sha }}',
      prompt: 'Review this pull request.',
      tools: 'Bash',
    });
    expect(sev(wf)).toMatch(/^(advisory|none)$/);
  });

  it('an environment that requires a reviewer: unchanged', () => {
    const wf = gated({ tools: 'Bash', env: 'agent' });
    const f = analyzeWorkflow('.github/workflows/w.yml', wf, undefined, undefined, undefined, {
      protected: new Set(['agent']),
    });
    expect(f?.severity ?? 'none').toMatch(/^(advisory|none)$/);
  });

  it('a re-run of an outsider run is not routine: medium', () => {
    const wf = gated({
      on: '  workflow_run:\n    workflows: [CI]\n    types: [completed]',
      checkout: '${{ github.event.workflow_run.head_sha }}',
      prompt: 'Fix the build.',
      tools: 'Bash',
    });
    expect(sev(wf)).toBe('medium');
  });

  it('the explanation says who starts it and what the outsider controls', () => {
    const f = ci2(gated({ tools: 'Bash' }))!;
    expect(f.explain?.happens).toMatch(/Only people with write access can start the agent, but/);
    expect(f.explain?.happens).toMatch(/a shell/);
    for (const s of [f.explain!.headline, f.explain!.happens, ...f.explain!.fix, f.fix ?? ''])
      expect(s).not.toMatch(/\u2014/);
  });
});

describe('B: the outsider test on a gate job upstream', () => {
  const wf = (agentIf: string) => `
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  gate:
    if: github.event.workflow_run.head_repository.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
  agent:
    needs: gate
${agentIf ? `    if: ${agentIf}\n` : ''}    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.workflow_run.head_sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: Review the branch.
          claude_args: '--allowedTools "Bash"'
`;
  it('a same-repository test on the job it needs keeps B out', () => {
    expect(sev(wf(''))).toMatch(/^(advisory|none)$/);
  });
  it('not when the agent job runs after a skipped gate (always())', () => {
    expect(sig(wf('always()'))).toMatch(/re-run starts the agent/);
  });
});

describe('review fixes', () => {
  it('D: a permission lookup that exits only on an API error is not a gate', () => {
    const check =
      'PERM=$(gh api "repos/o/r/collaborators/${ACTOR}/permission" --jq .permission) || exit 1\n          echo "perm=$PERM" >> "$GITHUB_OUTPUT"';
    expect(rank(checked({ check }))).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('C: a pin on another name under the same owner is read as a rename, not a copy', () => {
    expect(
      ci2Of(tree(guarded("github.repository == 'upstream/new-name'"), 'upstream', 'old-name'))
        .length
    ).toBe(1);
  });

  it('C: a pin on the same name under another owner is a copy', () => {
    expect(ci2Of(tree(guarded("github.repository == 'upstream/tool'"), 'someone', 'tool'))).toEqual(
      []
    );
  });

  it('B: a PAT with only read tools is not write reach', () => {
    const wf = gated({
      on: '  issues:\n    types: [labeled]',
      tools: 'Read,Grep',
      token: 'BOT_PAT',
      perms: '      contents: read',
    });
    expect(sev(wf)).toMatch(/^(advisory|none)$/);
  });

  it('A: CI-4 reads the same open door as CI-2', () => {
    const wf = starWhen(PRT_AND_COMMENT, WHEN_PRT).replace(
      '          prompt:',
      '          env:\n            AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n          prompt:'
    );
    const plain = starWhen(
      '  pull_request_target:\n    types: [opened, synchronize]',
      '"*"'
    ).replace(
      '          prompt:',
      '          env:\n            AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n          prompt:'
    );
    const ci4 = (w: string) =>
      scanTree(tree(w)).findings.find((f) => f.rule.startsWith('CI-4'))?.severity ?? 'none';
    expect(ci4(plain)).not.toBe('none');
    expect(ci4(wf)).toBe(ci4(plain));
  });
});

describe('a local wrapper around the agent action', () => {
  const wf = (uses: string) => `
on:
  pull_request_target:
    types: [labeled]
permissions:
  contents: write
jobs:
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: ${uses}
        with:
          oauth_token: \${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          claude_args: --permission-mode bypassPermissions
          prompt: Resolve the merge conflicts.
`;
  it('is an agent step when its path names the agent and it takes a prompt', () => {
    expect(sev(wf('./.github/actions/claude-with-retry'))).toBe('high');
  });
  it('a local action that names no agent is not', () => {
    expect(ci2(wf('./.github/actions/merge-helper'))).toBeNull();
  });
});
