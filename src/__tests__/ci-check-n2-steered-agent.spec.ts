// fw#481 N2/P2 (founder, 2026-11-21): a stranger who steers an agent that can write text to
// GitHub with a write credential is high, however narrow the tool list; critical needs a tool
// that reaches code. The shapes come from the 2026-11-21 hand re-read (two passes, 13
// repositories). Each "high" case below was medium on 2.65.9, the PAT case was critical.

import { describe, it, expect } from 'vitest';
import { analyzeWorkflow } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const ci2 = (wf: string) => analyzeWorkflow('w.yml', wf)!;

const issueAgent = (opts: {
  perms: string;
  token?: string;
  tools?: string;
  extra?: string;
  on?: string;
}) => `
on:
${opts.on ?? '  issues:\n    types: [opened]\n  issue_comment:\n    types: [created]'}
jobs:
  agent:
    runs-on: ubuntu-latest
    permissions:
${opts.perms}
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.${opts.token ?? 'GITHUB_TOKEN'} }}
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          allowed_non_write_users: "*"
          prompt: 'Translate this issue: \${{ github.event.issue.body }}'
${opts.tools === undefined ? '' : `          claude_args: '--allowedTools "${opts.tools}"'\n`}${opts.extra ?? ''}`;

const WRITE =
  '      contents: read\n      issues: write\n      pull-requests: write\n      id-token: write';

describe('N2: narrow tools that write to GitHub with a write credential', () => {
  it('translator template: PAT + gh issue tools is high, not critical (P2)', () => {
    const f = ci2(
      issueAgent({
        perms: WRITE,
        token: 'TOKEN_GITHUB_WRITE',
        tools:
          'Bash(gh issue:*),Bash(gh api:repos/*/issues:*),Bash(gh api:repos/*/pulls/comments/*)',
      })
    );
    expect(f.severity).toBe('high');
    expect(f.explain?.saw.join(' ')).toMatch(/personal access token/);
  });

  it('the default token with issues write and a comment tool is high', () => {
    const f = ci2(
      issueAgent({
        perms: '      contents: read\n      issues: write',
        tools: 'Bash(gh issue view:*),Bash(gh issue comment:*)',
      })
    );
    expect(f.severity).toBe('high');
    expect(f.explain?.saw.join(' ')).toMatch(/can comment on or edit issues and pull requests/);
  });

  it("the action's own inline-comment tool counts as writing to GitHub", () => {
    const f = ci2(
      issueAgent({
        perms: WRITE,
        tools: 'mcp__github_inline_comment__create_inline_comment,Bash(gh pr view:*)',
      })
    );
    expect(f.severity).toBe('high');
  });

  it('track_progress with no tool list writes its own comment: high', () => {
    const wf = `
on:
  pull_request_target:
    types: [opened]
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.GITHUB_TOKEN }}
          claude_code_oauth_token: \${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
          allowed_non_write_users: "*"
          track_progress: true
          prompt: 'Review this pull request.'
`;
    expect(ci2(wf).severity).toBe('high');
  });

  it('contents: write behind gh pr comment only is high, not critical', () => {
    const f = ci2(
      issueAgent({
        perms: '      contents: write\n      pull-requests: write\n      issues: write',
        tools: 'Bash(gh pr comment:*),Bash(gh pr diff:*),Bash(gh pr view:*)',
      })
    );
    expect(f.severity).toBe('high');
  });
});

describe('N2 limits: what stays where it was', () => {
  it('a PAT with unrestricted gh api reaches code: critical', () => {
    const f = ci2(issueAgent({ perms: WRITE, token: 'BOT_PAT', tools: 'Bash(gh api:*)' }));
    expect(f.severity).toBe('critical');
  });

  it('a PAT with an unrestricted gh pr grant (it includes gh pr merge) is critical-capable', () => {
    const wf = issueAgent({
      perms: '      contents: read\n      pull-requests: write',
      token: 'GH_TOKEN',
      tools: 'Bash(gh pr:*),Bash(gh issue view:*),Read',
      on: '  pull_request_target:\n    types: [opened]',
    });
    const f = ci2(wf);
    expect(['high', 'critical']).toContain(f.severity);
    expect(f.explain?.saw.join(' ')).toMatch(/personal access token/);
    // The same grant narrowed to comments only is never critical.
    const narrow = ci2(wf.replace('Bash(gh pr:*)', 'Bash(gh pr comment:*)'));
    expect(narrow.severity).toBe('high');
  });

  it('tag mode with contents: write reaches code (it commits): not capped below high', () => {
    const wf = `
on:
  issue_comment:
    types: [created]
jobs:
  claude:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.GITHUB_TOKEN }}
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          allowed_non_write_users: "*"
`;
    expect(['high', 'critical']).toContain(ci2(wf).severity);
  });

  it('a read-only token cannot write the comment: not high', () => {
    const f = ci2(
      issueAgent({
        perms: '      contents: read\n      issues: read',
        tools: 'Bash(gh issue view:*),Bash(gh issue comment:*)',
      })
    );
    expect(['medium', 'advisory']).toContain(f.severity);
  });

  it('contents: write alone cannot comment: a comment tool is not a write channel', () => {
    const f = ci2(
      issueAgent({
        perms: '      contents: write',
        tools: 'Bash(gh issue view:*),Bash(gh issue comment:*)',
      })
    );
    expect(['medium', 'advisory']).toContain(f.severity);
  });

  it('no tool that writes anywhere: medium', () => {
    const f = ci2(issueAgent({ perms: WRITE, tools: 'Bash(gh issue view:*),Read' }));
    expect(f.severity).toBe('medium');
  });

  it('a triage bot that can rewrite any issue (update_issue, gh issue edit) is high', () => {
    const perms = '      contents: read\n      issues: write';
    for (const tools of [
      'mcp__github__get_issue,mcp__github__update_issue',
      'Bash(gh label list),Bash(gh issue edit:*)',
    ])
      expect(ci2(issueAgent({ perms, tools })).severity).toBe('high');
  });

  it('a grant that only sets labels stays medium', () => {
    const perms = '      contents: read\n      issues: write';
    for (const tools of [
      'Bash(gh label list),Bash(gh issue edit 12 --add-label:*),Bash(gh issue edit 12 --remove-label:*)',
      'Bash(gh issue edit * --add-label *)',
      'Bash(gh api repos/acme/app/issues/12/labels -f:*)',
      'mcp__github__get_issue,mcp__github__add_labels_to_issue',
    ])
      expect(ci2(issueAgent({ perms, tools })).severity).toBe('medium');
  });

  it('a label grant that also pins --body or --title writes text: high', () => {
    for (const tools of [
      'Bash(gh issue edit * --body * --add-label *)',
      'Bash(gh issue edit 12 --title * --remove-label:*)',
    ]) {
      const f = ci2(issueAgent({ perms: '      contents: read\n      issues: write', tools }));
      expect(f.severity).toBe('high');
    }
  });

  it('a label grant next to a comment grant is still a write channel: high', () => {
    const f = ci2(
      issueAgent({
        perms: '      contents: read\n      issues: write',
        tools: 'Bash(gh issue edit 12 --add-label:*),Bash(gh issue comment:*)',
      })
    );
    expect(f.severity).toBe('high');
  });

  it("the action's default gate (no allowed_non_write_users): not N2's high", () => {
    const wf = issueAgent({ perms: WRITE, tools: 'Bash(gh issue comment:*)' }).replace(
      '          allowed_non_write_users: "*"\n',
      ''
    );
    // Gated: N2 does not apply. Gates round B grades a maintainer's comment that hands the
    // outsider's issue to a commenting agent: medium at most.
    const f = analyzeWorkflow('w.yml', wf);
    expect(SEVERITY_RANK[f?.severity ?? 'advisory']).toBeLessThanOrEqual(SEVERITY_RANK.medium);
    expect((f?.signals ?? []).join(' ')).not.toMatch(/no effective actor gate/);
  });

  it('plain pull_request (read-only token for forks): advisory', () => {
    const f = ci2(
      issueAgent({
        perms: WRITE,
        tools: 'Bash(gh pr comment:*)',
        on: '  pull_request:\n    types: [opened]',
      })
    );
    expect(f.severity).toBe('advisory');
  });

  it('a reusable template stays capped at medium', () => {
    const f = ci2(
      issueAgent({
        perms: WRITE,
        tools: 'Bash(gh issue comment:*)',
        on: '  workflow_call:',
      }).replace("prompt: 'Translate this issue: ${{ github.event.issue.body }}'", "prompt: 'Go.'")
    );
    expect(['medium', 'advisory']).toContain(f.severity);
  });
});
