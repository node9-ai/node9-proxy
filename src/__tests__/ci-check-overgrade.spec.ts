// fw#481 S1 to S4 (2026-11-18): the cases where scan-repo graded HIGHER than the real reach.
// Each test fails on the code before the change. Fixtures are short synthetic files.
//
//   S1  committed contributor-side config tops out at medium (covered where those rules are
//       tested; here: CI-5 still sees the loss of a guardrail at one severity)
//   S2  agent, Codex, MCP and task config under a test, fixture or example tree is listed, not counted
//   S3  critical needs reach that outlives the job (a: id-token alone, b: a shell with only a
//       model key and a comment token)
//   S4  a: a gate on a job the agent job needs   b: an open step's verdict joined with a held
//       step's tools   c: CI-4 and CI-2 read the same gate

import { describe, it, expect } from 'vitest';
import { scanTree } from '../ci-check';
import { diffScans } from '../ci-check/diff';
import { analyzeWorkflow, analyzeWorkflowSecrets } from '../ci-check/workflows';
import { lineOfNth } from '../ci-check/lines';
import { renderScanMarkdown } from '../ci-check/render';
import type { RepoTree } from '../ci-check/types';

const tree = (files: Record<string, string>): RepoTree => ({
  source: 'fixture',
  files: Object.entries(files).map(([p, content]) => ({ path: p, content })),
  notes: [],
});
const BROAD = JSON.stringify({ permissions: { allow: ['Bash(*)'] } });
const BACKED = JSON.stringify({ permissions: { allow: ['Bash(*)'], deny: ['Bash(rm:*)'] } });
const CODEX_FULL = 'sandbox_mode = "danger-full-access"\n';
const MCP_UNPINNED = JSON.stringify({
  mcpServers: { docs: { command: 'npx', args: ['-y', '@acme/docs-mcp'] } },
});

describe('S1: one severity, two forms', () => {
  it('losing the deny backstop is still guardrail erosion, at medium', () => {
    const base = scanTree(tree({ '.claude/settings.json': BACKED }));
    const head = scanTree(tree({ '.claude/settings.json': BROAD }));
    expect(base.worst).toBe('medium');
    expect(head.worst).toBe('medium');
    const d = diffScans(base, head);
    expect(d.escalated).toHaveLength(1);
    expect(d.worstIntroduced).toBe('medium');
    expect(renderScanMarkdown(head, d)).toMatch(
      /removes a guardrail from it \(still \*\*medium\*\*\)/
    );
  });

  it('gaining a deny backstop is not an escalation', () => {
    const base = scanTree(tree({ '.claude/settings.json': BROAD }));
    const head = scanTree(tree({ '.claude/settings.json': BACKED }));
    const d = diffScans(base, head);
    expect(d.escalated).toHaveLength(0);
    expect(d.worstIntroduced).toBeNull();
  });

  it('a Codex sandbox widened to full access is erosion too', () => {
    const base = scanTree(tree({ '.codex/config.toml': 'approval_policy = "never"\n' }));
    const head = scanTree(
      tree({ '.codex/config.toml': 'approval_policy = "never"\n' + CODEX_FULL })
    );
    expect(head.worst).toBe('medium');
    expect(diffScans(base, head).escalated).toHaveLength(1);
  });
});

describe('S2: config under a test, fixture or example tree', () => {
  const rules = (res: ReturnType<typeof scanTree>) =>
    res.findings.map((f) => `${f.rule}:${f.tier}`).sort();

  it('agent settings in a fixture tree are listed for review and do not set the result', () => {
    const res = scanTree(tree({ 'tests/fixtures/broad/.claude/settings.json': BROAD }));
    const f = res.findings.find((x) => x.rule === 'CI-1.broad-allow')!;
    expect(f.tier).toBe('review');
    expect(f.fixtureTree).toBe(true);
    expect(f.signals.join(' ')).toMatch(/test, fixture or example folder/);
    expect(res.worst).toBeNull();
  });

  it('the same settings at the repository root still count', () => {
    const res = scanTree(tree({ '.claude/settings.json': BROAD }));
    expect(res.findings.find((x) => x.rule === 'CI-1.broad-allow')!.tier).toBe('alert');
    expect(res.worst).toBe('medium');
  });

  it('settings in a package folder that is not a test tree still count', () => {
    const res = scanTree(tree({ 'packages/app/.claude/settings.json': BROAD }));
    expect(res.worst).toBe('medium');
    expect(res.findings[0].fixtureTree).toBeUndefined();
  });

  it('Codex and MCP config in fixture and example trees are listed too', () => {
    const res = scanTree(
      tree({
        'tests/fixtures/codex-invalid/.codex/config.toml': CODEX_FULL,
        'examples/app/.mcp.json': MCP_UNPINNED,
      })
    );
    expect(res.worst).toBeNull();
    expect(rules(res)).toEqual(
      expect.arrayContaining(['CI-1.codex-unsafe-defaults:review', 'CI-3.mcp-unpinned:review'])
    );
    expect(res.findings.every((f) => f.fixtureTree)).toBe(true);
  });

  it('a fixture next to a real config does not hide the real one', () => {
    const res = scanTree(
      tree({
        '.claude/settings.json': BROAD,
        'tests/fixtures/broad/.claude/settings.json': BROAD,
      })
    );
    expect(res.worst).toBe('medium');
    expect(res.findings.filter((f) => f.tier === 'alert')).toHaveLength(1);
  });

  it('a credential in a fixture allow rule is still an alert', () => {
    const password = ['Zq8v', 'L2pX', '9mQ4', 'rT7w', 'B1n'].join('');
    const settings = JSON.stringify({
      permissions: { allow: [`Bash(psql postgres://app:${password}@db.internal:5432/app)`] },
    });
    const res = scanTree(tree({ 'tests/fixtures/db/.claude/settings.json': settings }));
    const cred = res.findings.find((f) => f.rule === 'CI-1.allow-rule-credential');
    expect(cred?.tier).toBe('alert');
    expect(res.worst).not.toBeNull();
  });

  it('the review list asks the question that fits a fixture config', () => {
    const res = scanTree(tree({ 'tests/fixtures/broad/.claude/settings.json': BROAD }));
    expect(renderScanMarkdown(res)).toMatch(/Does anyone open that folder as a project\?/);
  });
});

// One agent step on outsider text, switched open, with a shell.
const openAgent = (o: {
  perms: string;
  tools?: string;
  token?: string;
  pre?: string;
  env?: string;
}) => `
on:
  pull_request_target:
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
${o.perms}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
${o.pre ?? ''}
      - uses: anthropics/claude-code-action@v1
        env:
          KEEP: "1"
${o.env ?? ''}
        with:
          allowed_non_write_users: "*"
          github_token: \${{ secrets.${o.token ?? 'GITHUB_TOKEN'} }}
          prompt: 'review github.event.pull_request.body'
          claude_args: '--allowedTools "${o.tools ?? 'Bash'}"'
`;
const COMMENT_ONLY = '      contents: read\n      pull-requests: write';
const AWS_LOGIN = `      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ci`;

describe('S3-b: CI-2 critical needs lasting reach', () => {
  const sev = (o: Parameters<typeof openAgent>[0]) =>
    analyzeWorkflow('w.yml', openAgent(o))!.severity;

  it('a shell with only a comment token is high', () => {
    expect(sev({ perms: COMMENT_ONLY })).toBe('high');
  });
  it('a shell with contents: write stays critical', () => {
    expect(sev({ perms: '      contents: write\n      pull-requests: write' })).toBe('critical');
  });
  it('a PAT stays critical', () => {
    expect(sev({ perms: COMMENT_ONLY, token: 'BOT_PAT' })).toBe('critical');
  });
  it('a cloud login step in the job stays critical', () => {
    expect(sev({ perms: COMMENT_ONLY + '\n      id-token: write', pre: AWS_LOGIN })).toBe(
      'critical'
    );
  });
  it('a publish token in the agent environment stays critical', () => {
    expect(sev({ perms: COMMENT_ONLY, env: '          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}' })).toBe(
      'critical'
    );
  });
  it('write-all stays critical', () => {
    const wf = openAgent({ perms: COMMENT_ONLY }).replace(
      /    permissions:\n {6}contents: read\n {6}pull-requests: write/,
      '    permissions: write-all'
    );
    expect(analyzeWorkflow('w.yml', wf)!.severity).toBe('critical');
  });
});

describe('S3-a: id-token alone is not a cloud secret', () => {
  const sev = (o: Parameters<typeof openAgent>[0]) =>
    analyzeWorkflowSecrets('w.yml', openAgent(o))!.severity;
  const OIDC = COMMENT_ONLY + '\n      id-token: write';

  it('id-token: write with a shell and no cloud login is high', () => {
    const f = analyzeWorkflowSecrets('w.yml', openAgent({ perms: OIDC }))!;
    expect(f.severity).toBe('high');
    expect(f.signals.join(' ')).toMatch(/id-token/);
  });
  it('with a cloud login step in the job it is critical', () => {
    expect(sev({ perms: OIDC, pre: AWS_LOGIN })).toBe('critical');
  });
  it('a static cloud secret is critical with or without id-token', () => {
    expect(
      sev({
        perms: COMMENT_ONLY,
        env: '          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
      })
    ).toBe('critical');
  });
});

// The agent job runs only through `plan`, whose `if:` holds the comment command to members.
const planned = (o: { planIf: string; agentIf?: string; needs?: boolean }) => `
on:
  schedule:
    - cron: "0 6 * * 1"
  issue_comment:
    types: [created]
jobs:
  plan:
    if: ${o.planIf}
    runs-on: ubuntu-latest
    steps:
      - run: echo plan
  update:
${o.needs === false ? '' : '    needs: plan\n'}${o.agentIf ? `    if: ${o.agentIf}\n` : ''}    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-base-action@beta
        env:
          DOCS_API_KEY: \${{ secrets.DOCS_API_KEY }}
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'address the comment: \${{ github.event.comment.body }}'
          allowed_tools: "Bash,Edit"
`;
const MEMBERS = `>-
      github.event_name != 'issue_comment' ||
      contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)`;

describe('S4-a and S4-c: a gate on the job the agent job needs', () => {
  it('holds the agent job: CI-2 and CI-4 are both notes', () => {
    const wf = planned({ planIf: MEMBERS });
    expect(analyzeWorkflow('w.yml', wf)!.severity).toBe('advisory');
    const s = analyzeWorkflowSecrets('w.yml', wf)!;
    expect(s.severity).toBe('advisory');
    expect(s.signals.join(' ')).toMatch(/gated/);
  });

  it('carries through two levels of needs', () => {
    const wf = planned({ planIf: MEMBERS }).replace(
      '  update:\n    needs: plan\n',
      '  mid:\n    needs: plan\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo mid\n  update:\n    needs: mid\n'
    );
    expect(wf).toMatch(/needs: mid/);
    expect(analyzeWorkflow('w.yml', wf)!.severity).toBe('advisory');
  });

  it('without the needs edge the agent job is open', () => {
    const wf = planned({ planIf: MEMBERS, needs: false });
    expect(analyzeWorkflow('w.yml', wf)!.severity).not.toBe('advisory');
    expect(analyzeWorkflowSecrets('w.yml', wf)!.severity).toBe('high');
  });

  it('an ungated plan job holds nothing', () => {
    const wf = planned({ planIf: "github.event_name != 'never'" });
    expect(analyzeWorkflow('w.yml', wf)!.severity).not.toBe('advisory');
  });

  it('always() on the agent job runs it even when plan was skipped', () => {
    const wf = planned({ planIf: MEMBERS, agentIf: 'always()' });
    expect(analyzeWorkflow('w.yml', wf)!.severity).not.toBe('advisory');
    expect(analyzeWorkflowSecrets('w.yml', wf)!.severity).toBe('high');
  });

  it('always() that requires the plan result keeps the gate', () => {
    const wf = planned({
      planIf: MEMBERS,
      agentIf: "always() && needs.plan.result == 'success'",
    });
    expect(analyzeWorkflow('w.yml', wf)!.severity).toBe('advisory');
  });

  it('a gate on the agent job itself is read the same way by CI-4', () => {
    const wf = planned({ planIf: 'true', agentIf: MEMBERS, needs: false });
    expect(analyzeWorkflow('w.yml', wf)!.severity).toBe('advisory');
    expect(analyzeWorkflowSecrets('w.yml', wf)!.severity).toBe('advisory');
  });
});

// One job, two steps of the official action: same-repository PRs keep the default write check
// and get the write tools; fork PRs get the check switched off and read-only tools.
const twoSteps = (o: { pre?: string; forkTools?: string; post?: string } = {}) => `
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: write
  pull-requests: write
  id-token: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
${o.pre ?? ''}
      - name: Review (same repository)
        if: steps.ctx.outputs.is_fork != 'true'
        uses: anthropics/claude-code-action@v1
        with:
          claude_args: '--allowedTools "Bash(git commit:*),Bash(git push origin:*),Bash(npm test:*),Read,Edit,Write"'
          prompt: 'Review this pull request and push fixes.'
      - name: Review (fork, read-only)
        if: steps.ctx.outputs.is_fork == 'true'
        uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          claude_args: '--allowedTools "${o.forkTools ?? 'Bash(gh pr comment:*),Bash(gh pr diff:*),Read,Glob,Grep'}"'
          prompt: 'Review the diff with gh pr diff and comment.'
${o.post ?? ''}
`;
const GCP_KEY = (extra = '') => `      - uses: google-github-actions/auth@v3
        with:
          credentials_json: \${{ secrets.GCP_SA_KEY }}
${extra}`;

describe('S4-b: an open step is judged by its own tools', () => {
  it('the held step keeps its write tools out of the finding', () => {
    const f = analyzeWorkflow('w.yml', twoSteps())!;
    const text = f.signals.join(' ');
    expect(text).not.toMatch(/git push|`Edit`|`Write`/);
    expect(f.severity).not.toBe('critical');
  });

  it('the finding is anchored at the open step, not the first one', () => {
    const wf = twoSteps();
    const f = analyzeWorkflow('w.yml', wf)!;
    const lines = wf.split('\n');
    expect(lines[f.line! - 1]).toMatch(/claude-code-action/);
    expect(lines[f.line! - 3]).toMatch(/Review \(fork, read-only\)/);
  });

  it('when the open step itself has the write tools they do count', () => {
    const f = analyzeWorkflow(
      'w.yml',
      twoSteps({ forkTools: 'Bash(git push origin:*),Edit,Read' })
    )!;
    expect(f.signals.join(' ')).toMatch(/git push/);
    expect(f.severity).toBe('critical');
  });

  it('with no secret of its own the fork step raises no CI-4 finding above a note', () => {
    const s = analyzeWorkflowSecrets('w.yml', twoSteps());
    expect(s === null || s.severity === 'advisory').toBe(true);
  });

  it('a single open step is unchanged by the per-step reading', () => {
    const wf = openAgent({ perms: '      contents: write', tools: 'Bash(git push origin:*),Edit' });
    const f = analyzeWorkflow('w.yml', wf)!;
    expect(f.signals.join(' ')).toMatch(/git push/);
  });
});

describe('S4-b: a cloud key file in the workspace', () => {
  it('written before a fork step that can read files: high, no shell needed', () => {
    const s = analyzeWorkflowSecrets('w.yml', twoSteps({ pre: GCP_KEY() }))!;
    expect(s.severity).toBe('high');
    const text = s.signals.join(' ');
    expect(text).toMatch(/GCP_SA_KEY \(key file the cloud login step writes into the workspace\)/);
    expect(text).toMatch(/file-read tool/);
    expect(s.explain?.saw.join(' ')).toMatch(/it can read files/);
  });

  it('create_credentials_file: false leaves no file to read', () => {
    const s = analyzeWorkflowSecrets(
      'w.yml',
      twoSteps({ pre: GCP_KEY('          create_credentials_file: false\n') })
    );
    expect(s === null || s.severity === 'advisory').toBe(true);
  });

  it('a login step after the agent leaves nothing for it', () => {
    const s = analyzeWorkflowSecrets('w.yml', twoSteps({ post: GCP_KEY() }));
    expect(s === null || s.severity === 'advisory').toBe(true);
  });

  it('workload identity (no key) is not a key file', () => {
    const wif = `      - uses: google-github-actions/auth@v3
        with:
          workload_identity_provider: projects/1/locations/global/workloadIdentityPools/p/providers/x
          service_account: ci@example.iam.gserviceaccount.com`;
    const s = analyzeWorkflowSecrets('w.yml', twoSteps({ pre: wif }));
    expect(s === null || !/key file/.test(s.signals.join(' '))).toBe(true);
  });

  it('a fork step with no file-read tool cannot read it', () => {
    const s = analyzeWorkflowSecrets(
      'w.yml',
      twoSteps({ pre: GCP_KEY(), forkTools: 'Bash(gh pr comment:*)' })
    );
    expect(s === null || s.severity === 'advisory').toBe(true);
  });

  it('with a shell the key is a cloud secret: critical', () => {
    const s = analyzeWorkflowSecrets(
      'w.yml',
      twoSteps({ pre: GCP_KEY(), forkTools: 'Bash,Read' })
    )!;
    expect(s.severity).toBe('critical');
  });
});

describe('lineOfNth', () => {
  const text = 'a\nx: 1\nb\nx: 1\nc\nx: 1\n';
  it('finds the n-th occurrence', () => {
    expect(lineOfNth(text, 'x: 1', 0)).toBe(2);
    expect(lineOfNth(text, 'x: 1', 1)).toBe(4);
    expect(lineOfNth(text, 'x: 1', 2)).toBe(6);
  });
  it('falls back to the last one, and to undefined when absent', () => {
    expect(lineOfNth(text, 'x: 1', 9)).toBe(6);
    expect(lineOfNth(text, 'zzz', 0)).toBeUndefined();
    expect(lineOfNth(text, '', 0)).toBeUndefined();
  });
});

describe('S3-a: a PAT by use stays critical whatever it is called', () => {
  it('a token passed as github_token, with a name that does not say PAT', () => {
    const wf = openAgent({
      perms: COMMENT_ONLY + '\n      id-token: write',
      token: 'RELEASE_BOT_KEY_X',
    });
    expect(analyzeWorkflowSecrets('w.yml', wf)!.severity).toBe('critical');
  });
  it('the same token in GH_TOKEN of the agent step', () => {
    const wf = openAgent({
      perms: COMMENT_ONLY,
      env: '          GH_TOKEN: ${{ secrets.MAINTAINER_CRED_X }}',
    });
    expect(analyzeWorkflowSecrets('w.yml', wf)!.severity).toBe('critical');
  });
  it('the default token first in an || chain is not a PAT', () => {
    const wf = openAgent({ perms: COMMENT_ONLY + '\n      id-token: write' }).replace(
      'secrets.GITHUB_TOKEN }}',
      'secrets.GITHUB_TOKEN || secrets.BOT_CRED_X }}'
    );
    expect(analyzeWorkflowSecrets('w.yml', wf)!.severity).toBe('high');
  });
});

describe('S4-b: the anchor when the open agent is a run step', () => {
  const wf = `
on:
  issues:
    types: [opened]
permissions:
  issues: write
jobs:
  held:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: 'triage'
  open:
    runs-on: ubuntu-latest
    steps:
      - env:
          ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}
        run: claude -p "\${{ github.event.issue.body }}" --allowedTools "Bash"
`;
  it('stays on the first agent action, never on the trigger line', () => {
    const f = analyzeWorkflow('w.yml', wf)!;
    expect(f.severity).not.toBe('advisory');
    expect(wf.split('\n')[f.line! - 1]).toMatch(/uses: anthropics\/claude-code-action@v1/);
  });
});

// Found by the code review of this change (2026-11-18).
describe('review: what still counts as lasting reach', () => {
  const ci2 = (o: Parameters<typeof openAgent>[0]) =>
    analyzeWorkflow('w.yml', openAgent(o))!.severity;
  const ci4 = (o: Parameters<typeof openAgent>[0]) =>
    analyzeWorkflowSecrets('w.yml', openAgent(o))?.severity;
  const APP_TOKEN = `      - id: app
        uses: actions/create-github-app-token@v2
        with:
          app-id: \${{ vars.APP_ID }}
          private-key: \${{ secrets.APP_KEY }}`;

  it('CI-2: a PAT in the step env, under a name that does not say token, stays critical', () => {
    expect(
      ci2({ perms: COMMENT_ONLY, env: '          GH_TOKEN: ${{ secrets.MAINTAINER_CRED_X }}' })
    ).toBe('critical');
  });

  it('an App token handed to the agent stays critical in both rules', () => {
    const o = {
      perms: COMMENT_ONLY + '\n      id-token: write',
      pre: APP_TOKEN,
      env: '          GH_TOKEN: ${{ steps.app.outputs.token }}',
    };
    expect(ci2(o)).toBe('critical');
    expect(ci4(o)).toBe('critical');
  });

  it('an App token minted for another step is not handed to the agent', () => {
    const o = { perms: COMMENT_ONLY + '\n      id-token: write', pre: APP_TOKEN };
    expect(ci2(o)).toBe('high');
    expect(ci4(o)).toBe('high');
  });

  it('id-token with the agent on a cloud model (use_bedrock) is critical', () => {
    const wf = openAgent({ perms: COMMENT_ONLY + '\n      id-token: write' }).replace(
      '          allowed_non_write_users: "*"',
      '          allowed_non_write_users: "*"\n          use_bedrock: "true"'
    );
    expect(wf).toMatch(/use_bedrock/);
    expect(analyzeWorkflowSecrets('w.yml', wf)!.severity).toBe('critical');
  });

  it('use_bedrock: "false" is not a cloud sign-in', () => {
    const wf = openAgent({ perms: COMMENT_ONLY + '\n      id-token: write' }).replace(
      '          allowed_non_write_users: "*"',
      '          allowed_non_write_users: "*"\n          use_bedrock: "false"'
    );
    expect(analyzeWorkflowSecrets('w.yml', wf)!.severity).toBe('high');
  });
});

describe('review: the key-file finding', () => {
  it('is anchored at the login step, also when the key is the only secret', () => {
    const wf = twoSteps({ pre: GCP_KEY() }).replace('  id-token: write\n', '');
    const s = analyzeWorkflowSecrets('w.yml', wf)!;
    expect(s.severity).toBe('high');
    expect(s.signals[0]).toMatch(/^agent can reach: GCP_SA_KEY \(key file/);
    expect(wf.split('\n')[s.line! - 1]).toMatch(/credentials_json/);
  });

  it('tag mode (no prompt) reads files without Read in the tool list', () => {
    const wf = twoSteps({ pre: GCP_KEY(), forkTools: 'Bash(gh pr comment:*)' }).replace(
      "          prompt: 'Review the diff with gh pr diff and comment.'\n",
      ''
    );
    expect(wf).not.toMatch(/Review the diff with/);
    expect(analyzeWorkflowSecrets('w.yml', wf)!.severity).toBe('high');
  });
});

describe('review: many agent jobs behind one long gate stay cheap', () => {
  it('reads each ancestor once per event', () => {
    const cond = `github.event_name != 'issue_comment' || (${Array.from({ length: 300 }, (_, i) => `github.event.comment.user.login == 'u${i}'`).join(' || ')})`;
    const jobs = Array.from(
      { length: 150 },
      (_, i) => `  a${i}:
    needs: plan
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-base-action@beta
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'do \${{ github.event.comment.body }}'
          allowed_tools: "Bash"`
    ).join('\n');
    const wf = `
on:
  issue_comment:
    types: [created]
jobs:
  plan:
    if: ${cond}
    runs-on: ubuntu-latest
    steps:
      - run: echo plan
${jobs}
`;
    const t0 = Date.now();
    const f = analyzeWorkflow('w.yml', wf)!;
    analyzeWorkflowSecrets('w.yml', wf);
    expect(f.severity).toBe('advisory');
    expect(Date.now() - t0).toBeLessThan(5_000);
  });
});
