// Round-2 review, batch 2: shapes 2.29.0 flagged that the round-2 code let through
// (adversarial review, 2026-10-11). WRITTEN BEFORE THE FIX. Each case is a dangerous workflow
// or config next to the trick that hid it.

import { describe, it, expect } from 'vitest';
import { scanTree } from '../ci-check';
import { analyzeMcp, ownPackageNames } from '../ci-check/mcp';
import { SEVERITY_RANK, type RepoTree } from '../ci-check/types';
import { isAlert } from '../ci-check/tier';
import { readLocalTree } from '../ci-check/fetch';
import fs from 'fs';
import os from 'os';
import path from 'path';

const tree = (files: Record<string, string>): RepoTree => ({
  source: 'owner/repo',
  notes: [],
  files: Object.entries(files).map(([path, content]) => ({ path, content })),
});
const worst = (files: Record<string, string>) => {
  const r = scanTree(tree(files));
  return r.worst ? SEVERITY_RANK[r.worst] : -1;
};

// An open agent: anyone's comment drives a shell with a write token.
const AGENT_STEPS = [
  '    steps:',
  '      - uses: anthropics/claude-code-base-action@v1',
  '        with:',
  '          prompt: "Handle this: ${{ github.event.comment.body }}"',
  '          allowed_tools: "Bash"',
  '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
].join('\n');
const onComment = (jobIf: string | null) =>
  [
    'on:',
    '  issue_comment:',
    '    types: [created]',
    'permissions:',
    '  contents: write',
    'jobs:',
    '  agent:',
    '    runs-on: ubuntu-latest',
    ...(jobIf === null ? [] : [`    if: ${jobIf}`]),
    AGENT_STEPS,
    '',
  ].join('\n');
const WF = '.github/workflows/agent.yml';

describe('batch 2 — `if:` text outside `${{ }}` is a string, always true', () => {
  it('`false && ${{ … }}` does not delete the job', () => {
    expect(worst({ [WF]: onComment(`"false && \${{ true }}"`) })).toBeGreaterThanOrEqual(
      SEVERITY_RANK.high
    );
  });

  it('a gate wrapped in `${{ }}` with text after it is not a gate', () => {
    expect(
      worst({ [WF]: onComment(`"\${{ github.actor == 'maintainer' }} && \${{ true }}"`) })
    ).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });
});

describe('batch 2 — label gates', () => {
  const onIssues = (types: string, jobIf: string, extraOn = '') =>
    [
      'on:',
      '  issues:',
      `    types: [${types}]`,
      extraOn,
      'permissions:',
      '  contents: write',
      '  issues: write',
      'jobs:',
      '  agent:',
      '    runs-on: ubuntu-latest',
      `    if: ${jobIf}`,
      AGENT_STEPS.replace('github.event.comment.body', 'github.event.issue.body'),
      '',
    ]
      .filter((l) => l !== '')
      .join('\n') + '\n';

  it('`label.name != …` on `issues: opened` is not a gate', () => {
    expect(
      worst({ [WF]: onIssues('opened', "github.event.label.name != 'skip-ai'") })
    ).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('an issue label on an `issue_comment` job is not a gate for the comment text', () => {
    const wf = onComment("contains(github.event.issue.labels.*.name, 'ai-help')").replace(
      'on:\n',
      'on:\n  issues:\n    types: [labeled]\n'
    );
    expect(worst({ [WF]: wf })).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it.each([
    ['a compact block list', 'labels:\n- ai-review\nbody: []\n'],
    ['a comment after the key', 'labels: # applied on open\n  - ai-review\nbody: []\n'],
  ])('an issue form label written as %s is read', (_n, form) => {
    expect(
      worst({
        [WF]: onIssues('opened', "contains(github.event.issue.labels.*.name, 'ai-review')"),
        '.github/ISSUE_TEMPLATE/request.yml': `name: Request\n${form}`,
      })
    ).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });
});

describe('batch 2 — an upstream script gate needs a positive allowlist', () => {
  const gatedBy = (script: string, readerIf: string) =>
    [
      'on:',
      '  issue_comment:',
      '    types: [created]',
      'permissions:',
      '  contents: write',
      'jobs:',
      '  check:',
      '    runs-on: ubuntu-latest',
      '    outputs:',
      '      allowed: ${{ steps.c.outputs.allowed }}',
      '    steps:',
      '      - id: c',
      '        uses: actions/github-script@v7',
      '        with:',
      '          script: |',
      `            ${script}`,
      '  agent:',
      '    needs: check',
      `    if: ${readerIf}`,
      '    runs-on: ubuntu-latest',
      AGENT_STEPS,
      '',
    ].join('\n');
  const ALLOW =
    "core.setOutput('allowed', ['owner-a', 'owner-b'].includes(context.actor) ? 'true' : 'false');";

  it('an allowlist read on a yes is a gate', () => {
    expect(
      scanTree(
        tree({ [WF]: gatedBy(ALLOW, "needs.check.outputs.allowed == 'true'") })
      ).findings.filter(isAlert)
    ).toEqual([]);
  });

  it('the same allowlist read on a no is not', () => {
    expect(
      worst({ [WF]: gatedBy(ALLOW, "needs.check.outputs.allowed != 'true'") })
    ).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it("a permission read on `!= 'none'` is not (a stranger has `read`)", () => {
    const perm =
      "const { data } = await github.rest.repos.getCollaboratorPermissionLevel({ ...context.repo, username: context.actor }); core.setOutput('allowed', data.permission);";
    expect(
      worst({ [WF]: gatedBy(perm, "needs.check.outputs.allowed != 'none'") })
    ).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('a block list (`blocked.includes(actor) ? false : true`) is not a gate', () => {
    const wf = [
      'on:',
      '  issue_comment:',
      '    types: [created]',
      'permissions:',
      '  contents: write',
      'jobs:',
      '  check:',
      '    runs-on: ubuntu-latest',
      '    outputs:',
      '      allowed: ${{ steps.c.outputs.allowed }}',
      '    steps:',
      '      - id: c',
      '        uses: actions/github-script@v7',
      '        with:',
      '          script: |',
      "            const blocked = ['spam-bot', 'known-abuser'];",
      "            core.setOutput('allowed', blocked.includes(context.actor) ? 'false' : 'true');",
      '  agent:',
      '    needs: check',
      "    if: needs.check.outputs.allowed == 'true'",
      '    runs-on: ubuntu-latest',
      AGENT_STEPS,
      '',
    ].join('\n');
    expect(worst({ [WF]: wf })).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });
});

describe('batch 2 — issue forms past the read cap', () => {
  it('a repository with more forms than are read says the result may be incomplete', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'forms-'));
    try {
      fs.mkdirSync(path.join(dir, '.github', 'ISSUE_TEMPLATE'), { recursive: true });
      for (let i = 0; i < 45; i++)
        fs.writeFileSync(path.join(dir, '.github', 'ISSUE_TEMPLATE', `f${i}.yml`), 'name: F\n');
      const t = readLocalTree(dir);
      expect(t.notes.join(' ')).toMatch(/45 issue forms; read the first 40/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('batch 2 — a template called through another template', () => {
  it('A (pull_request_target) calls B, B calls C: C keeps its own score', () => {
    const c = [
      'on:',
      '  workflow_call:',
      'permissions:',
      '  contents: write',
      'jobs:',
      '  agent:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: anthropics/claude-code-action@v1',
      '        with:',
      '          anthropic_api_key: ${{ secrets.K }}',
      '          github_token: ${{ secrets.GITHUB_TOKEN }}',
      "          allowed_non_write_users: '*'",
      '          prompt: Review ${{ github.event.pull_request.title }}',
      '          claude_args: --allowedTools Bash',
      '',
    ].join('\n');
    const files = {
      '.github/workflows/a.yml':
        'on: pull_request_target\njobs:\n  call:\n    uses: ./.github/workflows/b.yml\n',
      '.github/workflows/b.yml':
        'on: workflow_call\njobs:\n  call:\n    uses: ./.github/workflows/c.yml\n',
      '.github/workflows/c.yml': c,
    };
    expect(worst(files)).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });
});

describe('batch 2 — `with:` keys are lower-cased, and every lookup follows', () => {
  it('`allowedTools: Bash` on base-action is still a shell', () => {
    const wf = [
      'on: pull_request_target',
      'permissions:',
      '  contents: write',
      'jobs:',
      '  r:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: anthropics/claude-code-base-action@v1',
      '        with:',
      '          prompt: Review ${{ github.event.pull_request.title }}',
      '          allowedTools: "Bash"',
      '          anthropic_api_key: ${{ secrets.K }}',
      '',
    ].join('\n');
    const f = scanTree(tree({ [WF]: wf })).findings.find((x) => x.check === 'CI-2');
    expect(f?.signals.join(' ')).toMatch(/broad\/write-capable tools/);
  });
});

describe('batch 2 — the own-package exemption covers only the own package', () => {
  const own = new Set(['acme-docs-site', 'own-cli']);
  const server = (args: string[]) =>
    JSON.stringify({ mcpServers: { s: { command: 'npx', args } } });
  const flagged = (args: string[], o: ReadonlySet<string> = own) =>
    analyzeMcp('.mcp.json', server(args), o).some((f) => f.rule === 'CI-3.mcp-unpinned');

  it.each([
    [['-y', '-p', 'acme-docs-site', '-p', 'helper-mcp-server', 'helper-mcp']],
    [['-y', '--package=evil-pkg', 'own-cli']],
  ])('%j installs another package: flagged', (args) => {
    expect(flagged(args)).toBe(true);
  });

  it('a shell around the launcher is not excused by its first command', () => {
    const cfg = JSON.stringify({
      mcpServers: {
        s: { command: 'sh', args: ['-c', 'npx acme-docs-site --check ; npx -y helper-mcp-server'] },
      },
    });
    expect(analyzeMcp('.mcp.json', cfg, own).some((f) => f.rule === 'CI-3.mcp-unpinned')).toBe(
      true
    );
  });

  it('a private package.json name is not a published package', () => {
    expect(
      ownPackageNames([
        { path: 'package.json', content: '{"name":"acme-docs-site","private":true}' },
      ]).size
    ).toBe(0);
  });

  it('a PyPI launcher is not excused by an npm name', () => {
    const npmOnly = ownPackageNames([{ path: 'package.json', content: '{"name":"some-tool"}' }]);
    const cfg = JSON.stringify({ mcpServers: { s: { command: 'uvx', args: ['some-tool'] } } });
    expect(analyzeMcp('.mcp.json', cfg, npmOnly).some((f) => f.rule === 'CI-3.mcp-unpinned')).toBe(
      true
    );
  });
});

describe('batch 2 — sanity', () => {
  it('the open agent alone is high', () => {
    expect(worst({ [WF]: onComment(null) })).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
    expect(scanTree(tree({ [WF]: onComment(null) })).findings.some(isAlert)).toBe(true);
  });
});
