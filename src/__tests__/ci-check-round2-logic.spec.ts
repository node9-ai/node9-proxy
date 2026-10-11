// Round-2 review, batch 3b: logic and interactions (adversarial review, 2026-10-11). WRITTEN
// BEFORE THE FIX. All inputs are synthetic.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';
import { createRequire } from 'module';
import { scanTree } from '../ci-check';
import { analyzeMcp } from '../ci-check/mcp';
import { analyzeAgentConfig, analyzeSkillGrants } from '../ci-check/agent-config';
import { readLocalTree, readGitRefTree } from '../ci-check/fetch';
import type { RepoTree } from '../ci-check/types';
import { isAlert } from '../ci-check/tier';

const tree = (files: Record<string, string>): RepoTree => ({
  source: 'owner/repo',
  notes: [],
  files: Object.entries(files).map(([p, content]) => ({ path: p, content })),
});
const alertRules = (files: Record<string, string>) =>
  scanTree(tree(files))
    .findings.filter(isAlert)
    .map((f) => f.rule);

describe('batch 3b: every MCP section is read on its own', () => {
  it('a pinned decoy under `servers` does not hide the real server under `mcpServers`', () => {
    const cfg = {
      mcpServers: { helper: { command: 'npx', args: ['-y', 'some-mcp-server'] } },
      servers: { helper: { command: 'npx', args: ['-y', 'some-mcp-server@1.2.3'] } },
    };
    const f = analyzeMcp('.mcp.json', JSON.stringify(cfg)).filter(
      (x) => x.rule === 'CI-3.mcp-unpinned'
    );
    expect(f.map((x) => x.locator)).toEqual(['mcpServers.helper']);
    expect(f[0].line).toBeDefined();
  });

  it("opencode's `environment` is read for inline credentials", () => {
    const cfg = {
      mcp: {
        s: {
          type: 'local',
          command: ['node', './server.js'],
          environment: { AWS_ACCESS_KEY_ID: 'AKIA' + 'QX7Z3BHDM7NPLKV5' },
        },
      },
    };
    expect(
      analyzeMcp('opencode.json', JSON.stringify(cfg)).some(
        (x) => x.rule === 'CI-3.mcp-inline-credential'
      )
    ).toBe(true);
  });

  it('the explanation names the package and its registry pin syntax', () => {
    const f = analyzeMcp(
      '.mcp.json',
      JSON.stringify({ mcpServers: { f: { command: 'uvx', args: ['mcp-server-fetch'] } } })
    )[0];
    expect(f.explain?.happens).toMatch(/the newest `mcp-server-fetch` from PyPI/);
    expect(f.explain?.fix.join(' ')).toMatch(/mcp-server-fetch==x\.y\.z/);
  });
});

describe('batch 3b: T.5 and T.7 see a template through its callers', () => {
  const template = (steps: string[]) =>
    [
      'on:',
      '  workflow_call:',
      'permissions:',
      '  contents: write',
      '  issues: write',
      'jobs:',
      '  agent:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      ...steps,
      '      - uses: anthropics/claude-code-action@v1',
      '        with:',
      '          prompt: Run gh issue list and fix the bugs it shows.',
      '          claude_args: --allowedTools Bash',
      '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
      '',
    ].join('\n');

  it('a maintainer-gated caller of a template that runs the agent in the fork', () => {
    const caller = [
      'on:',
      '  issue_comment:',
      '    types: [created]',
      'jobs:',
      '  call:',
      "    if: github.event.issue.pull_request && github.event.comment.author_association == 'OWNER'",
      '    uses: ./.github/workflows/agent.yml',
      '    secrets: inherit',
      '',
    ].join('\n');
    const files = {
      '.github/workflows/caller.yml': caller,
      '.github/workflows/agent.yml': template([
        '      - uses: actions/checkout@v4',
        '        with:',
        '          ref: refs/pull/${{ github.event.issue.number }}/head',
      ]),
    };
    expect(alertRules(files)).toContain('CI-2.fork-code-on-trust');
  });

  it('a scheduled caller of a template that reads open issues with a write token', () => {
    const caller = [
      'on:',
      '  schedule:',
      "    - cron: '0 3 * * *'",
      'jobs:',
      '  call:',
      '    uses: ./.github/workflows/agent.yml',
      '    secrets: inherit',
      '',
    ].join('\n');
    const files = {
      '.github/workflows/caller.yml': caller,
      '.github/workflows/agent.yml': template([]),
    };
    expect(alertRules(files)).toContain('CI-2.trusted-trigger-reader');
  });

  it("the caller's trigger keys reach the signal through safeText", () => {
    const caller =
      'on:\n  pull_request_target:\n  "x`\\n\\n[Approve](https://example.invalid/)":\njobs:\n  call:\n    uses: ./.github/workflows/agent.yml\n';
    const f = scanTree(
      tree({ '.github/workflows/a.yml': caller, '.github/workflows/agent.yml': template([]) })
    ).findings.find((x) => x.file === '.github/workflows/agent.yml' && x.check === 'CI-2');
    const sig = f?.signals.find((s) => s.startsWith('called by')) ?? '';
    expect(sig).toMatch(/called by/);
    expect(sig).not.toMatch(/\n/);
  });
});

describe('batch 3b: a PowerShell grant is graded like the Bash one', () => {
  it('`PowerShell(*)` with no deny is high', () => {
    const f = analyzeAgentConfig(
      '.claude/settings.json',
      JSON.stringify({ permissions: { allow: ['PowerShell(*)'] } })
    ).find((x) => x.rule === 'CI-1.broad-allow');
    expect(f?.severity).toBe('high');
  });

  it('a skill with `PowerShell(*)` that reads a PR is counted', () => {
    const skill =
      '---\nname: pr\nallowed-tools: PowerShell(*)\n---\nRead it with `gh pr view $1 --json title,body`.\n';
    expect(
      analyzeSkillGrants('.claude/skills/pr/SKILL.md', skill).some(
        (x) => x.rule === 'CI-1.skill-untrusted-input'
      )
    ).toBe(true);
  });
});

describe('batch 3b: the repository owner', () => {
  const git = (cwd: string, ...args: string[]) =>
    execFileSync('git', args, { cwd, stdio: ['ignore', 'pipe', 'ignore'] });
  const repo = () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'owner-')));
    git(dir, 'init', '-q');
    git(dir, 'config', 'user.email', 't@example.invalid');
    git(dir, 'config', 'user.name', 't');
    git(dir, 'remote', 'add', 'origin', 'https://github.com/acme/x.git');
    fs.writeFileSync(path.join(dir, 'README.md'), 'x\n');
    git(dir, 'add', '.');
    git(dir, 'commit', '-q', '-m', 'init');
    return dir;
  };

  it('the base read carries the same owner as the head read', () => {
    const dir = repo();
    try {
      expect(readLocalTree(dir).owner).toBe('acme');
      expect(readGitRefTree(dir, 'HEAD')?.owner).toBe('acme');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a directory inside a clone is not given the clone owner', () => {
    const dir = repo();
    try {
      fs.mkdirSync(path.join(dir, 'vendor', 'x'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'vendor', 'x', 'README.md'), 'x\n');
      expect(readLocalTree(path.join(dir, 'vendor', 'x')).owner).toBeUndefined();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('batch 3b: the PR comment for a counted low finding', () => {
  const c = createRequire(__filename)(path.resolve(__dirname, '../../comment.js')) as {
    renderComment: (r: object) => string;
  };
  it('does not call it a note that is gated today', () => {
    const f = {
      check: 'CI-2',
      rule: 'CI-2.fork-code-on-trust',
      severity: 'advisory',
      tier: 'alert',
      title: "A maintainer's action runs the agent inside the fork's code",
      file: '.github/workflows/fix.yml',
      signals: ['checks out the untrusted PR head into the workspace root'],
      fix: 'Check out the base branch.',
    };
    const md = c.renderComment({
      source: 'x',
      findings: [f],
      inspected: ['.github/workflows/fix.yml'],
      notes: [],
      worst: 'advisory',
      incomplete: false,
    });
    expect(md).not.toMatch(/Advisory: note|minor hardening note|gated or scoped today/);
    expect(md).toMatch(/inside a fork's code/);
  });
});
