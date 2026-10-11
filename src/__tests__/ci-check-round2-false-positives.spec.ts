// Round-2 review, batch 3c: false positives the round-2 code added (adversarial review,
// 2026-10-11). WRITTEN BEFORE THE FIX. Every fixture is synthetic; each one is a safe shape the
// round-2 rules counted.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanTree } from '../ci-check';
import { analyzeAgentConfig } from '../ci-check/agent-config';
import { analyzeInstructionFile } from '../ci-check/instructions';
import type { RepoTree } from '../ci-check/types';
import { isAlert } from '../ci-check/tier';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'round2-false-positives');
// The repository ignores `.claude/`, so skill fixtures are stored under `claude/` and read back at
// the path the agent opens.
const agentPath = (p: string) => p.replace(/^claude\//, '.claude/');
const load = (dir: string): RepoTree => {
  const files: { path: string; content: string }[] = [];
  const walk = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else
        files.push({
          path: agentPath(path.relative(path.join(FX, dir), p).split(path.sep).join('/')),
          content: fs.readFileSync(p, 'utf8'),
        });
    }
  };
  walk(path.join(FX, dir));
  return { source: 'owner/repo', notes: [], files };
};
const alerts = (t: RepoTree) =>
  scanTree(t)
    .findings.filter(isAlert)
    .map((f) => `${f.rule} ${f.file}`);

describe('batch 3c: safe shapes stay clean', () => {
  it.each([
    ['a skill that prints its own PR link', 'skill-prints-own-pr-link'],
    ['a skill that names a web tool in prose', 'skill-names-web-tool-in-prose'],
    ['a hardened, pinned image and pinned or local uvx servers', 'mcp-hardened-and-pinned'],
    ['a scheduled agent told to open pull requests', 'scheduled-agent-opens-prs'],
    ['a scheduled agent that looks up a PR number', 'scheduled-agent-number-lookup'],
    ['a fork gate written as a head/base repository compare', 'fork-gate-base-repo-compare'],
    ['a review-approved follow-up (review events carry no secrets)', 'fork-gate-review-approved'],
    ['the common review-trigger template with a fallback ref', 'fork-gate-review-triggers'],
    ['artifacts of a scheduled upstream run', 'artifacts-of-scheduled-upstream'],
    ['a read-only codex reviewer on the PR merge ref', 'codex-read-only-pr-merge-ref'],
  ])('%s', (_n, dir) => {
    expect(alerts(load(dir))).toEqual([]);
  });
});

describe('batch 3c: other spellings of "same repository only"', () => {
  const wf = (cond: string) =>
    [
      'on:',
      '  pull_request_target:',
      '    types: [labeled]',
      'jobs:',
      '  review:',
      `    if: github.event.label.name == 'claude-review' && ${cond}`,
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
      '      - uses: anthropics/claude-code-action@v1',
      '        with:',
      '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
      '          prompt: Review this pull request.',
      '',
    ].join('\n');
  it.each([
    '!github.event.pull_request.head.repo.fork',
    'github.repository == github.event.pull_request.head.repo.full_name',
    'github.event.pull_request.head.repo.owner.login == github.repository_owner',
  ])('%s', (cond) => {
    expect(
      alerts({
        source: 'owner/repo',
        notes: [],
        files: [{ path: '.github/workflows/review.yml', content: wf(cond) }],
      })
    ).toEqual([]);
  });
});

describe('batch 3c: settings grants that run nothing on the machine', () => {
  const broad = (allow: string[]) =>
    analyzeAgentConfig('.claude/settings.json', JSON.stringify({ permissions: { allow } })).filter(
      (f) => f.rule === 'CI-1.broad-allow'
    );
  it.each(['Bash(git remote:*)', 'mcp__playwright__browser_evaluate'])('%s', (g) => {
    expect(broad(['Read', g])).toEqual([]);
  });

  it('a runner grant has a headline with a verb', () => {
    const f = broad(['Bash(node:*)'])[0];
    expect(f?.explain?.headline).toMatch(/run programs without asking/);
  });
});

describe('batch 3c: Greek notation is not a disguise', () => {
  it.each([
    'Clamp density to \u03c1max before the pressure solve; \u03c4max is the relaxation cap.',
    'Place item i at angle \u03b8=360*i/N, position = C + (r*cos\u03b8, r*sin\u03b8).',
  ])('%s', (line) => {
    expect(
      analyzeInstructionFile('CLAUDE.md', `# Notes\n\n${line}\n`).filter(
        (f) => f.rule === 'CI-6.homoglyph'
      )
    ).toEqual([]);
  });
});

describe('batch 3c: a sanitized lookup does not excuse a full listing beside it', () => {
  it('a scheduled agent that also lists issue bodies is still counted', () => {
    const wf = [
      'on:',
      '  schedule:',
      "    - cron: '0 3 * * *'",
      'permissions:',
      '  contents: write',
      '  issues: write',
      'jobs:',
      '  fix:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      "          gh pr list --head bot/fix --json number --jq '.[0].number' > pr.txt",
      '          gh issue list --state open \\',
      '            --json number,title,body > issues.json',
      '        env:',
      '          GH_TOKEN: ${{ github.token }}',
      '      - uses: anthropics/claude-code-action@v1',
      '        with:',
      '          prompt: Fix the bugs described in issues.json.',
      '          claude_args: --allowedTools Bash',
      '          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}',
      '',
    ].join('\n');
    expect(
      alerts({
        source: 'owner/repo',
        notes: [],
        files: [{ path: '.github/workflows/n.yml', content: wf }],
      })
    ).toContain('CI-2.trusted-trigger-reader .github/workflows/n.yml');
  });
});

describe('workflow_run after a workflow only the team can start', () => {
  const doctor = [
    'name: CI doctor',
    'on:',
    '  workflow_run:',
    '    workflows: [Build]',
    '    types: [completed]',
    'permissions:',
    '  contents: write',
    'jobs:',
    '  doctor:',
    '    runs-on: ubuntu-latest',
    '    env:',
    '      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}',
    '    steps:',
    '      - run: claude -p "Explain the failed run and comment on its pull request" --allowedTools "Write,mcp__github__get_pull_request" --dangerously-skip-permissions',
    '',
  ].join('\n');
  const build = (on: string) =>
    `name: Build\non:\n${on}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n`;
  const scan = (files: Record<string, string>) =>
    alerts({
      source: 'owner/repo',
      notes: [],
      files: Object.entries(files).map(([p, content]) => ({ path: p, content })),
    });

  it('a push-only upstream: no stranger reaches the agent', () => {
    expect(
      scan({
        '.github/workflows/build.yml': build('  push:\n    branches: [main]'),
        '.github/workflows/doctor.yml': doctor,
      })
    ).toEqual([]);
  });

  it('an upstream a fork PR starts: still open', () => {
    expect(
      scan({
        '.github/workflows/build.yml': build('  pull_request:'),
        '.github/workflows/doctor.yml': doctor,
      })
    ).toContain('CI-2.injectable-workflow .github/workflows/doctor.yml');
  });

  it('an upstream not in the tree: still open', () => {
    expect(scan({ '.github/workflows/doctor.yml': doctor })).toContain(
      'CI-2.injectable-workflow .github/workflows/doctor.yml'
    );
  });
});
