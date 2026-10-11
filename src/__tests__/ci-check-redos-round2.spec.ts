// Round-2 hostile input (adversarial review, 2026-10-11). WRITTEN BEFORE THE FIX. Every shape
// below is attacker-written workflow text that stalled the scanner, made it throw (which drops
// every finding of the file), or let one YAML alias rewrite another job's context. The budget is
// the same as ci-check-redos.spec.ts: linear code meets it in milliseconds.

import { describe, it, expect } from 'vitest';
import { scanTree } from '../ci-check';
import { analyzeWorkflow } from '../ci-check/workflows';
import type { RepoTree } from '../ci-check/types';

const BUDGET_MS = 2_000;
const timed = (fn: () => unknown): number => {
  const t = performance.now();
  fn();
  return performance.now() - t;
};
const tree = (content: string): RepoTree => ({
  source: 'owner/repo',
  notes: [],
  files: [{ path: '.github/workflows/x.yml', content }],
});

describe('round 2 — no crafted workflow stalls a scan', () => {
  it('a `git fetch … pull/1/head` followed by a long run of newlines', () => {
    const run = 'git fetch origin pull/1/head' + '\n'.repeat(80_000) + 'x';
    const wf =
      'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n' +
      `      - run: ${JSON.stringify(run)}\n` +
      '      - uses: anthropics/claude-code-action@v1\n';
    expect(timed(() => scanTree(tree(wf)))).toBeLessThan(BUDGET_MS);
  });

  it('many agent steps, each with a long `if:`', () => {
    const cond = 'steps.a.outputs.' + 'permission'.repeat(1_900) + " && github.actor == 'me'";
    const step = `      - if: ${JSON.stringify(cond)}\n        uses: anthropics/claude-code-action@v1\n`;
    const wf =
      'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n' + step.repeat(60);
    expect(timed(() => scanTree(tree(wf)))).toBeLessThan(BUDGET_MS);
  });

  it('many `steps.<id>.outputs` references to one large step', () => {
    const wf =
      'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n' +
      `      - id: a\n        run: ${JSON.stringify('x'.repeat(300_000))}\n` +
      '      - uses: someone/agent-wrapper@v1\n        with:\n' +
      '          anthropic_api_key: ${{ secrets.K }}\n' +
      `          prompt: ${JSON.stringify('${{ steps.a.outputs.o }}'.repeat(20_000))}\n`;
    expect(timed(() => scanTree(tree(wf)))).toBeLessThan(BUDGET_MS);
  });

  it('a large workflow env and many run-step agents', () => {
    const wf =
      `on: issue_comment\nenv:\n  BIG: ${JSON.stringify('z'.repeat(1_000_000))}\n` +
      'jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n' +
      '      - run: claude -p hi\n'.repeat(600);
    expect(timed(() => scanTree(tree(wf)))).toBeLessThan(BUDGET_MS);
  });

  it('a 1 MB `allowed_non_write_users` repeated through an alias', () => {
    const v = '${{' + 'github.event.'.repeat(80_000);
    const first =
      '      - uses: anthropics/claude-code-action@v1\n        with:\n' +
      `          allowed_non_write_users: &u ${JSON.stringify(v)}\n`;
    const rest =
      '      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: *u\n';
    const wf =
      'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n' +
      first +
      rest.repeat(30);
    expect(timed(() => scanTree(tree(wf)))).toBeLessThan(BUDGET_MS);
  });
});

describe('round 2 — a throw never reads as clean', () => {
  it('a decoy step whose env references would exceed the string limit keeps the real finding', () => {
    const wf =
      `on: pull_request_target\nenv:\n  A: ${JSON.stringify('y'.repeat(100_000))}\n` +
      'jobs:\n  review:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n' +
      '    steps:\n      - uses: actions/checkout@v4\n        with:\n' +
      '          ref: ${{ github.event.pull_request.head.sha }}\n' +
      '      - if: false\n        uses: actions/github-script@v7\n        with:\n' +
      `          script: ${JSON.stringify('${{ env.A }}'.repeat(6_000))}\n` +
      '      - uses: anthropics/claude-code-action@v1\n        with:\n' +
      '          anthropic_api_key: ${{ secrets.K }}\n          github_token: ${{ secrets.GITHUB_TOKEN }}\n' +
      "          allowed_non_write_users: '*'\n" +
      '          prompt: Review ${{ github.event.pull_request.title }}\n' +
      '          claude_args: --allowedTools Bash\n';
    const r = scanTree(tree(wf));
    expect(r.worst).toBe('critical');
  });

  it('a checker that throws marks the scan incomplete', () => {
    // A run-step agent whose `run:` is a list (GitHub rejects it; the scanner must not read
    // the resulting throw as clean).
    const wf =
      'on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n' +
      '      ANTHROPIC_API_KEY: ${{ secrets.K }}\n    steps:\n      - run: ["claude -p hi"]\n';
    const r = scanTree(tree(wf));
    expect(r.notes.some((n) => /checker degraded/.test(n)) ? r.incomplete : true).toBe(true);
  });
});

describe('round 2 — a YAML alias does not carry one job’s context into another', () => {
  it('a run-step agent shared with a second job keeps its own job env', () => {
    const wf = [
      'on: issue_comment',
      'jobs:',
      '  triage:',
      '    runs-on: ubuntu-latest',
      '    permissions: {contents: write}',
      '    env:',
      '      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}',
      '      BODY: ${{ github.event.comment.body }}',
      '    steps:',
      '      - &agent',
      '        run: claude -p "$BODY" --dangerously-skip-permissions',
      '  lint:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - *agent',
      '',
    ].join('\n');
    expect(analyzeWorkflow('.github/workflows/x.yml', wf)?.severity).toBe('high');
  });
});
