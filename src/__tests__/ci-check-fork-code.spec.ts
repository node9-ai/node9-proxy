// T.7 — fork code in a gated agent job (2026-10-11). WRITTEN BEFORE THE IMPLEMENTATION.
// Founder decision (node9Firewall#337): an agent that a maintainer starts on fork code is a
// problem, counted at the lowest level (advisory, tier alert). The job's gate (the action's
// write check, a label, an association or membership test) stops a stranger from starting it,
// but once a maintainer does, the agent runs inside the fork's checkout: its CLAUDE.md,
// `.claude/settings.json` hooks, `.mcp.json` and build scripts, next to the job's secrets.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanTree } from '../ci-check';
import { isAlert } from '../ci-check/tier';
import type { RepoTree } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'fork-code');
const tree = (f: string): RepoTree => ({
  source: 'owner/repo',
  notes: [],
  files: [{ path: `.github/workflows/${f}`, content: fs.readFileSync(path.join(FX, f), 'utf8') }],
});
const rules = (f: string) =>
  scanTree(tree(f))
    .findings.filter(isAlert)
    .map((x) => `${x.rule}:${x.severity}`);

describe('T.7 — a maintainer-started agent inside the fork head', () => {
  it.each([
    'pr-target-head-implicit-gate.yml',
    'comment-gh-pr-checkout.yml',
    'refs-pull-head-membership.yml',
    'label-gate-head.yml',
  ])('%s: counted', (f) => {
    expect(rules(f)).toContain('CI-2.fork-code-on-trust:advisory');
  });
});

describe('T.7 — what stays as it is', () => {
  it.each([
    'same-repo-test.yml',
    'base-checkout.yml',
    'codex-read-only-sandbox.yml',
    'trusted-author-gate.yml',
  ])('%s: no alert', (f) => {
    expect(rules(f)).toEqual([]);
  });
});
