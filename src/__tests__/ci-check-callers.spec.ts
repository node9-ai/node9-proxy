// T.1 — a local reusable workflow is judged by its callers (2026-10-11). WRITTEN BEFORE THE
// IMPLEMENTATION. A `workflow_call` template has no trigger of its own; when another workflow
// in the same repository calls it with `uses: ./.github/workflows/<file>`, that caller's
// triggers and gate decide who can reach the agent. With no local caller the template keeps
// today's "potentially untrusted" score (capped at medium).

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanTree } from '../ci-check';
import { SEVERITY_RANK, type RepoTree } from '../ci-check/types';
import { isAlert } from '../ci-check/tier';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'callers');
const tree = (dir: string): RepoTree => ({
  source: 'owner/repo',
  notes: [],
  files: fs.readdirSync(path.join(FX, dir)).map((f) => ({
    path: `.github/workflows/${f}`,
    content: fs.readFileSync(path.join(FX, dir, f), 'utf8'),
  })),
});
const ci2On = (dir: string, file: string) =>
  scanTree(tree(dir)).findings.find(
    (f) => f.check === 'CI-2' && f.file === `.github/workflows/${file}`
  );
const rank = (dir: string, file: string) => {
  const f = ci2On(dir, file);
  return f ? SEVERITY_RANK[f.severity] : -1;
};
const alerts = (dir: string) => scanTree(tree(dir)).findings.filter(isAlert);

describe('T.1 — the caller decides who reaches the template', () => {
  it('an ungated caller on workflow_run: the template scores with that trigger', () => {
    const f = ci2On('stranger-caller', 'analysis.yml');
    expect(f).toBeDefined();
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(f!.signals.join(' ')).toMatch(/called by \.github\/workflows\/review\.yml/);
    expect(f!.signals.join(' ')).not.toMatch(/reachability depends on the caller/);
  });

  it('every caller is trusted (repository_dispatch): no alert', () => {
    expect(alerts('trusted-caller')).toEqual([]);
  });

  it('the calling job is gated to write roles: no alert', () => {
    expect(alerts('gated-caller')).toEqual([]);
  });

  it('the calling job runs only when an upstream allowlist job says so: no alert', () => {
    expect(alerts('needs-output-gate')).toEqual([]);
  });
});

describe('T.1 — what stays as it is', () => {
  it('a caller that runs on a dispatcher output: the template keeps the reusable score', () => {
    const f = ci2On('dispatcher', 'analysis.yml');
    expect(f).toBeDefined();
    expect(f!.signals.join(' ')).toMatch(/reusable workflow \(workflow_call\)/);
    expect(f!.signals.join(' ')).not.toMatch(/called by/);
  });

  it('no local caller: the template keeps the reusable score', () => {
    const f = ci2On('no-caller', 'analysis.yml');
    expect(f).toBeDefined();
    expect(f!.signals.join(' ')).toMatch(/reusable workflow \(workflow_call\)/);
    expect(rank('no-caller', 'analysis.yml')).toBeLessThanOrEqual(SEVERITY_RANK.medium);
  });
});
