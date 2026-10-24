// Gap 1 (2026-10-24): a reusable workflow called by its full path in the same repository
// (`<owner>/<repo>/.github/workflows/<file>@<ref>`) was not resolved, so the template kept the
// "unseen caller" score (capped at medium) even when its caller runs on pull_request_target.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanTree } from '../ci-check';
import { SEVERITY_RANK, type RepoTree } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'full-path-calls');
const files = () =>
  fs.readdirSync(FX).map((f) => ({
    path: `.github/workflows/${f}`,
    content: fs.readFileSync(path.join(FX, f), 'utf8'),
  }));
const template = (t: Partial<RepoTree>) =>
  scanTree({ source: 'x', notes: [], files: files(), ...t }).findings.find(
    (f) => f.rule === 'CI-2.injectable-workflow' && f.file === '.github/workflows/template.yml'
  );

describe('gap 1: a full-path call to the same repository is a local call', () => {
  it('owner and repo match (any case): the template takes the caller trigger', () => {
    const f = template({ owner: 'example-org', repo: 'example-repo' });
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
    expect(f!.signals.join(' ')).toMatch(/called by \.github\/workflows\/caller\.yml/);
  });
});

describe('gap 1: what stays as it is', () => {
  // Unresolved, the template keeps the reusable score: its prompt file is no reach of its own.
  it('another repository of the same owner stays an external call', () => {
    const f = template({ owner: 'example-org', repo: 'other-repo' });
    expect(f!.severity).toBe('advisory');
    expect(f!.signals.join(' ')).toMatch(/reachability depends on the caller/);
  });

  it('the repository name unknown (local path without a GitHub origin): unresolved', () => {
    expect(template({ owner: 'example-org' })!.severity).toBe('advisory');
    expect(template({})!.severity).toBe('advisory');
  });
});
