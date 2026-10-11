// T.6.9 — a label on a new issue is a gate unless an issue form applies it (2026-10-11).
// WRITTEN BEFORE THE IMPLEMENTATION. Only someone with triage access can label an issue, so
// `contains(github.event.issue.labels.*.name, 'x')` keeps strangers out, except when
// `.github/ISSUE_TEMPLATE/<form>` puts `x` on every issue opened from it.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanTree } from '../ci-check';
import { issueFormLabels } from '../ci-check/workflows';
import { SEVERITY_RANK, type RepoTree } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'issue-forms');
const tree = (dir: string): RepoTree => ({
  source: 'owner/repo',
  notes: [],
  files: fs.readdirSync(path.join(FX, dir)).map((f) => ({
    path: f === 'agent.yml' ? `.github/workflows/${f}` : `.github/ISSUE_TEMPLATE/${f}`,
    content: fs.readFileSync(path.join(FX, dir, f), 'utf8'),
  })),
});
const worstCi2 = (dir: string) => {
  const f = scanTree(tree(dir)).findings.find((x) => x.check === 'CI-2');
  return f ? SEVERITY_RANK[f.severity] : -1;
};

describe('T.6.9 — issue labels and issue forms', () => {
  it('no form applies the label: the label is a gate', () => {
    expect(worstCi2('no-form')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('a form applies the label to every new issue: not a gate', () => {
    expect(worstCi2('form-applies-label')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('an issue form is read for its labels, not listed as inspected agent surface', () => {
    expect(scanTree(tree('form-applies-label')).inspected).not.toContain(
      '.github/ISSUE_TEMPLATE/bug.yml'
    );
  });

  it('reads inline, list and Markdown front-matter label forms', () => {
    expect(issueFormLabels('labels: ["Bug", \'triage\']')).toEqual(['bug', 'triage']);
    expect(issueFormLabels('labels:\n  - bug\n  - "needs info"\nbody: []')).toEqual([
      'bug',
      'needs info',
    ]);
    expect(issueFormLabels('---\nname: Bug\nlabels: bug, help wanted\n---\nText')).toEqual([
      'bug',
      'help wanted',
    ]);
  });
});
