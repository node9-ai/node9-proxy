// T.5 — items strangers write, read by an agent on a trigger they cannot fire (2026-10-11).
// WRITTEN BEFORE THE IMPLEMENTATION. Founder decision (#337): a scheduled agent that reads
// open issues/PRs or third-party web content while holding a write token is an alert at the
// lowest counted level (advisory, tier alert). And a `labeled` trigger is stranger-firable when
// an issue form applies the label to every new issue.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanTree } from '../ci-check';
import { isAlert } from '../ci-check/tier';
import { SEVERITY_RANK, type RepoTree } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'trusted-readers');
const single = (f: string): RepoTree => ({
  source: 'owner/repo',
  notes: [],
  files: [{ path: `.github/workflows/${f}`, content: fs.readFileSync(path.join(FX, f), 'utf8') }],
});
const alerts = (t: RepoTree) => scanTree(t).findings.filter(isAlert);

describe('T.5a — a trusted-trigger agent that reads items strangers write, with a write token', () => {
  it.each(['schedule-lists-issues.yml', 'schedule-webfetch-push.yml'])('%s: counted', (f) => {
    const a = alerts(single(f));
    expect(a.map((x) => x.rule)).toContain('CI-2.trusted-trigger-reader');
    const r = a.find((x) => x.rule === 'CI-2.trusted-trigger-reader')!;
    expect(r.severity).toBe('advisory');
  });

  it.each(['schedule-no-token.yml', 'schedule-read-only.yml', 'schedule-local-only.yml'])(
    '%s: not counted',
    (f) => {
      expect(alerts(single(f))).toEqual([]);
    }
  );
});

describe('T.5b — a label an issue form applies makes `labeled` stranger-firable', () => {
  it('form applies the gate label: the agent is reachable (medium or more)', () => {
    const t: RepoTree = {
      source: 'owner/repo',
      notes: [],
      files: [
        {
          path: '.github/workflows/agent.yml',
          content: fs.readFileSync(path.join(FX, 'form-labeled', 'agent.yml'), 'utf8'),
        },
        {
          path: '.github/ISSUE_TEMPLATE/submit.yml',
          content: fs.readFileSync(path.join(FX, 'form-labeled', 'submit.yml'), 'utf8'),
        },
      ],
    };
    const f = scanTree(t).findings.find((x) => x.rule === 'CI-2.injectable-workflow');
    expect(f && SEVERITY_RANK[f.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('the same workflow without the form: not reachable', () => {
    const t: RepoTree = {
      source: 'owner/repo',
      notes: [],
      files: [
        {
          path: '.github/workflows/agent.yml',
          content: fs.readFileSync(path.join(FX, 'form-labeled', 'agent.yml'), 'utf8'),
        },
      ],
    };
    expect(alerts(t)).toEqual([]);
  });
});
