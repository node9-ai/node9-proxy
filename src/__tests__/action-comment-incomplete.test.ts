// O — "node9 could not read everything" on a PR (design: scanner-gaps-code-design.md §O;
// founder decision 2026-09-27). WRITTEN BEFORE THE IMPLEMENTATION.
//
// The check-run conclusion for an incomplete scan was already neutral, but the sticky comment
// said "✅ No agent-security findings" and the check-run title said the same, and nothing named
// what was not read. A PR author can make a scan incomplete (padding, caps, budgets), so the
// page a reviewer reads must say so, and say what.

import { describe, it, expect } from 'vitest';
import path from 'path';
import { createRequire } from 'module';

// comment.js is plain CommonJS, run by action.yml with `node`, outside the TS build.
const c = createRequire(__filename)(path.resolve(__dirname, '../../comment.js')) as {
  decide: (w: string | null, f: string, i?: boolean) => { conclusion: string; exitCode: number };
  renderComment: (r: object) => string;
  checkSummary: (r: object) => { title: string; summary: string };
  incompleteWarning: (r: object) => string | null;
};

const NOTE = 'big/SKILL.md is larger than 4 MiB — not read; results may be INCOMPLETE.';
const clean = {
  source: 'x',
  findings: [],
  inspected: ['CLAUDE.md'],
  notes: [],
  worst: null,
  incomplete: false,
};
const partial = {
  ...clean,
  notes: ['skipped 2 files under a build-output dir', NOTE],
  incomplete: true,
};
const diff = (incomplete: boolean) => ({
  base: 'ok',
  added: [],
  escalated: [],
  unchanged: [],
  removed: [],
  worstIntroduced: null,
  incomplete,
});
const finding = {
  check: 'CI-2',
  rule: 'CI-2.injectable-workflow',
  severity: 'high',
  title: 'Injectable workflow',
  file: '.github/workflows/a.yml',
  signals: ['s'],
  fix: 'f',
};

describe('O — an incomplete scan never reads as clean, and says what was not read', () => {
  for (const [name, r] of [
    ['no base', partial],
    ['base read, head incomplete', { ...partial, diff: diff(true) }],
    ['diff incomplete only', { ...clean, notes: [NOTE], diff: diff(true) }],
  ] as const)
    it(`comment and check-run: ${name}`, () => {
      const md = c.renderComment(r);
      expect(md).not.toMatch(/node9 agent-security · ✅/);
      expect(md).not.toMatch(/No agent-security findings/);
      expect(md).toContain('could not read everything');
      expect(md).toContain('big/SKILL.md');
      expect(md).not.toContain('build-output dir'); // only what was NOT read is listed
      const cs = c.checkSummary(r);
      expect(cs.title).toBe('node9 could not read everything');
      expect(cs.summary).toContain('big/SKILL.md');
      expect(c.decide(null, 'high', true).conclusion).toBe('neutral');
    });

  it('with findings: the findings lead, the partial-scan block follows, the title says so', () => {
    const r = { ...partial, findings: [finding], worst: 'high' };
    const md = c.renderComment(r);
    expect(md).toMatch(/node9 agent-security · 🔴 High/);
    expect(md.indexOf('could not read everything')).toBeGreaterThan(md.indexOf('High'));
    expect(md).toContain('big/SKILL.md');
    expect(c.checkSummary(r).title).toBe(
      '1 agent-security finding(s), worst: high — scan incomplete'
    );
  });

  it('lists at most 5 reasons, then how many more', () => {
    const notes = Array.from(
      { length: 8 },
      (_, i) => `f${i}.md could not be read (EACCES) — results may be INCOMPLETE.`
    );
    const md = c.renderComment({ ...partial, notes });
    expect(md).toContain('f4.md');
    expect(md).not.toContain('f5.md');
    expect(md).toContain('and 3 more');
  });

  it('a file name that carries markdown renders inert', () => {
    const evil =
      'x](https://evil.test)`@team<!--.md could not be read (ENOENT) — results may be INCOMPLETE.\n### forged';
    const md = c.renderComment({ ...partial, notes: [evil] });
    expect(md).not.toMatch(/^### forged/m);
    expect(md).not.toContain('`@team'); // no backtick survives to close the code span
  });

  it('one Actions warning line, with workflow-command data escaped', () => {
    const w = c.incompleteWarning({
      ...partial,
      notes: ['a.md\nb % c — results may be INCOMPLETE.'],
    });
    expect(w).toMatch(/^::warning title=node9 could not read everything::/);
    expect(w).not.toContain('\n');
    expect(w).toContain('%0A');
    expect(w).toContain('%25');
    expect(c.incompleteWarning(clean)).toBeNull();
  });

  it('a complete clean scan is unchanged: ✅ and "No agent-security findings"', () => {
    expect(c.renderComment(clean)).toMatch(/node9 agent-security · ✅/);
    expect(c.checkSummary(clean).title).toBe('No agent-security findings');
    expect(c.decide(null, 'high', false).conclusion).toBe('success');
  });
});
