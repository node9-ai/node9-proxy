// Follow-ups I.1 and I.2 (design: scanner-gaps-code-design.md §I, 2026-09-27).
//
// WRITTEN BEFORE THE IMPLEMENTATION. Paths are real, from Adityavanjre/Project-K and the
// 119-repo A/B samples.
//
// I.2 — a skill directory with a package manifest beside its SKILL.md is an APPLICATION that
// carries a skill at its root. Its own docs are not agent instructions: 7 of 7 findings under
// such directories were false (gstack design docs, CHANGELOG, TODOS). Only the Agent Skills
// layout counts there. Every other skill directory keeps today's rule — 2,824 real support
// files, many in `templates/`, `resources/`, `examples/`, `docs/`, must not move.
//
// I.1 — under `pull_request_target` the Action must say it did not scan, not scan the base.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { parse as parseYaml } from 'yaml';
import {
  skillDirsOf,
  appSkillDirsOf,
  isSkillSupportFile,
  isInstructionFile,
} from '../ci-check/instructions';
import { selectSurface } from '../ci-check/fetch';

const G = 'integrations/gstack';
const V = 'integrations/claude-code-harness/skills/generate-video';

describe('I.2 — an application with a SKILL.md at its root is not one big skill', () => {
  const listing = [
    `${G}/SKILL.md`,
    `${G}/package.json`,
    `${G}/CHANGELOG.md`,
    `${G}/TODOS.md`,
    `${G}/CLAUDE.md`,
    `${G}/docs/designs/GCOMPACTION.md`,
    `${G}/docs/designs/ML_PROMPT_INJECTION_KILLER.md`,
    `${G}/references/usage.md`,
    `${G}/autoplan/SKILL.md`, // a nested ordinary skill inside the app
    `${G}/autoplan/notes.md`,
    `${V}/SKILL.md`,
    `${V}/package.json`,
    `${V}/references/prompts.md`,
    `${V}/templates/scene.md`,
    `${V}/src/README.md`,
    `${V}/tests/fixtures/case.md`,
    '.claude/skills/deploy/SKILL.md', // an ordinary skill, no manifest
    '.claude/skills/deploy/docs/runbook.md',
    '.claude/skills/deploy/rules/style.md',
  ];
  const dirs = skillDirsOf(listing);
  const apps = appSkillDirsOf(listing, dirs);

  it('recognises exactly the directories with a manifest beside the SKILL.md', () => {
    expect([...apps].sort()).toEqual([V, G].sort());
  });

  it("the app's own docs are not support files", () => {
    for (const p of [
      `${G}/CHANGELOG.md`,
      `${G}/TODOS.md`,
      `${G}/docs/designs/GCOMPACTION.md`,
      `${G}/docs/designs/ML_PROMPT_INJECTION_KILLER.md`,
      `${V}/src/README.md`,
      `${V}/tests/fixtures/case.md`,
    ]) {
      expect(isSkillSupportFile(p, dirs, apps), p).toBe(false);
    }
  });

  it('the Agent Skills layout under an app-root skill still counts', () => {
    for (const p of [
      `${G}/references/usage.md`,
      `${V}/references/prompts.md`,
      `${V}/templates/scene.md`,
    ]) {
      expect(isSkillSupportFile(p, dirs, apps), p).toBe(true);
    }
  });

  it('a nested ordinary skill inside the app keeps the ordinary rule', () => {
    expect(isSkillSupportFile(`${G}/autoplan/notes.md`, dirs, apps)).toBe(true);
  });

  it('an ordinary skill is unchanged: docs/ and rules/ are still support files', () => {
    expect(isSkillSupportFile('.claude/skills/deploy/docs/runbook.md', dirs, apps)).toBe(true);
    expect(isSkillSupportFile('.claude/skills/deploy/rules/style.md', dirs, apps)).toBe(true);
  });

  it("the app's CLAUDE.md is still an always-loaded instruction file", () => {
    expect(isInstructionFile(`${G}/CLAUDE.md`, dirs)).toBe(true);
  });

  it('the ONE selector applies it (so all three readers agree)', () => {
    const picked = selectSurface(listing);
    expect(picked).not.toContain(`${G}/docs/designs/GCOMPACTION.md`);
    expect(picked).not.toContain(`${G}/CHANGELOG.md`);
    expect(picked).toContain(`${G}/references/usage.md`);
    expect(picked).toContain(`${G}/CLAUDE.md`);
    expect(picked).toContain('.claude/skills/deploy/docs/runbook.md');
  });
});

describe('I.1 — action.yml says node9 did not run under pull_request_target', () => {
  const action = parseYaml(
    fs.readFileSync(path.resolve(__dirname, '../../action.yml'), 'utf8')
  ) as {
    runs: {
      steps: {
        id?: string;
        name?: string;
        if?: string;
        env?: Record<string, string>;
        run?: string;
      }[];
    };
  };
  const steps = action.runs.steps;
  const guardIdx = steps.findIndex((s) => s.id === 'guard');

  it('has a guard step first, which recognises pull_request_target', () => {
    expect(guardIdx).toBe(0);
    expect(steps[0].run).toMatch(/pull_request_target/);
  });

  it('every step that checks out, fetches or scans is gated on the guard', () => {
    // Node and the comment step always run: comment.js must report the skip.
    const alwaysRun = new Set(['Comment + gate', 'Set up Node']);
    for (const s of steps.slice(1)) {
      if (alwaysRun.has(s.name ?? '')) continue;
      expect(s.if ?? '', s.name).toMatch(/steps\.guard\.outputs\.skip == ''/);
    }
  });

  it('Set up Node is not gated (comment.js needs it to report the skip)', () => {
    expect(steps.find((s) => s.name === 'Set up Node')?.if).toBeUndefined();
  });

  it('the comment step always runs and is told why the scan was skipped', () => {
    const c = steps.find((s) => s.name === 'Comment + gate');
    expect(c?.if).toBeUndefined();
    expect(c?.env?.NODE9_SKIPPED).toMatch(/steps\.guard\.outputs\.skip/);
  });
});
