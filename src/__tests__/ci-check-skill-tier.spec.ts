// T.8 — a skill's grant counts when it meets text strangers write (2026-10-11). Most skill
// grants are what the skill needs, so CI-1.skill-allowed-tools stays review-tier. In a skill of
// the repository's own agent surface, a grant that runs code (or edits and runs git/gh) next to
// PR, issue or web text is CI-1.skill-untrusted-input: advisory, counted.

import { describe, it, expect } from 'vitest';
import { scanTree } from '../ci-check';
import { isAlert } from '../ci-check/tier';

const skill = (path: string, tools: string, body: string) =>
  scanTree({
    source: 'owner/repo',
    notes: [],
    files: [{ path, content: `---\nname: x\nallowed-tools: ${tools}\n---\n\n${body}\n` }],
  }).findings;
const counted = (path: string, tools: string, body: string) =>
  skill(path, tools, body)
    .filter(isAlert)
    .map((f) => `${f.rule}:${f.severity}`);

describe('T.8 — counted', () => {
  it('an interpreter grant in a skill that reads a community PR', () => {
    expect(
      counted(
        '.agents/skills/pr-check/SKILL.md',
        'Bash(gh:*), Bash(git:*), Bash(node:*), Read',
        'Run `gh pr view <number> --json title,body` and decide.'
      )
    ).toEqual(['CI-1.skill-untrusted-input:advisory']);
  });

  it('a bare shell in a skill that searches the web', () => {
    expect(
      counted(
        '.claude/skills/research/SKILL.md',
        'Bash, Read, WebSearch',
        'Summarise what people say.'
      )
    ).toEqual(['CI-1.skill-untrusted-input:advisory']);
  });

  it('Write/Edit with git and gh in a skill that reviews a PR diff', () => {
    expect(
      counted(
        '.claude/skills/review/SKILL.md',
        'Read, Write, Edit, Bash(git:*), Bash(gh:*)',
        'Read the diff with `gh pr diff` and fix what you find.'
      )
    ).toEqual(['CI-1.skill-untrusted-input:advisory']);
  });
});

describe('T.8 — not counted', () => {
  it('a bare shell over the repository only', () => {
    expect(counted('.claude/skills/build/SKILL.md', 'Bash, Read', 'Run the tests.')).toEqual([]);
  });

  it('git and gh alone on the maintainer branch', () => {
    expect(
      counted(
        '.agents/skills/create-pr/SKILL.md',
        'Bash(git:*), Bash(gh:*)',
        'Open a PR for this branch.'
      )
    ).toEqual([]);
  });

  it('a skill catalogue outside the root agent surface', () => {
    expect(
      counted('skills/pr-comments/SKILL.md', 'Bash(gh *), Bash(node *)', 'Run `gh pr view` first.')
    ).toEqual([]);
  });
});
