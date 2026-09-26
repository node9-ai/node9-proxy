// PR-A corpus: tool grants in skills and slash commands, and the lowercase skill.md.
//
// WRITTEN BEFORE THE IMPLEMENTATION (CLAUDE.md: corpus before code). Fixtures are real
// files fetched from public repositories on 2026-09-26; the synthetic rows are edits of
// those files, never invented shapes.
//
// The load-bearing distinctions:
//   1. `allowed-tools:` in a SKILL.md or a slash command is a PRE-AUTHORIZATION ("tools
//      Claude may use without asking while this is active") and is graded by the SAME law
//      as `permissions.allow` in settings.json — one predicate, two containers.
//   2. `tools:` in a subagent is SCOPE, not authorization: permission prompts still apply.
//      It must not fire. ~218k committed subagents; noise here is how a gate gets muted.
//   3. `skill.md` (lowercase) is loaded on every contributor Mac and Windows box, so the
//      scanner must see it, without making CLAUDE.md/AGENTS.md matching case-insensitive.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanTree } from '../ci-check';
import { parseFrontmatter, allowedToolsOf } from '../ci-check/frontmatter';
import { analyzeAgentConfig, analyzeSkillGrants, gradeBroadGrant } from '../ci-check/agent-config';
import { INSTRUCTION_FILE_RE, skillDirsOf, isSkillSupportFile } from '../ci-check/instructions';
import { selectSurface } from '../ci-check/fetch';
import type { RepoFile } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check');
const fx = (name: string) => fs.readFileSync(path.join(FX, name), 'utf8');
const scan = (files: RepoFile[]) => scanTree({ source: 'owner/repo', files, notes: [] });
const grants = (files: RepoFile[]) =>
  scan(files).findings.filter((f) => f.rule === 'CI-1.skill-allowed-tools');

/** Replace the allowed-tools value in a real fixture, keeping everything else real. */
const withAllowedTools = (content: string, value: string) =>
  content.replace(/^allowed-tools:.*(\n {2}- .*)*$/m, `allowed-tools: ${value}`);

describe('frontmatter — the three real shapes of allowed-tools', () => {
  it('comma-separated (Jesseovo/last30days-skill-cn)', () => {
    const fm = parseFrontmatter(fx('last30days-SKILL.md'));
    expect(allowedToolsOf(fm)).toEqual(['Bash', 'Read', 'Write', 'WebSearch']);
  });

  it('YAML list (op7418/Claude-to-IM-skill)', () => {
    const fm = parseFrontmatter(fx('claude-to-im-SKILL.md'));
    expect(allowedToolsOf(fm)).toEqual([
      'Bash',
      'Read',
      'Write',
      'Edit',
      'AskUserQuestion',
      'Grep',
      'Glob',
    ]);
  });

  it('a malformed sibling line does not lose allowed-tools (moltis-org/moltis, real)', () => {
    // `argument-hint: ["<commit message>"] ["<pr title>"] ["<pr body>"]` is not valid YAML
    // (three flow sequences on one line) and strict parsing throws on the whole block. The
    // grant is on its own well-formed line and must still be read: a scanner that drops a
    // real file's grant because a neighbouring line is sloppy is a silent miss.
    const fm = parseFrontmatter(fx('moltis-ship-command.md'));
    expect(fm).not.toBeNull();
    expect(allowedToolsOf(fm)).toContain('Bash(git rev-parse:*)');
    expect(allowedToolsOf(fm)).toContain('Read');
    // …and the salvage path handles the list form too.
    const listy = '---\nname: x\nargument-hint: [a] [b]\nallowed-tools:\n  - Bash\n  - Read\n---\n';
    expect(allowedToolsOf(parseFrontmatter(listy))).toEqual(['Bash', 'Read']);
  });

  it('space-separated (the Agent Skills spec form)', () => {
    const fm = parseFrontmatter(
      '---\nname: x\nallowed-tools: Read Write Edit Bash WebSearch\n---\n# x\n'
    );
    expect(allowedToolsOf(fm)).toEqual(['Read', 'Write', 'Edit', 'Bash', 'WebSearch']);
  });

  it('a scoped grant keeps its parentheses whole', () => {
    // `Bash(git status:*)` contains a space inside the parens; splitting on whitespace
    // would produce `Bash(git` and `status:*)` and the predicate would see a bare Bash.
    const fm = parseFrontmatter('---\nallowed-tools: Bash(git status:*) Read\n---\n');
    expect(allowedToolsOf(fm)).toEqual(['Bash(git status:*)', 'Read']);
  });

  it('no frontmatter, malformed frontmatter, or no field → empty, never a throw', () => {
    expect(parseFrontmatter('# just a heading\n')).toBeNull();
    expect(allowedToolsOf(parseFrontmatter('---\n: : not yaml [\n---\n'))).toEqual([]);
    expect(allowedToolsOf(parseFrontmatter('---\nname: x\n---\n'))).toEqual([]);
    expect(allowedToolsOf(null)).toEqual([]);
  });
});

describe('ONE broad-grant law — settings.json and skills cannot drift', () => {
  it('is the predicate analyzeAgentConfig uses: the sentry/glances fixtures grade as before', () => {
    // These two real settings.json fixtures already have asserted severities in
    // ci-check.spec.ts. If the extraction changed the law, they would move.
    const sentry = analyzeAgentConfig('.claude/settings.json', fx('sentry-settings.json'));
    const glances = analyzeAgentConfig('.claude/settings.json', fx('glances-settings.json'));
    const broad = (f: ReturnType<typeof analyzeAgentConfig>) =>
      f.find((x) => x.rule === 'CI-1.broad-allow')?.severity ?? null;
    expect(broad(sentry)).toBe(null);
    expect(broad(glances)).toBe(null);
  });

  it('bare Bash with no deny → high; scoped Bash → nothing; Write/Edit → medium', () => {
    expect(gradeBroadGrant(['Bash'], [])?.high).toBe(true);
    expect(gradeBroadGrant(['Bash(*)'], [])?.high).toBe(true);
    expect(gradeBroadGrant(['Bash(git status:*)', 'Read'], [])).toBeNull();
    const we = gradeBroadGrant(['Write', 'Edit'], []);
    expect(we?.high).toBe(false);
    expect(we?.broad).toEqual(['Write', 'Edit']);
  });
});

describe('CI-1.skill-allowed-tools — a skill that pre-authorizes broad tools', () => {
  it('real: last30days-skill-cn grants a bare Bash → high, one finding, file-level', () => {
    const f = grants([
      { path: '.claude/skills/last30days/SKILL.md', content: fx('last30days-SKILL.md') },
    ]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].check).toBe('CI-1');
    expect(f[0].locator ?? '').toBe('');
    expect(f[0].signals.join(' ')).toMatch(/Bash/);
  });

  it('real: Claude-to-IM (YAML list with Bash) → high', () => {
    const f = grants([
      { path: '.claude/skills/im/SKILL.md', content: fx('claude-to-im-SKILL.md') },
    ]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
  });

  it('the same skill with a scoped grant → no finding', () => {
    const scoped = withAllowedTools(fx('last30days-SKILL.md'), 'Bash(git status:*) Read');
    expect(grants([{ path: '.claude/skills/last30days/SKILL.md', content: scoped }])).toHaveLength(
      0
    );
  });

  it('the same skill granting only Write and Edit → medium, like settings.json', () => {
    const we = withAllowedTools(fx('last30days-SKILL.md'), 'Write, Edit');
    const f = grants([{ path: '.claude/skills/last30days/SKILL.md', content: we }]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('medium');
  });

  it('a slash command with allowed-tools is graded the same way', () => {
    const cmd = '---\nallowed-tools: Bash\ndescription: ship it\n---\nRun the release.\n';
    const f = grants([{ path: '.claude/commands/ship.md', content: cmd }]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].file).toBe('.claude/commands/ship.md');
  });

  it('real: moltis-org/moltis ship command scopes every Bash grant → no finding', () => {
    // `Bash(git status:*), Bash(gh pr create:*), Bash(./scripts/ship-pr.sh:*), Read` — nine
    // scoped grants and a read. This is what a well-written command looks like; it is the
    // cry-wolf guard for this rule, and the comma-split must keep each `Bash(...)` whole.
    const content = fx('moltis-ship-command.md');
    expect(allowedToolsOf(parseFrontmatter(content))).toContain('Bash(git rev-parse:*)');
    expect(gradeBroadGrant(allowedToolsOf(parseFrontmatter(content)), [])).toBeNull();
    expect(grants([{ path: '.claude/commands/ship.md', content }])).toHaveLength(0);
  });

  it('real: a subagent with `tools: Read, Bash, Glob, Grep, Task` is SCOPE → no finding', () => {
    // pgplex/pgschema/.claude/agents/plan.md. Permission prompts still apply to a
    // subagent; the repo's settings.json decides whether Bash runs unprompted, and CI-1
    // already grades that file.
    const files = [{ path: '.claude/agents/plan.md', content: fx('pgschema-plan-agent.md') }];
    expect(grants(files)).toHaveLength(0);
    expect(analyzeSkillGrants('.claude/agents/plan.md', fx('pgschema-plan-agent.md'))).toHaveLength(
      0
    );
  });

  it('a CLAUDE.md with an allowed-tools line in its prose is not a grant', () => {
    // Only a SKILL.md or a command carries the field with that meaning.
    const md = '---\nallowed-tools: Bash\n---\n# Project notes\n';
    expect(grants([{ path: 'CLAUDE.md', content: md }])).toHaveLength(0);
  });

  it('identity: same skill re-worded elsewhere keeps its fingerprint (CI-5 contract)', () => {
    const a = grants([
      { path: '.claude/skills/x/SKILL.md', content: fx('last30days-SKILL.md') },
    ])[0];
    const b = grants([
      {
        path: '.claude/skills/x/SKILL.md',
        content: fx('last30days-SKILL.md') + '\n\nMore prose.\n',
      },
    ])[0];
    expect(a.rule).toBe(b.rule);
    expect(a.file).toBe(b.file);
    expect(a.locator ?? '').toBe(b.locator ?? '');
  });
});

describe('lowercase skill.md (talmolab/sleap) is surface on the machines that load it', () => {
  const P = '.claude/skills/pr/skill.md';

  it('matches the instruction-file law', () => {
    expect(INSTRUCTION_FILE_RE.test(P)).toBe(true);
    expect(INSTRUCTION_FILE_RE.test('.claude/skills/pr/SKILL.md')).toBe(true);
  });

  it('does NOT make the always-loaded files case-insensitive', () => {
    expect(INSTRUCTION_FILE_RE.test('claude.md')).toBe(false);
    expect(INSTRUCTION_FILE_RE.test('agents.md')).toBe(false);
    expect(INSTRUCTION_FILE_RE.test('docs/Skill.md')).toBe(true); // any case of the skill file itself
  });

  it('defines a skill directory, so its support files are surface too', () => {
    const dirs = skillDirsOf([P, '.claude/skills/pr/checklist.md']);
    expect(dirs.has('.claude/skills/pr')).toBe(true);
    expect(isSkillSupportFile('.claude/skills/pr/checklist.md', dirs)).toBe(true);
    expect(isSkillSupportFile(P, dirs)).toBe(false); // the entry point is not its own support file
  });

  it('is selected by the ONE selector and routed to CI-6 by scanTree', () => {
    expect(selectSurface([P, 'README.md'])).toEqual([P]);
    const res = scan([{ path: P, content: fx('sleap-pr-skill-lowercase.md') }]);
    expect(res.inspected).toContain(P);
    // The real sleap skill is benign: it must produce no CI-6 finding.
    expect(res.findings.filter((f) => f.check === 'CI-6')).toHaveLength(0);
  });
});
