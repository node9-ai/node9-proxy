// Withdrawn vendor guidance (node9Firewall#454 step 1): an installed skill that
// still carries guidance its vendor removed from its own copy. Synthetic
// fixtures shaped like Render's render-deploy skill before its 2026-08-14 fix.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../../config', async () => {
  const actual = await vi.importActual<typeof import('../../config')>('../../config');
  return { ...actual, getConfig: () => actual.DEFAULT_CONFIG };
});

import { checkInstructionFiles } from '../instruction-files';
import { analyzeInstructionFile, analyzeWithdrawnGuidance } from '../../ci-check/instructions';
import { scanTree } from '../../ci-check';

const STALE = [
  '# Private services',
  '',
  'Private services are reachable at `<name>.render-internal.com`.',
  'Example: http://internal-api.render-internal.com:10000',
  'Always use .render-internal.com domains for service-to-service calls.',
].join('\n');

const FIXED = [
  '# Private services',
  '',
  'Private services are reachable on the private network by their internal hostname.',
  'See https://render.com/docs/private-network for details.',
].join('\n');

const ROW = /guidance (its|their) vendor withdrew/;
const RULE = 'CI-6.withdrawn-guidance';
// A note that names the domain in prose, as a research note or a changelog does.
const NOTE = 'Render removed render-internal.com from its deploy skill on 2026-08-14.';

let home: string;
let cwd: string;

function write(root: string, rel: string, text: string): void {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-withdrawn-'));
  cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-withdrawn-proj-'));
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(cwd, { recursive: true, force: true });
});

describe('CI-6.withdrawn-guidance (shared by scan-repo and posture)', () => {
  it('reports one finding per file, at the first mention, with the count', () => {
    const hits = analyzeWithdrawnGuidance(
      'skills/render-deploy/references/service-types.md',
      STALE
    );
    expect(hits).toHaveLength(1);
    expect(hits[0].line).toBe(3);
    expect(hits[0].severity).toBe('medium');
    expect(hits[0].signals[0]).toMatch(/^3 mentions/);
  });

  it("stays silent on the vendor's fixed text and on look-alike words", () => {
    const rule = (t: string) => analyzeWithdrawnGuidance('SKILL.md', t);
    expect(rule(FIXED)).toHaveLength(0);
    expect(rule('Deploy to render.com; use internal hostnames.')).toHaveLength(0);
    expect(rule('See myrender-internal.company.dev')).toHaveLength(0);
  });
});

// 2.66.0 ran the rule inside analyzeInstructionFile, so every instruction file that
// names the domain was reported as a stale skill (three memory notes on the founder's
// machine). The rule is for skill files only, and the caller decides what one is.
describe('CI-6.withdrawn-guidance applies to skill files only', () => {
  it('is not part of the general instruction-file rules', () => {
    for (const p of ['CLAUDE.md', 'AGENTS.md', '.claude/commands/deploy.md'])
      expect(analyzeInstructionFile(p, STALE).filter((h) => h.rule === RULE)).toHaveLength(0);
  });

  it('scan-repo flags the files of a skill, wherever the skill sits, and no other file', () => {
    const tree = {
      source: 'fixture',
      notes: [],
      files: [
        // A skill at the repository root: no "skills" folder in the path.
        { path: 'render-deploy/SKILL.md', content: '# Render deploy\n\nSee references/.' },
        { path: 'render-deploy/references/service-types.md', content: STALE },
        { path: 'skills/.curated/render-deploy/SKILL.md', content: '# Render deploy' },
        { path: 'skills/.curated/render-deploy/references/service-types.md', content: STALE },
        { path: 'CLAUDE.md', content: NOTE },
        { path: 'AGENTS.md', content: STALE },
      ],
    };
    const hits = scanTree(tree).findings.filter((f) => f.rule === RULE);
    expect(hits.map((f) => f.file).sort()).toEqual([
      'render-deploy/references/service-types.md',
      'skills/.curated/render-deploy/references/service-types.md',
    ]);
  });
});

describe('posture: installed skills with withdrawn guidance', () => {
  it('does not report memory notes, CLAUDE.md, agents or commands that name the text', async () => {
    write(home, '.claude/projects/-home-u/memory/research-note.md', NOTE);
    write(home, '.claude/CLAUDE.md', NOTE);
    write(home, '.codex/AGENTS.md', STALE);
    write(home, '.claude/commands/deploy.md', STALE);
    write(home, '.claude/agents/deployer.md', STALE);
    const findings = await checkInstructionFiles({ home, cwd });
    expect(findings.some((f) => ROW.test(f.title))).toBe(false);
  });

  it('reads the layout the desktop app syncs skills into, and external plugins', async () => {
    const rel = 'render-deploy/references/service-types.md';
    write(home, `.claude/skills/synced/bucket-1/${rel}`, STALE);
    write(home, `.claude/plugins/marketplaces/m/external_plugins/p/skills/${rel}`, STALE);
    const row = (await checkInstructionFiles({ home, cwd })).find((f) => ROW.test(f.title));
    expect(row).toBeDefined();
    expect(row!.detail).toHaveLength(2);
  });

  it('counts a file once when the project folder is the home folder', async () => {
    write(home, '.claude/skills/render-deploy/references/service-types.md', STALE);
    const row = (await checkInstructionFiles({ home, cwd: home })).find((f) => ROW.test(f.title));
    expect(row!.detail).toHaveLength(1);
  });

  it('finds a stale copy in every skill folder agents load', async () => {
    const rel = 'render-deploy/references/service-types.md';
    write(home, `.claude/skills/${rel}`, STALE);
    write(home, `.codex/skills/${rel}`, STALE);
    write(home, `.agents/skills/${rel}`, STALE);
    write(home, `.claude/plugins/marketplaces/m/plugins/p/skills/${rel}`, STALE);
    write(cwd, `.claude/skills/${rel}`, STALE);
    write(cwd, `.agents/skills/${rel}`, STALE);
    const findings = await checkInstructionFiles({ home, cwd });
    const row = findings.find((f) => ROW.test(f.title));
    expect(row).toBeDefined();
    expect(row!.detail).toHaveLength(6);
    expect(row!.owner).toBe('os');
    // Never reported as hidden or suspicious content.
    expect(findings.some((f) => /hidden or suspicious/.test(f.title))).toBe(false);
  });

  it('shows no row when every copy carries the fixed text', async () => {
    write(home, '.claude/skills/render-deploy/references/service-types.md', FIXED);
    write(home, '.codex/skills/render-deploy/references/service-types.md', FIXED);
    const findings = await checkInstructionFiles({ home, cwd });
    expect(findings.some((f) => ROW.test(f.title))).toBe(false);
  });

  it('never puts the skill text in the row, only file and line', async () => {
    write(home, '.codex/skills/render-deploy/references/service-types.md', STALE);
    const row = (await checkInstructionFiles({ home, cwd })).find((f) => ROW.test(f.title))!;
    const all = JSON.stringify(row);
    expect(all).not.toContain('internal-api');
    expect(row.detail[0]).toMatch(/service-types\.md \(line 3\)/);
  });
});
