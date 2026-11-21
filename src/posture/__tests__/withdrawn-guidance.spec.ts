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
import { analyzeInstructionFile } from '../../ci-check/instructions';

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

const ROW = /guidance its vendor withdrew/;

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
    const hits = analyzeInstructionFile(
      'skills/render-deploy/references/service-types.md',
      STALE
    ).filter((h) => h.rule === 'CI-6.withdrawn-guidance');
    expect(hits).toHaveLength(1);
    expect(hits[0].line).toBe(3);
    expect(hits[0].severity).toBe('medium');
    expect(hits[0].signals[0]).toMatch(/^3 mentions/);
  });

  it("stays silent on the vendor's fixed text and on look-alike words", () => {
    const rule = (t: string) =>
      analyzeInstructionFile('SKILL.md', t).filter((h) => h.rule === 'CI-6.withdrawn-guidance');
    expect(rule(FIXED)).toHaveLength(0);
    expect(rule('Deploy to render.com; use internal hostnames.')).toHaveLength(0);
    expect(rule('See myrender-internal.company.dev')).toHaveLength(0);
  });
});

describe('posture: installed skills with withdrawn guidance', () => {
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
