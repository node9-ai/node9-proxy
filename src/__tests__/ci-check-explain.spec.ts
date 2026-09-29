// R: every finding a reader is likely to meet says, in plain words, what is wrong, what can
// happen, what was seen and how to fix it (design: scanner-gaps-code-design.md §R; 2026-09-28).
// The signals stay the technical record; `explain` is built from the analyzer's facts, never
// parsed back out of the signals.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import { scanTree } from '../ci-check';
import { npxPackage } from '../ci-check/explain';
import { renderScan, renderScanMarkdown } from '../ci-check/render';
import type { CiFinding, RepoTree } from '../ci-check/types';

const comment = createRequire(__filename)(path.resolve(__dirname, '../../comment.js')) as {
  renderComment: (r: object) => string;
};

const tree = (files: Record<string, string>): RepoTree => ({
  source: 'fixture',
  files: Object.entries(files).map(([p, content]) => ({ path: p, content })),
  notes: [],
});
const scan = (files: Record<string, string>) => scanTree(tree(files));
const find = (files: Record<string, string>, rule: string): CiFinding => {
  const f = scan(files).findings.find((x) => x.rule === rule);
  if (!f) throw new Error(`no ${rule}`);
  return f;
};
const FX = (n: string) => fs.readFileSync(path.join(__dirname, 'fixtures', 'ci-check', n), 'utf8');

/** hive's real issue-triage shape: anyone can open an issue and start the agent, which has
 *  no shell and no extra secrets. */
const TRIAGE = (star: boolean) => `on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
${star ? '          allowed_non_write_users: "*"\n' : ''}          prompt: |
            Triage issue #\${{ github.event.issue.number }}.
`;

const settings = (allow: string[], deny: string[] = []) =>
  JSON.stringify({ permissions: { allow, deny } });

/** Every part is there, plain, and bounded. */
function wellFormed(f: CiFinding) {
  const ex = f.explain!;
  expect(ex, f.rule).toBeDefined();
  expect(ex.headline.length).toBeGreaterThan(10);
  expect(ex.happens.length).toBeGreaterThan(20);
  expect(ex.saw.length).toBeGreaterThan(0);
  expect(ex.fix.length).toBeGreaterThan(0);
  expect(ex.fix.length).toBeLessThanOrEqual(4);
  for (const s of [ex.headline, ex.happens, ...ex.saw, ...ex.fix]) {
    expect(s).not.toContain('—');
    expect(s).not.toMatch(/undefined|null|\[object/);
    expect((s.match(/`/g) ?? []).length % 2, s).toBe(0); // code spans closed
  }
}

describe('R: an injectable agent workflow, at each severity', () => {
  it('critical: anyone, with secrets, on the stranger files, with a shell', () => {
    const f = find(
      { '.github/workflows/review.yml': FX('injectable-pr-target.yml') },
      'CI-2.injectable-workflow'
    );
    expect(['critical', 'high']).toContain(f.severity);
    wellFormed(f);
    expect(f.explain!.headline).toMatch(/^Anyone can make this repository's AI agent act/);
    expect(f.explain!.saw.join('\n')).toMatch(/secrets/);
    expect(f.explain!.fix[0]).toMatch(/write access/);
  });

  it('medium: anyone can steer it, and it says what limits the damage (hive)', () => {
    const f = find({ '.github/workflows/triage.yml': TRIAGE(true) }, 'CI-2.injectable-workflow');
    expect(f.severity).toBe('medium');
    wellFormed(f);
    expect(f.explain!.headline).toMatch(/with limited power/);
    expect(f.explain!.happens).toMatch(/an issue/);
    expect(f.explain!.happens).toMatch(/What limits the damage: it cannot run commands/);
    expect(f.explain!.saw[0]).toMatch(/allowed_non_write_users/);
  });

  it('advisory: held by the action default gate, so protected today', () => {
    // A real claude.yml from the 768-repo run: untrusted triggers, write permissions, and
    // claude-code-action's default write-access gate.
    const f = find(
      { '.github/workflows/claude.yml': FX('claude-default-gated.yml') },
      'CI-2.injectable-workflow'
    );
    expect(f.severity).toBe('advisory');
    wellFormed(f);
    expect(f.explain!.headline).toBe('An AI agent workflow that is protected today');
    expect(f.explain!.fix).toEqual(['Nothing to do now. Keep the check on who can start it.']);
  });
});

describe('R: a note never contradicts what it saw', () => {
  it('a stranger can start it but it can do little: says so, not "cannot start" (codex-cli)', () => {
    const f = find(
      { '.github/workflows/issue-labeler.yml': FX('codex-issue-labeler.yml') },
      'CI-2.injectable-workflow'
    );
    expect(f.severity).toBe('advisory');
    wellFormed(f);
    expect(f.explain!.headline).toMatch(/but it can do very little/);
    expect(f.explain!.headline).not.toMatch(/cannot start/);
  });
});

describe('R: secrets the agent can reach', () => {
  it('names the secrets and says how they leak', () => {
    const f = find(
      { '.github/workflows/review.yml': FX('injectable-pr-target.yml') },
      'CI-4.agent-reachable-secret'
    );
    wellFormed(f);
    expect(f.explain!.saw[0]).toMatch(/^It can read `/);
  });
});

describe('R: broad permissions in a committed settings file', () => {
  it('an unrestricted shell with no deny list', () => {
    const f = find({ '.claude/settings.json': settings(['Bash(*)', 'Edit']) }, 'CI-1.broad-allow');
    wellFormed(f);
    expect(f.explain!.headline).toBe('Agents in this repository run commands without asking');
    expect(f.explain!.happens).toMatch(/at once/);
  });

  it('git and edit only: says what it allows, not "run commands"', () => {
    const f = find(
      { '.claude/settings.json': settings(['Bash(git:*)', 'Edit']) },
      'CI-1.broad-allow'
    );
    wellFormed(f);
    expect(f.explain!.headline).toBe(
      'Agents in this repository run git commands and change files without asking'
    );
    expect(f.explain!.saw.join('\n')).toMatch(/git can run other programs/);
  });

  it('a template says every project made from it gets the permissions (odk-ai)', () => {
    const f = find(
      { 'template/config/.claude/settings.json': settings(['Bash(*)']) },
      'CI-1.broad-allow'
    );
    wellFormed(f);
    expect(f.explain!.headline).toMatch(/^This template lets agents/);
    expect(f.explain!.saw[0]).toMatch(/every project made from it/);
  });
});

describe('R: an MCP server that is not pinned', () => {
  it('names the package and how to pin it', () => {
    const f = find(
      {
        '.mcp.json': JSON.stringify({
          mcpServers: { pw: { command: 'npx', args: ['-y', '@playwright/mcp@latest'] } },
        }),
      },
      'CI-3.mcp-unpinned'
    );
    wellFormed(f);
    expect(f.explain!.happens).toContain('`@playwright/mcp`');
    expect(f.explain!.fix[0]).toContain('`@playwright/mcp@x.y.z`');
  });

  it('reads the package past npx flags', () => {
    expect(npxPackage('npx -y shadcn@latest mcp')).toBe('shadcn');
    expect(npxPackage('npx --yes -p left-pad @scope/tool@1 run')).toBe('@scope/tool');
    expect(npxPackage('node server.js')).toBeNull();
  });
});

describe('R: repository text stays inside code spans', () => {
  it('a server name with backticks and a line break cannot break out', () => {
    const f = find(
      {
        '.mcp.json': JSON.stringify({
          mcpServers: { 'x`\n**owned** @everyone': { command: 'npx', args: ['evil'] } },
        }),
      },
      'CI-3.mcp-unpinned'
    );
    wellFormed(f);
    expect(f.explain!.headline).not.toContain('\n');
    const md = comment.renderComment(
      scan({
        '.mcp.json': JSON.stringify({
          mcpServers: { 'x`\n**owned** @everyone': { command: 'npx', args: ['evil'] } },
        }),
      })
    );
    // Inside a code span GitHub makes no mention; outside one there must be none.
    expect(md.replace(/`[^`\n]*`/g, '')).not.toContain('@everyone');
  });
});

describe('R: how it reads', () => {
  const res = scan({ '.github/workflows/review.yml': FX('injectable-pr-target.yml') });

  it('the PR comment leads with the plain words and keeps the technical record collapsed', () => {
    const md = comment.renderComment(res);
    const top = md.split('technical details')[0];
    expect(top).toContain("**Anyone can make this repository's AI agent act");
    expect(top).toContain('**What we saw** in `');
    expect(top).toMatch(/\*\*✅ How to fix:\*\*\n1\. /);
    expect(md).toContain('technical details</summary>');
  });

  it('the CLI and the markdown report show the same words', () => {
    const f = res.findings.find((x) => x.rule === 'CI-2.injectable-workflow')!;
    expect(renderScan(res)).toContain(f.explain!.headline);
    const md = renderScanMarkdown(res);
    expect(md).toContain(f.explain!.headline);
    expect(md).toContain('<details><summary>Technical details</summary>');
  });

  it('a finding without explain (an older CLI) renders as before', () => {
    const old = JSON.parse(JSON.stringify(res));
    for (const f of old.findings) delete f.explain;
    const md = comment.renderComment(old);
    expect(md).not.toContain('**What we saw**');
    expect(md).toContain('**✅ Fix**');
  });
});
