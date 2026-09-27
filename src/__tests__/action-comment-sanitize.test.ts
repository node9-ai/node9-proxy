// P3 — repo text cannot rewrite the PR comment (design: scanner-gaps-code-design.md §P;
// 2026-09-27). WRITTEN BEFORE THE FIX.
//
// A finding carries text from the scanned repository: its file path, and inside its title and
// signals an MCP server name, a permission entry, a workflow trigger, a command. Quoted as-is,
// that text could forge a header ("### ✅ node9: looks good"), hide the rest of the comment
// (`<!--`), ping a team (@org/team), break out of a code span (a backtick in a file name), or —
// in an Actions annotation — start a new workflow command (a newline in `file=`). All of it is
// now made inert in ONE place, when the comment, the check-run and the annotations are rendered.
// Several of these existed in 2.24.2 too.

import { describe, it, expect } from 'vitest';
import path from 'path';
import { createRequire } from 'module';
import { renderScanMarkdown } from '../ci-check/render';
import type { ScanResult } from '../ci-check/types';

const c = createRequire(__filename)(path.resolve(__dirname, '../../comment.js')) as {
  renderComment: (r: object) => string;
  annotationLines: (r: object) => string[];
};

const FORGE = '\n\n### ✅ node9: looks good\n<!--';
const PING = ' **node9: all clear** @node9-ai/security <!--';
const finding = (over: object) => ({
  check: 'CI-3',
  rule: 'CI-3.mcp-unpinned',
  severity: 'high',
  title: 'MCP server',
  file: '.mcp.json',
  signals: ['s'],
  fix: 'Pin it.',
  ...over,
});
const result = (f: object) =>
  ({
    source: 'x',
    findings: [f],
    inspected: ['.mcp.json'],
    notes: [],
    worst: 'high',
    incomplete: false,
  }) as unknown as ScanResult;

// What a reader would see as markdown structure: code spans removed, their text is literal.
const outsideCode = (md: string) => md.replace(/`[^`\n]*`/g, '');
const renders = (r: ScanResult) => [c.renderComment(r), renderScanMarkdown(r)];

describe('P3 — repo text in a finding renders inert, in the comment and the CLI markdown', () => {
  it('an MCP server name in the title cannot forge a header or hide the rest', () => {
    for (const md of renders(result(finding({ title: `Unpinned MCP server "x${FORGE}"` })))) {
      expect(md).not.toMatch(/^### ✅ node9: looks good/m);
      expect(md.split('<!--').length).toBeLessThanOrEqual(2); // at most the sticky marker
    }
  });

  it('a permission entry in a signal cannot ping a team or hide the rest', () => {
    for (const md of renders(result(finding({ signals: [`broad allow(s): Bash(*)${PING}`] })))) {
      expect(outsideCode(md)).not.toMatch(/@node9-ai\/security/);
      expect(md.split('<!--').length).toBeLessThanOrEqual(2);
    }
  });

  it('a workflow trigger name in a signal cannot forge a header', () => {
    const f = finding({ check: 'CI-2', signals: [`runs with base-repo secrets (target${FORGE})`] });
    for (const md of renders(result(f))) expect(md).not.toMatch(/^### ✅ node9: looks good/m);
  });

  it('a file name with a backtick cannot break out of its code span', () => {
    const f = finding({ file: 'a` **node9 all clear** @node9-ai <!--.yml' });
    for (const md of renders(result(f))) {
      expect(outsideCode(md)).not.toContain('node9 all clear');
      expect(outsideCode(md)).not.toMatch(/@node9-ai/);
    }
  });

  it('an annotation file= with a newline cannot start a second workflow command', () => {
    const f = finding({
      file: 'x\n::error title=node9 all clear::forged\n',
      title: 'T\n::stop-commands::t',
    });
    const lines = c.annotationLines(result(f)).join('\n').split('\n');
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^::error file=/);
    expect(lines[0]).not.toMatch(/::error title=node9 all clear/);
  });

  it('ordinary text is unchanged', () => {
    const f = finding({
      title: 'Unpinned MCP server "fs"',
      signals: ['`npx -y pkg@latest` — unversioned'],
    });
    const md = c.renderComment(result(f));
    expect(md).toContain('Unpinned MCP server "fs"');
    expect(md).toContain('`npx -y pkg@latest` — unversioned');
  });
});
