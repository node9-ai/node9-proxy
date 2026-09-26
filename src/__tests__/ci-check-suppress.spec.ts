// PR-C corpus: suppressing a finding, and the one property that makes a suppression file
// safe to commit.
//
// WRITTEN BEFORE THE IMPLEMENTATION (CLAUDE.md: corpus before code). The attack row comes
// first because it is the reason the design exists: a suppression file is part of the
// committed agent surface, so whoever can add a finding can add its suppression in the same
// commit. Applied blindly, that pull request is green and the gate is worthless.
//
//   THE RULE: a suppression that did not exist in the base does not apply to a finding
//   introduced in the same change. Silencing something costs a separate, reviewable commit.
//
// A suppressed finding is never deleted from the output: it is marked, counted, and kept out
// of `worst` and the gate. Suppressions are keyed on readable fields (rule + file + locator),
// not the opaque fingerprint, because a file a person edits must be a file a person can read.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanTree } from '../ci-check';
import { diffScans } from '../ci-check/diff';
import { parseSuppressions, suppressionKey, SUPPRESSIONS_FILE } from '../ci-check/suppress';
import { exitCodeFor } from '../ci-check/render';
import { SURFACE_FILES } from '../ci-check/fetch';
import type { RepoFile, ScanResult } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check');
const fx = (name: string) => fs.readFileSync(path.join(FX, name), 'utf8');
const scan = (files: RepoFile[], notes: string[] = []): ScanResult =>
  scanTree({ source: 'owner/repo', files, notes });

const MCP = '.mcp.json';
const unpinned = JSON.stringify({
  mcpServers: { search: { command: 'npx', args: ['-y', '@acme/search-mcp'] } },
});
const suppress = (entries: unknown[]) => ({
  path: SUPPRESSIONS_FILE,
  content: JSON.stringify(entries, null, 2),
});
const ENTRY = {
  rule: 'CI-3.mcp-unpinned',
  file: MCP,
  locator: 'search',
  reason: 'pinned by the devcontainer lockfile; tracked in #412',
};

describe('THE RULE: a suppression added in the same change does not apply', () => {
  it('base clean · head adds the finding AND its suppression → still introduced, unsuppressed', () => {
    const base = scan([{ path: MCP, content: JSON.stringify({ mcpServers: {} }) }]);
    const head = scan([{ path: MCP, content: unpinned }, suppress([ENTRY])]);

    // In isolation the head honours its own file…
    expect(head.findings[0].suppressed).toBeTruthy();
    expect(head.worst).toBeNull();

    // …but against the base, the suppression is new, so the finding is NOT silenced.
    const d = diffScans(base, head);
    expect(d.added).toHaveLength(1);
    expect(d.added[0].suppressed).toBeUndefined();
    expect(d.added[0].signals.join(' ')).toMatch(/suppression .* same change/i);
    expect(d.worstIntroduced).toBe('medium');
  });

  it('base: finding + suppression · head: same → unchanged, suppressed, nothing introduced', () => {
    const files = [{ path: MCP, content: unpinned }, suppress([ENTRY])];
    const d = diffScans(scan(files), scan(files));
    expect(d.added).toHaveLength(0);
    expect(d.unchanged).toHaveLength(1);
    expect(d.unchanged[0].suppressed).toBeTruthy();
    expect(d.worstIntroduced).toBeNull();
  });

  it('base: finding, no suppression · head: adds ONLY the suppression → honoured (a separate commit)', () => {
    const base = scan([{ path: MCP, content: unpinned }]);
    const head = scan([{ path: MCP, content: unpinned }, suppress([ENTRY])]);
    const d = diffScans(base, head);
    expect(d.added).toHaveLength(0);
    expect(d.unchanged).toHaveLength(1);
    expect(d.unchanged[0].suppressed).toBeTruthy();
    expect(d.worstIntroduced).toBeNull();
  });

  it('an escalation cannot be silenced by a suppression added with it', () => {
    const settings = (deny: string[]) =>
      JSON.stringify({ permissions: { allow: ['Bash(*)'], deny } });
    const base = scan([{ path: '.claude/settings.json', content: settings(['Bash(rm:*)']) }]);
    const head = scan([
      { path: '.claude/settings.json', content: settings([]) },
      suppress([{ rule: 'CI-1.broad-allow', file: '.claude/settings.json', reason: 'known' }]),
    ]);
    const d = diffScans(base, head);
    expect(d.escalated).toHaveLength(1);
    expect(d.escalated[0].finding.suppressed).toBeUndefined();
    expect(d.worstIntroduced).toBe('high');
  });

  it('an untrustworthy base honours nothing new either (degrades, never opens)', () => {
    const head = scan([{ path: MCP, content: unpinned }, suppress([ENTRY])]);
    const d = diffScans(null, head);
    expect(d.base).toBe('did-not-run');
    // The absolute answer over UNSUPPRESSED findings: the head honours its own file, so
    // the absolute worst is null — but incomplete stays true and the gate cannot pass.
    expect(d.incomplete).toBe(true);
  });
});

describe('the file: .node9-ignore.json', () => {
  it('is part of the fixed root surface, so every reader carries it', () => {
    expect(SURFACE_FILES).toContain(SUPPRESSIONS_FILE);
  });

  it('is never routed to a content analyzer', () => {
    const res = scan([suppress([ENTRY])]);
    expect(
      res.findings.filter((f) => f.file === SUPPRESSIONS_FILE && f.check === 'CI-6')
    ).toHaveLength(0);
  });

  it('keys on rule + file + locator, readable, not on the fingerprint', () => {
    expect(suppressionKey(ENTRY)).toBe('CI-3.mcp-unpinned\n.mcp.json\nsearch');
    expect(suppressionKey({ ...ENTRY, locator: undefined })).toBe('CI-3.mcp-unpinned\n.mcp.json\n');
  });

  it('a matching entry marks the finding, keeps it in the output, and drops it from worst', () => {
    const res = scan([{ path: MCP, content: unpinned }, suppress([ENTRY])]);
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0].suppressed?.reason).toBe(ENTRY.reason);
    expect(res.worst).toBeNull();
    expect(res.suppressedCount).toBe(1);
    expect(exitCodeFor(res)).toBe(0);
  });

  it('locator must match when given; an entry without a locator matches any locator of that rule+file', () => {
    const two = JSON.stringify({
      mcpServers: {
        search: { command: 'npx', args: ['-y', '@acme/search-mcp'] },
        lookup: { command: 'npx', args: ['-y', '@acme/lookup-mcp'] },
      },
    });
    const narrow = scan([{ path: MCP, content: two }, suppress([ENTRY])]);
    expect(narrow.findings.filter((f) => f.suppressed)).toHaveLength(1);
    expect(narrow.worst).toBe('medium');
    const wide = scan([{ path: MCP, content: two }, suppress([{ ...ENTRY, locator: undefined }])]);
    expect(wide.findings.filter((f) => f.suppressed)).toHaveLength(2);
    expect(wide.worst).toBeNull();
  });

  it('an entry with no reason does not suppress, and is itself an advisory finding', () => {
    const res = scan([
      { path: MCP, content: unpinned },
      suppress([{ rule: ENTRY.rule, file: MCP, locator: 'search' }]),
    ]);
    expect(res.findings.find((f) => f.rule === 'CI-3.mcp-unpinned')?.suppressed).toBeUndefined();
    expect(res.worst).toBe('medium');
    expect(res.findings.map((f) => f.rule)).toContain('CI-0.suppression-unjustified');
  });

  it('an expired entry does not suppress; the note names the date', () => {
    const res = scan([
      { path: MCP, content: unpinned },
      suppress([{ ...ENTRY, expires: '2020-01-01' }]),
    ]);
    expect(res.findings.find((f) => f.rule === 'CI-3.mcp-unpinned')?.suppressed).toBeUndefined();
    expect(res.worst).toBe('medium');
    expect(res.notes.join(' ')).toMatch(/2020-01-01/);
  });

  it('a future expiry suppresses', () => {
    const res = scan([
      { path: MCP, content: unpinned },
      suppress([{ ...ENTRY, expires: '2999-01-01' }]),
    ]);
    expect(res.worst).toBeNull();
  });

  it('a stale entry (rule no longer fires) has no effect and raises nothing', () => {
    const res = scan([
      { path: MCP, content: JSON.stringify({ mcpServers: {} }) },
      suppress([ENTRY]),
    ]);
    expect(res.findings).toHaveLength(0);
    expect(res.worst).toBeNull();
  });

  it('a malformed file suppresses nothing and says so', () => {
    const res = scan([
      { path: MCP, content: unpinned },
      { path: SUPPRESSIONS_FILE, content: '{not json' },
    ]);
    expect(res.worst).toBe('medium');
    expect(res.findings.map((f) => f.rule)).toContain('CI-0.suppression-malformed');
  });

  it('parseSuppressions is pure and never throws', () => {
    const today = new Date('2026-09-26');
    expect(parseSuppressions('[]', today).active).toEqual([]);
    expect(parseSuppressions('null', today).active).toEqual([]);
    expect(parseSuppressions('[{"rule":1}]', today).active).toEqual([]);
    const ok = parseSuppressions(JSON.stringify([ENTRY]), today);
    expect(ok.active).toHaveLength(1);
    expect(ok.findings).toHaveLength(0);
  });
});

describe('a suppressed finding stays honest in the report', () => {
  it('a CI-2 critical from a real fixture, suppressed, still lists — and the pile is visible', () => {
    const wf = { path: '.github/workflows/review.yml', content: fx('injectable-pr-target.yml') };
    const res = scan([
      wf,
      suppress([
        { rule: 'CI-2.injectable-workflow', file: wf.path, reason: 'accepted risk, private repo' },
        {
          rule: 'CI-4.agent-reachable-secret',
          file: wf.path,
          reason: 'accepted risk, private repo',
        },
      ]),
    ]);
    expect(res.findings).toHaveLength(2);
    expect(res.findings.every((f) => f.suppressed)).toBe(true);
    expect(res.suppressedCount).toBe(2);
    expect(res.worst).toBeNull();
  });
});
