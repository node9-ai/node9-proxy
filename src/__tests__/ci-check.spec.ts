// Tests for `node9 scan-repo` / the ci-check engine.
//
// The load-bearing assertion is the SEVERITY NUANCE (design §4.5): the same
// "pull_request_target + agent" shape must rate milvus HIGH+, NVIDIA MEDIUM
// (mitigated), and strapi safe/advisory. A tool that flags them identically is
// the cry-wolf failure the whole design exists to avoid. Fixtures are the REAL
// verified configs (per CLAUDE.md: real caller inputs).

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { analyzeAgentConfig } from '../ci-check/agent-config';
import { analyzeMcp } from '../ci-check/mcp';
import { scanTree } from '../ci-check';
import { SEVERITY_RANK } from '../ci-check/types';
import { parseRepoUrl, isLocalPath } from '../ci-check/fetch';

const FX = path.join(__dirname, 'fixtures', 'ci-check');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');

// A GitHub-token-shaped string built at runtime so no literal credential lives
// in the source (node9's own DLP — correctly — blocks committing one). Built as
// a full 36-char permutation of the base36 alphabet (high entropy, non-repeating)
// so the DLP scanner's entropy gate accepts it.
const ALPHA = 'abcdefghijklmnopqrstuvwxyz0123456789';
const FAKE_TOKEN = 'ghp_' + Array.from({ length: 36 }, (_, i) => ALPHA[(i * 13 + 5) % 36]).join('');

describe('CI-2 workflow analyzer — the severity nuance (the moat)', () => {
  it('F7: rates milvus ADVISORY — claude-code-action gates to write-access by default', () => {
    // milvus uses claude-code-action with NO allowed_non_write_users, so the
    // action blocks untrusted authors by default → this is a hardening advisory,
    // NOT a HIGH "any attacker" finding. (The pre-F7 HIGH was crying wolf.)
    const f = analyzeWorkflow(
      '.github/workflows/claude-code-review.yml',
      read('milvus-claude-review.yml')
    );
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(f!.mitigations?.join(' ')).toMatch(/write-access users by default/i);
    // The hardening opportunities still surface as signals.
    expect(f!.signals.join(' ')).toMatch(/root/i);
  });

  it('rates NVIDIA MEDIUM — the risky pattern is present but mitigated', () => {
    const f = analyzeWorkflow(
      '.github/workflows/_claude-fix-attempt.yml',
      read('nvidia-claude-fix.yml')
    );
    expect(f).not.toBeNull();
    expect(f!.severity).toBe('medium');
    expect(f!.mitigations?.join(' ')).toMatch(/subdir|env-denied|pinned/i);
  });

  it('rates strapi SAFE/advisory — label-gated, base checkout, scoped tools', () => {
    const f = analyzeWorkflow(
      '.github/workflows/needs-qa-checklist.yml',
      read('strapi-needs-qa.yml')
    );
    if (f) expect(SEVERITY_RANK[f.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('THE MOAT: a truly-ungated workflow > a mitigated one > a gated one', () => {
    // Post-F7 the moat is anchored honestly: only a workflow with the default
    // gate REMOVED (allowed_non_write_users:*) is genuinely high; a mitigated one
    // is medium; a gated one (milvus, via the implicit gate) is advisory.
    const dangerous = `
on:
  pull_request_target:
jobs:
  x:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          claude_args: '--allowedTools "Bash"'
`;
    const danger = analyzeWorkflow('d.yml', dangerous)!;
    const nvidia = analyzeWorkflow('n.yml', read('nvidia-claude-fix.yml'))!;
    const milvus = analyzeWorkflow('m.yml', read('milvus-claude-review.yml'))!;
    expect(SEVERITY_RANK[danger.severity]).toBeGreaterThan(SEVERITY_RANK[nvidia.severity]);
    expect(SEVERITY_RANK[nvidia.severity]).toBeGreaterThan(SEVERITY_RANK[milvus.severity]);
  });

  it('F8: a GATED workflow with dangerous tools but no untrusted reach is advisory, not HIGH', () => {
    // The NVIDIA claude-copy-to-main pattern: gated (claude-code-action's default),
    // a static PAT + broad tools + id-token, but the untrusted comment body never
    // reaches the agent prompt. Gated → not externally exploitable → advisory, with
    // the static-PAT hardening concern still surfaced as a signal.
    const wf = `
on:
  issue_comment:
    types: [created]
jobs:
  copy:
    if: contains(github.event.comment.body, '/claude copy')
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.PAT }}
          claude_args: '--allowedTools "Bash(curl *),Write"'
          prompt: 'copy this PR to main'
`;
    const f = analyzeWorkflow('copy.yml', wf)!;
    expect(f.severity).toBe('advisory');
    expect(f.signals.join(' ')).toMatch(/static PAT/i);
    expect(f.mitigations?.join(' ')).toMatch(/write-access users by default/i);
  });

  it('F7: allowed_non_write_users:* REMOVES the implicit gate → HIGH', () => {
    const wf = `
on:
  pull_request_target:
jobs:
  x:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
`;
    const f = analyzeWorkflow('x.yml', wf)!;
    expect(SEVERITY_RANK[f.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
    expect(f.mitigations?.join(' ') ?? '').not.toMatch(/write-access users by default/i);
  });

  it('F1 regression: a stray "write" in a label name is NOT an actor gate', () => {
    // Dangerous workflow whose only `if` references a label named "needs-rewrite"
    // — must NOT be treated as an explicit gate. allowed_non_write_users:* removes
    // the implicit gate too, so the only gate question is the (bogus) label if.
    const wf = `
on:
  pull_request_target:
    types: [opened]
jobs:
  review:
    if: contains(github.event.pull_request.labels.*.name, 'needs-rewrite')
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          claude_args: '--allowedTools "Bash"'
`;
    const f = analyzeWorkflow('danger.yml', wf)!;
    expect(SEVERITY_RANK[f.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
    expect(f.signals.join(' ')).toMatch(/no effective actor gate/i);
  });

  it('B1 regression: elevated permissions (id-token: write) are actually detected', () => {
    // Guards the permsElevated regex against the JSON-stringify quote bug: the
    // "elevated permissions" signal MUST fire for a workflow whose only escalator
    // is id-token/contents: write (otherwise it silently dies again).
    const wf = `
on:
  pull_request_target:
jobs:
  review:
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
          path: pr-head
      - uses: anthropics/claude-code-action@v1
`;
    const f = analyzeWorkflow('perms.yml', wf)!;
    expect(f.signals.join(' ')).toMatch(/elevated permissions/i);
  });

  it('returns null for a non-agentic workflow (no cry-wolf on plain CI)', () => {
    const plain =
      'name: ci\non:\n  pull_request_target:\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n';
    expect(analyzeWorkflow('ci.yml', plain)).toBeNull();
  });

  it('does not throw on unparseable YAML', () => {
    expect(analyzeWorkflow('bad.yml', ':::not: yaml: [')).toBeNull();
  });
});

describe('CI-1 agent-config', () => {
  it('flags the glances npx hook (pinned → medium, not overclaimed as high)', () => {
    const findings = analyzeAgentConfig('.claude/settings.json', read('glances-settings.json'));
    const hook = findings.find((f) => /hook/i.test(f.title));
    expect(hook).toBeTruthy();
    expect(hook!.severity).toBe('medium'); // pinned @1.1.2 → not high
  });

  it('sentry’s scoped allow-list is clean (the low-FP proof)', () => {
    const findings = analyzeAgentConfig('.claude/settings.json', read('sentry-settings.json'));
    expect(findings).toEqual([]);
  });

  it('flags an UNPINNED hook as high', () => {
    const cfg = JSON.stringify({
      hooks: {
        PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'npx evil-thing' }] }],
      },
    });
    const findings = analyzeAgentConfig('.claude/settings.json', cfg);
    expect(findings[0].severity).toBe('high');
  });

  it('flags a broad Bash(git:*) allow as medium', () => {
    const cfg = JSON.stringify({ permissions: { allow: ['Bash(git:*)'], deny: [] } });
    const findings = analyzeAgentConfig('.claude/settings.json', cfg);
    expect(findings.some((f) => /broad tools/i.test(f.title))).toBe(true);
  });
});

describe('CI-3 mcp', () => {
  it('flags an unpinned npx server', () => {
    const cfg = JSON.stringify({
      mcpServers: { docs: { command: 'npx', args: ['-y', 'some-mcp@latest'] } },
    });
    expect(analyzeMcp('.mcp.json', cfg).some((f) => /unpinned/i.test(f.title))).toBe(true);
  });

  it('flags an inline credential in an MCP env', () => {
    const cfg = JSON.stringify({
      mcpServers: { db: { command: 'x', env: { TOKEN: FAKE_TOKEN } } },
    });
    expect(analyzeMcp('.mcp.json', cfg).some((f) => /inline credential/i.test(f.title))).toBe(true);
  });

  it('does not flag a pinned/benign server', () => {
    const cfg = JSON.stringify({
      mcpServers: { pw: { command: 'npx', args: ['playwright@1.2.3'] } },
    });
    expect(analyzeMcp('.mcp.json', cfg)).toEqual([]);
  });
});

describe('scanTree orchestration + fetch parsing', () => {
  it('aggregates + sorts worst-first over a mixed tree', () => {
    const tree = {
      source: 'x/y',
      notes: [],
      files: [
        {
          path: '.github/workflows/claude-code-review.yml',
          content: read('milvus-claude-review.yml'),
        },
        { path: '.claude/settings.json', content: read('glances-settings.json') },
      ],
    };
    const res = scanTree(tree);
    expect(res.findings.length).toBeGreaterThanOrEqual(2);
    // worst-first: findings[0] is the worst, and every later finding is <= it.
    expect(res.worst).toBe(res.findings[0].severity);
    for (let i = 1; i < res.findings.length; i++) {
      expect(SEVERITY_RANK[res.findings[i].severity]).toBeLessThanOrEqual(
        SEVERITY_RANK[res.findings[0].severity]
      );
    }
    // Post-F7 milvus is advisory (implicit gate); glances' hook (medium) is the worst.
    expect(res.worst).toBe('medium');
  });

  it('parseRepoUrl handles url/shorthand/tree forms', () => {
    expect(parseRepoUrl('https://github.com/milvus-io/milvus')).toEqual({
      owner: 'milvus-io',
      repo: 'milvus',
    });
    expect(parseRepoUrl('milvus-io/milvus')).toEqual({ owner: 'milvus-io', repo: 'milvus' });
    expect(parseRepoUrl('github.com/a/b/tree/main')).toEqual({ owner: 'a', repo: 'b' });
    expect(parseRepoUrl('not-a-repo')).toBeNull();
  });

  it('isLocalPath recognizes paths vs repo refs', () => {
    expect(isLocalPath('./foo')).toBe(true);
    expect(isLocalPath('/tmp/x')).toBe(true);
    expect(isLocalPath('owner/repo')).toBe(false);
  });
});
