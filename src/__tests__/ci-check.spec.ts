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
import { analyzeWorkflow, analyzeWorkflowSecrets } from '../ci-check/workflows';
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

  it('F10: allowed_non_write_users:* on a SCHEDULED job is moot → advisory (no untrusted trigger)', () => {
    // lobehub claude-auto-testing pattern: schedule + workflow_dispatch, broad
    // tools, "*" — but no untrusted user can trigger a cron, so it's not injectable.
    const wf = `
on:
  schedule:
    - cron: '0 0 * * *'
  workflow_dispatch:
jobs:
  x:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.PAT }}
          allowed_non_write_users: "*"
          claude_args: '--allowedTools "Bash,Write,Edit"'
`;
    const f = analyzeWorkflow('sched.yml', wf)!;
    expect(SEVERITY_RANK[f.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('F9: ungated + reach but only SCOPED tools (no Bash) → medium, not high', () => {
    // umbraco pattern: issues trigger + "*" bypass + untrusted reach, but the
    // agent only has scoped mcp github issue tools — limited blast radius.
    const wf = `
on:
  issues:
    types: [opened]
jobs:
  dedupe:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          prompt: 'read github.event.issue.body and dedupe'
          claude_args: '--allowedTools "mcp__github__get_issue,mcp__github__add_issue_comment"'
`;
    const f = analyzeWorkflow('dedupe.yml', wf)!;
    expect(f.severity).toBe('medium');
  });

  it('F11: read-only token + scoped-script tools (medusa/sentry) → medium, not high', () => {
    // Ungated issues trigger + "*" + reach + a `Write` tool, BUT the token is
    // read-only and the Bash tools are scoped to specific scripts — an injected
    // agent can't write to GitHub or exfil/RCE → limited blast radius → medium.
    const wf = `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: read
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          prompt: 'read github.event.issue.body'
          claude_args: '--allowedTools "Write,Bash(gh api *),Bash(python3 .claude/scripts/x.py *)"'
`;
    const f = analyzeWorkflow('triage.yml', wf)!;
    expect(f.severity).toBe('medium');
  });

  it('F11: the SAME workflow but with pull-requests:write is NOT capped → high (the hyperdx case)', () => {
    const wf = `
on:
  pull_request_target:
    types: [opened]
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      issues: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          claude_args: '--allowedTools "Bash(gh api:*),Bash(git:*)"'
`;
    const f = analyzeWorkflow('review.yml', wf)!;
    expect(SEVERITY_RANK[f.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('F11: write perms on a SEPARATE (non-agent) job are not credited to the agent (medusa two-job)', () => {
    // The agent runs in a read-only job; a downstream "post the review" job has
    // write perms. An injected agent can't use the other job's token → medium.
    const wf = `
on:
  workflow_call:
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: read
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          prompt: 'read github.event.issue.body'
          claude_args: '--allowedTools "Bash(bash scripts/get_pr.sh:*),Write"'
  post:
    needs: analyze
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      issues: write
    steps:
      - run: echo "post the decision"
`;
    const f = analyzeWorkflow('two-job.yml', wf)!;
    expect(f.severity).toBe('medium');
  });

  it('F12: write perms but NO tool to use them (read-only git + Read/Write) → medium (UKGov)', () => {
    // pull-requests:write + id-token, ungated PR trigger, reach — BUT the tools
    // are read-only git + Read/Write with no gh api / gh pr comment / git push,
    // so the agent can't actually modify GitHub or exfil → medium.
    const wf = `
on:
  pull_request_target:
    types: [opened]
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          prompt: 'review github.event.pull_request.title'
          claude_args: '--allowedTools "Bash(git diff *),Bash(git log *),Read,Write,GrepTool"'
`;
    const f = analyzeWorkflow('ro.yml', wf)!;
    expect(f.severity).toBe('medium');
  });

  it('F12: the SAME + a gh-api tool (can use the write token) → high/critical (hyperdx)', () => {
    const wf = `
on:
  pull_request_target:
    types: [opened]
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          prompt: 'review github.event.pull_request.title'
          claude_args: '--allowedTools "Bash(gh api:*),Bash(git:*)"'
`;
    const f = analyzeWorkflow('hyperdx.yml', wf)!;
    expect(SEVERITY_RANK[f.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('F13: --disallowedTools denylist must NOT be read as granted tools (repomix) → not high', () => {
    // repomix: ungated issues trigger + "*", read-only job, and a DENYLIST that
    // blocks Bash/Write/network. The blocked names must not be counted as broad.
    const wf = `
on:
  issues:
    types: [opened]
jobs:
  find:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: read
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          prompt: 'read github.event.issue.body'
          claude_args: '--disallowedTools "Bash,Edit,Write,MultiEdit,WebFetch,WebSearch,Task"'
`;
    const f = analyzeWorkflow('repomix.yml', wf)!;
    expect(SEVERITY_RANK[f.severity]).toBeLessThanOrEqual(SEVERITY_RANK.medium);
    expect(f.signals.join(' ')).not.toMatch(/broad\/write-capable/i);
  });

  it('F14a: pull_request (labeled) + label-name gate → advisory, and NOT "no actor gate" (metabase)', () => {
    // metabase resolve-backport-conflicts: a maintainer must apply the label
    // (needs write access) — an effective actor gate on `pull_request` (not _target).
    const wf = `
on:
  pull_request:
    types: [labeled]
jobs:
  resolve:
    if: github.event.label.name == 'auto-resolve-conflicts'
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.ref }}
      - uses: anthropics/claude-code-base-action@v1
        with:
          allowed_tools: "Read,Edit,Write,Bash(git:*)"
`;
    const f = analyzeWorkflow('backport.yml', wf)!;
    expect(f.severity).toBe('advisory');
    expect(f.signals.join(' ')).not.toMatch(/no effective actor gate/i);
  });

  it('F14b: an UNGATED plain pull_request is sandboxed (read-only fork token) → advisory, not high', () => {
    // Same power, but plain `pull_request` — fork PRs get a read-only token + no
    // secrets, so injection can't write to the repo or exfil. Not a vuln.
    const wf = `
on:
  pull_request:
    types: [opened]
jobs:
  x:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-base-action@v1
        with:
          allowed_tools: "Bash,Write,Edit"
`;
    const f = analyzeWorkflow('pr.yml', wf)!;
    expect(f.severity).toBe('advisory');
    expect(f.signals.join(' ')).toMatch(/read-only token/i);
  });

  it('F14 regression: the SAME shape but pull_request_TARGET stays high/critical (privileged)', () => {
    const wf = `
on:
  pull_request_target:
    types: [opened]
jobs:
  x:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-base-action@v1
        with:
          allowed_tools: "Bash,Write,Edit"
`;
    const f = analyzeWorkflow('prt.yml', wf)!;
    expect(SEVERITY_RANK[f.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('CATASTROPHIC (the genuine one): untrusted trigger + * + broad Bash + secrets → high/critical', () => {
    const wf = `
on:
  issue_comment:
    types: [created]
jobs:
  x:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.PAT }}
          allowed_non_write_users: "*"
          prompt: 'process github.event.comment.body'
          claude_args: '--allowedTools "Bash,Write,curl"'
`;
    const f = analyzeWorkflow('bad.yml', wf)!;
    expect(SEVERITY_RANK[f.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
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
          claude_args: '--allowedTools "Bash"'
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

describe('CI-4 — agent-reachable secrets', () => {
  const base = (env: string, tools: string, extra = '') => `
on:
  issues:
    types: [opened]
jobs:
  x:
    runs-on: ubuntu-latest
    ${extra}
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
${env}
        with:
          allowed_non_write_users: "*"
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'read github.event.issue.body'
          claude_args: '--allowedTools "${tools}"'
`;

  it('extra CLOUD secret + injectable + bare Bash → critical', () => {
    const f = analyzeWorkflowSecrets(
      'w.yml',
      base('          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}', 'Bash,Read')
    )!;
    expect(f.check).toBe('CI-4');
    expect(f.severity).toBe('critical');
    expect(f.signals.join(' ')).toMatch(/AWS_SECRET_ACCESS_KEY/);
  });

  it('id-token:write (cloud OIDC) + injectable + bare Bash → critical', () => {
    const f = analyzeWorkflowSecrets(
      'w.yml',
      base('          FOO: bar', 'Bash', 'permissions:\n      id-token: write')
    )!;
    expect(f.severity).toBe('critical');
    expect(f.signals.join(' ')).toMatch(/cloud OIDC/i);
  });

  it('a plain extra API key + injectable + bare Bash → high (not critical)', () => {
    const f = analyzeWorkflowSecrets(
      'w.yml',
      base('          SERVICE_API_KEY: ${{ secrets.SERVICE_API_KEY }}', 'Bash')
    )!;
    expect(f.severity).toBe('high');
  });

  it('extra secret but only SCOPED tools (no bare shell) → advisory (agent can’t read env)', () => {
    const f = analyzeWorkflowSecrets(
      'w.yml',
      base(
        '          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
        'Bash(gh:*),Read'
      )
    )!;
    expect(f.severity).toBe('advisory');
  });

  it('only the agent’s own fuel (ANTHROPIC_API_KEY / GITHUB_TOKEN) → no CI-4 finding', () => {
    const wf = `
on:
  issues:
    types: [opened]
jobs:
  x:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          github_token: \${{ secrets.GITHUB_TOKEN }}
          claude_args: '--allowedTools "Bash"'
`;
    expect(analyzeWorkflowSecrets('w.yml', wf)).toBeNull();
  });

  it('extra secret but GATED (claude-code-action default, no *) → advisory', () => {
    const wf = `
on:
  issue_comment:
    types: [created]
jobs:
  x:
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          AWS_SECRET_ACCESS_KEY: \${{ secrets.AWS_SECRET_ACCESS_KEY }}
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: '--allowedTools "Bash"'
`;
    const f = analyzeWorkflowSecrets('w.yml', wf)!;
    expect(f.severity).toBe('advisory');
  });

  // ── Fix A: per-agent-job scoping (no cross-job conflation) ──
  // The exfiltratable-secret danger (untrusted reach + a real secret + a shell) must
  // all land in the SAME job. A secret + bare Bash sitting in a job that ISN'T
  // externally reachable must NOT combine with a DIFFERENT job's untrusted trigger.
  it('cross-job: injectable job has only fuel, the secret+bare-Bash job is NOT reachable → advisory, not critical', () => {
    const wf = `
on:
  issues:
    types: [opened]
jobs:
  respond:            # injectable ('*' + untrusted prompt) but only fuel — no extra secret
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'respond to github.event.issue.body'
          claude_args: '--allowedTools "Bash(gh:*),Read"'
  deploy:             # has the real secret + bare Bash, but NOT externally reachable (no *, no untrusted input)
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          AWS_SECRET_ACCESS_KEY: \${{ secrets.AWS_SECRET_ACCESS_KEY }}
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'run the deploy'
          claude_args: '--allowedTools "Bash"'
`;
    const f = analyzeWorkflowSecrets('w.yml', wf)!;
    expect(f.severity).toBe('advisory'); // was 'critical' pre-fix (conflated across jobs)
  });

  it('cross-job: injectable job holds the real secret but only SCOPED tools; a separate job has bare Bash → advisory (netwrix/rnikitin shape)', () => {
    const wf = `
on:
  issue_comment:
    types: [created]
jobs:
  triage:                    # injectable + real secret, but SCOPED tools (no shell to exfil it)
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          SERVICE_API_KEY: \${{ secrets.SERVICE_API_KEY }}
        with:
          allowed_non_write_users: "*"
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'triage github.event.comment.body'
          claude_args: '--allowedTools "Bash(gh:*),Read,Grep"'
  build:                     # bare Bash but no extra secret (and gated by the default)
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'build'
          claude_args: '--allowedTools "Bash"'
`;
    const f = analyzeWorkflowSecrets('w.yml', wf)!;
    expect(f.severity).toBe('advisory'); // was 'high' pre-fix (bare Bash borrowed from the build job)
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

  it('a rate-limited (incomplete) scan is NEVER rendered as clean', async () => {
    const { renderScan, exitCodeFor } = await import('../ci-check/render.js');
    // No files read + a rate-limit note = we couldn't look. This must NOT be
    // "clean" — it's the 3x-ui case the user hit (0 files → "✅ clean").
    const tree = {
      source: 'MHSanaei/3x-ui',
      notes: [
        'GitHub rate limit hit — results may be INCOMPLETE (a missing file could be unread, not absent). Set GITHUB_TOKEN.',
      ],
      files: [],
    };
    const res = scanTree(tree);
    expect(res.incomplete).toBe(true);
    expect(res.worst).toBeNull();
    expect(exitCodeFor(res)).toBe(3); // not 0 — a script must not read it as a clean pass
    const out = renderScan(res);
    expect(out).toMatch(/INCOMPLETE/);
    expect(out).not.toMatch(/agent-security: clean/);
    expect(out).not.toMatch(/No committed agent hooks/);
  });

  it('resolveGitHubToken prefers an explicit env token', async () => {
    const { resolveGitHubToken } = await import('../ci-check/fetch.js');
    const saved = process.env.GITHUB_TOKEN;
    process.env.GITHUB_TOKEN = FAKE_TOKEN;
    try {
      expect(resolveGitHubToken()).toBe(FAKE_TOKEN);
    } finally {
      if (saved === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = saved;
    }
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
