// fw#481 L1 to L6 (2026-11-18): the cases where scan-repo graded LOWER than the real reach.
// Each test fails on 2.65.5. Fixtures are short synthetic files.

import { describe, it, expect } from 'vitest';
import { scanTree } from '../ci-check';
import { analyzeWorkflow } from '../ci-check/workflows';
import type { RepoTree } from '../ci-check/types';

const tree = (files: Record<string, string>): RepoTree => ({
  source: 'fixture',
  files: Object.entries(files).map(([p, content]) => ({ path: p, content })),
  notes: [],
});
const ci2 = (wf: string) => analyzeWorkflow('w.yml', wf)!;

// An issue-triage agent anyone starts, its gate switched off, a PAT as its token.
const triage = (args: string, token = 'BOT_PAT') => `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.${token} }}
          allowed_non_write_users: "*"
          prompt: 'Triage the new issue with gh.'
          claude_args: "${args}"
`;

describe('L1-a: every argument of --allowedTools', () => {
  it('reads an unquoted list up to the next option', () => {
    const f = ci2(triage('--allowedTools Read Grep Glob Bash(gh:*) --max-turns 15'));
    expect(f.signals.join(' ')).toMatch(/Bash\(gh:\*\)/);
    expect(f.severity).toBe('high'); // was medium: the open gh was never read
  });

  it('reads several quoted arguments', () => {
    const f = ci2(triage(`--allowedTools 'Read' 'Bash(gh:*)' --model x`));
    expect(f.signals.join(' ')).toMatch(/Bash\(gh:\*\)/);
  });

  it('keeps an unquoted grant with a space inside its parentheses whole', () => {
    const f = ci2(
      triage('--allowedTools Read Bash(gh issue comment:*) --max-turns 3', 'GITHUB_TOKEN')
    );
    expect(f.signals.join(' ')).not.toMatch(/`Bash`/);
  });

  it('does not take a prompt written after the list for a tool', () => {
    const wf = `
on:
  issues:
    types: [opened]
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - env:
          ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}
          BODY: \${{ github.event.issue.body }}
        run: claude -p --allowedTools Read "Summarize, never use Bash or Write" < body.txt
`;
    const f = analyzeWorkflow('w.yml', wf);
    expect(f?.signals.join(' ') ?? '').not.toMatch(/`Bash`|`Write`/);
  });

  it('a single quoted list is read as before', () => {
    const f = ci2(triage('--allowedTools \\"Read,Grep\\"', 'GITHUB_TOKEN'));
    expect(f.signals.join(' ')).not.toMatch(/broad/);
  });
});

describe('L1-b: the legacy Bash:* form', () => {
  it('is an unrestricted shell', () => {
    const wf = triage('', 'GITHUB_TOKEN').replace(
      '          claude_args: ""',
      '          allowed_tools: "Bash:*,Read"'
    );
    expect(ci2(wf).signals.join(' ')).toMatch(/`Bash`/);
  });
});

// A review on pull_request_target that checks out the PR head and then runs a script from it.
const headScript = (run: string) => `
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          repository: \${{ github.event.pull_request.head.repo.full_name }}
          ref: \${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: ${run}
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: \${{ secrets.MERGE_PAT }}
          allowed_non_write_users: \${{ github.event.pull_request.user.login }}
          prompt: 'Review the agent files.'
          claude_args: '--allowedTools "Read,Bash(gh pr review:*)"'
`;

describe('L3-a: a run step executes the checked-out PR head', () => {
  it('a script from the head runs with the secrets: critical', () => {
    const f = ci2(headScript('python scripts/validate.py'));
    expect(f.signals.join(' ')).toMatch(/executes the checked-out PR code/);
    expect(f.severity).toBe('critical');
  });

  it('git and gh commands run nothing from the head', () => {
    const f = ci2(headScript('git diff --name-only HEAD~1'));
    expect(f.signals.join(' ')).not.toMatch(/executes the checked-out PR code/);
  });
});

describe('L4: stranger text expanded into a script', () => {
  const inject = `
on:
  issue_comment:
    types: [created]
jobs:
  check:
    runs-on: ubuntu-latest
    outputs:
      ok: \${{ steps.c.outputs.ok }}
    steps:
      - id: c
        run: |
          BODY="\${{ github.event.comment.body }}"
          if gh api repos/o/r/collaborators/\${{ github.actor }}/permission | grep -q write; then echo "ok=true" >> $GITHUB_OUTPUT; fi
        env:
          GH_TOKEN: \${{ github.token }}
  agent:
    needs: check
    if: needs.check.outputs.ok == 'true'
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-base-action@beta
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'Do what the comment asks.'
          allowed_tools: "Bash(git:*),Bash(gh:*)"
`;

  it('voids a gate computed in the injected job', () => {
    expect(ci2(inject).severity).not.toBe('advisory');
  });

  it('the env form is safe and keeps the gate', () => {
    const safe = inject.replace('BODY="${{ github.event.comment.body }}"', 'BODY="$COMMENT_BODY"');
    expect(ci2(safe).severity).toBe('advisory');
  });

  it('in the agent job itself it is a shell, whatever the tool list', () => {
    const wf = triage('--allowedTools Read', 'GITHUB_TOKEN').replace(
      '    steps:\n',
      '    steps:\n      - run: echo "${{ github.event.issue.title }}" > /tmp/t\n'
    );
    const f = ci2(wf);
    expect(f.signals.join(' ')).toMatch(/shell injection/);
    expect(f.signals.join(' ')).toMatch(/`Bash`/);
  });
});

describe('L5: the trusted-trigger reader with a shell and a lasting secret', () => {
  const reader = (tools: string) => `
on:
  schedule:
    - cron: "0 6 * * *"
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: acme/agent-wrappers/.github/actions/claude-run@main
        with:
          agent: triager
          prompt: 'Read the open issues with gh issue list and label them.'
          tools: "${tools}"
        env:
          ANTHROPIC_API_KEY: \${{ secrets.ANTHROPIC_API_KEY }}
          GH_TOKEN: \${{ secrets.BOT_PAT }}
`;
  const trusted = (wf: string) =>
    scanTree(tree({ '.github/workflows/t.yml': wf })).findings.find(
      (f) => f.rule === 'CI-2.trusted-trigger-reader'
    );

  it('reads the tools input of an agent wrapper, and is high with a shell and a PAT', () => {
    expect(trusted(reader('Bash,Read'))?.severity).toBe('high');
  });

  it('an agent behind the agentic-workflow firewall stays at the lowest level', () => {
    const wf = reader('Bash,Read').replace(
      '      - uses: acme/agent-wrappers',
      '      - run: awf --config cfg.json -- echo ready\n      - uses: acme/agent-wrappers'
    );
    expect(trusted(wf)?.severity ?? 'none').not.toBe('high');
  });

  it('a run a maintainer starts is not a trusted-trigger reader', () => {
    const wf = reader('Bash,Read').replace(
      '  schedule:\n    - cron: "0 6 * * *"',
      '  workflow_dispatch:'
    );
    expect(trusted(wf)).toBeUndefined();
  });

  it('without a shell it stays at the lowest level', () => {
    expect(trusted(reader('Read,Bash(gh issue edit:*)'))?.severity ?? 'none').not.toBe('high');
  });

  it('codex exec -s danger-full-access is an unrestricted shell', () => {
    const wf = `
on:
  issues:
    types: [opened]
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - env:
          OPENAI_API_KEY: \${{ secrets.OPENAI_API_KEY }}
        run: codex exec -s danger-full-access "triage \${{ github.event.issue.number }}"
`;
    expect(ci2(wf).signals.join(' ')).toMatch(/`Bash`/);
  });
});

describe('L6: committed settings joined into the CI agent', () => {
  const wf = triage('--allowedTools Read', 'GITHUB_TOKEN').replace(
    '    steps:\n',
    '    steps:\n      - uses: actions/checkout@v4\n'
  );
  const allow = JSON.stringify({ permissions: { allow: ['Bash(curl:*)', 'Bash(node:*)'] } });

  it('the action loads the committed allow list in its checkout', () => {
    const f = scanTree(
      tree({ '.github/workflows/t.yml': wf, '.claude/settings.local.json': allow })
    ).findings.find((x) => x.rule === 'CI-2.injectable-workflow')!;
    expect(f.signals.join(' ')).toMatch(/committed `.claude\/settings` allow list/);
    expect(f.signals.join(' ')).toMatch(/Bash\(curl:\*\)/);
  });

  it('without a checkout there is nothing to load', () => {
    const f = scanTree(
      tree({
        '.github/workflows/t.yml': triage('--allowedTools Read', 'GITHUB_TOKEN'),
        '.claude/settings.json': allow,
      })
    ).findings.find((x) => x.rule === 'CI-2.injectable-workflow')!;
    expect(f.signals.join(' ')).not.toMatch(/committed `.claude\/settings`/);
  });

  it('--setting-sources without project or local turns it off', () => {
    const narrowed = wf.replace(
      '--allowedTools Read',
      '--allowedTools Read --setting-sources user'
    );
    const f = scanTree(
      tree({ '.github/workflows/t.yml': narrowed, '.claude/settings.json': allow })
    ).findings.find((x) => x.rule === 'CI-2.injectable-workflow')!;
    expect(f.signals.join(' ')).not.toMatch(/committed `.claude\/settings`/);
  });

  it('is not left behind for the next analysis', () => {
    scanTree(tree({ '.github/workflows/t.yml': wf, '.claude/settings.json': allow }));
    expect(ci2(wf).signals.join(' ')).not.toMatch(/committed `.claude\/settings`/);
  });
});

describe('L2-a: a label automation adds with a PAT is no gate', () => {
  const labeler = `
on:
  issues:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: gh issue edit \${{ github.event.issue.number }} --add-label agent-fix
        env:
          GH_TOKEN: \${{ secrets.TRIAGE_PAT }}
`;
  const fixer = `
on:
  issues:
    types: [labeled]
jobs:
  fix:
    if: github.event.label.name == 'agent-fix'
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-base-action@beta
        with:
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
          prompt: 'Fix the issue described in \${{ github.event.issue.body }}'
          allowed_tools: "Bash,Edit"
`;
  const fix = (files: Record<string, string>) =>
    scanTree(tree(files)).findings.find(
      (f) => f.rule === 'CI-2.injectable-workflow' && f.file.endsWith('fix.yml')
    );

  it('makes the labeled workflow reachable by whoever opens an issue', () => {
    expect(
      fix({ '.github/workflows/label.yml': labeler, '.github/workflows/fix.yml': fixer })?.severity
    ).not.toBe('advisory');
  });

  it('a label made with the default token starts nothing', () => {
    const plain = labeler.replace('secrets.TRIAGE_PAT', 'secrets.GITHUB_TOKEN');
    expect(
      fix({ '.github/workflows/label.yml': plain, '.github/workflows/fix.yml': fixer })?.severity
    ).toBe('advisory');
  });
});

describe('L3-a: a heredoc body is data, not commands', () => {
  it('jq and gh over a heredoc of the agent output run nothing from the head', () => {
    const run = `|
          cat <<'EOF' > /tmp/out.json
          \${{ steps.analyze.outputs.structured_output }}
          EOF
          jq -r '.reason' /tmp/out.json`;
    const wf = headScript(run);
    expect(analyzeWorkflow('w.yml', wf)!.signals.join(' ')).not.toMatch(
      /executes the checked-out PR code/
    );
  });
});
