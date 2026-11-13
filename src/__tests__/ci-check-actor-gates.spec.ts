// Actor gates the scanner did not read (design: scanner-actor-gates-c3-a8-design.md).
// WRITTEN BEFORE THE IMPLEMENTATION.
//
// G1: a same-job gate written in an `actions/github-script` step was not read (only `run:` was).
// G2: the collaborator CHECK endpoint (`repos/<repo>/collaborators/<user>`, 204 or 404) was not
//     a known membership check; only `.../collaborators/<user>/permission` was.
// G3: `openai/codex-action` checks that the actor has write access before it starts Codex
//     (every release), and `allow-users: "*"` switches that check off. The scanner read neither:
//     an open Codex step scored no reach, and a default one scored as ungated.

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow, analyzeWorkflowSecrets } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'actor-gates');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');
const ci2 = (f: string) => analyzeWorkflow(`.github/workflows/${f}`, read(f));
const rank = (f: string) => {
  const r = ci2(f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};
const signals = (f: string) => (ci2(f)?.signals ?? []).join(' | ');
const mitigations = (f: string) => (ci2(f)?.mitigations ?? []).join(' | ');
/** A substitution in a fixture that must find its text: a variant that changes nothing would
 *  test the unchanged fixture and pass (or fail) for the wrong reason. */
const sub = (text: string, from: string | RegExp, to: string): string => {
  const out = text.replace(from, to);
  if (out === text && !(typeof from === 'string' && from === to))
    throw new Error(`fixture text not found: ${String(from)}`);
  return out;
};

describe('G1: an actor gate in a github-script step of the same job', () => {
  it('holds the agent step that reads its output: advisory at most', () => {
    expect(rank('script-gate-same-job.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(signals('script-gate-same-job.yml')).not.toMatch(/no effective actor gate/);
    expect(mitigations('script-gate-same-job.yml')).toMatch(/actor-gated/);
  });

  it('is not a gate when the agent step does not read the output', () => {
    expect(rank('script-gate-unread.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('script-gate-unread.yml')).toMatch(/no effective actor gate/);
  });

  it('is not a gate when the script step has no id', () => {
    expect(rank('script-gate-no-id.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('script-gate-no-id.yml')).toMatch(/no effective actor gate/);
  });

  it('holds with a positive flag the agent step requires', () => {
    expect(rank('script-gate-positive.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  // An agent that answers OUTSIDERS reads the same output the other way round.
  it('is not a gate when the agent step runs on the NO of the check', () => {
    expect(rank('script-gate-inverted.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('script-gate-inverted.yml')).toMatch(/no effective actor gate/);
  });

  it('is not a gate when a refusal flag is read as "refused"', () => {
    const y = sub(
      read('script-gate-same-job.yml'),
      "if: steps.guard.outputs.denied != 'true'",
      "if: steps.guard.outputs.denied == 'true'"
    );
    const f = analyzeWorkflow('.github/workflows/x.yml', y);
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  it('the same holds for a check in a run: step (it was credited without reading polarity)', () => {
    const asRun = (cond: string) =>
      analyzeWorkflow(
        '.github/workflows/x.yml',
        sub(
          read('script-gate-positive.yml'),
          /        uses: actions\/github-script@v7\n        with:\n          script: \|\n(?: {12}.*\n)+/,
          [
            '        env:',
            '          GH_TOKEN: ${{ github.token }}',
            '        run: |',
            '          p=$(gh api "repos/$GITHUB_REPOSITORY/collaborators/${{ github.actor }}/permission" --jq .permission)',
            '          echo "is_writer=$([ "$p" = write ] && echo true || echo false)" >> "$GITHUB_OUTPUT"',
            '',
          ].join('\n')
        )
          .split("if: steps.guard.outputs.is_writer == 'true'")
          .join(`if: ${cond}`)
      );
    const yes = asRun("steps.guard.outputs.is_writer == 'true'");
    const no = asRun("steps.guard.outputs.is_writer == 'false'");
    expect(SEVERITY_RANK[yes!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(SEVERITY_RANK[no!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });
});

describe('G2: the collaborator check endpoint in an upstream job', () => {
  it('gates a dependent that requires its yes: advisory at most', () => {
    expect(rank('collaborator-check-upstream.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(signals('collaborator-check-upstream.yml')).not.toMatch(/no effective actor gate/);
  });

  it('a listing of all collaborators is not a check of the actor', () => {
    expect(rank('collaborator-list-upstream.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('collaborator-list-upstream.yml')).toMatch(/no effective actor gate/);
  });

  it('a call that adds the collaborator (-X PUT) is not a check', () => {
    expect(rank('collaborator-put-upstream.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('collaborator-put-upstream.yml')).toMatch(/no effective actor gate/);
  });

  const upstream = (call: string) =>
    analyzeWorkflow(
      '.github/workflows/x.yml',
      sub(
        read('collaborator-check-upstream.yml'),
        'gh api "repos/$GITHUB_REPOSITORY/collaborators/$WHO" --silent',
        call
      )
    );

  it.each([
    ['inside a command substitution', 'x=$(gh api repos/$GITHUB_REPOSITORY/collaborators/$WHO)'],
    ['directly before ||', 'gh api repos/$GITHUB_REPOSITORY/collaborators/$WHO|| exit 1; true'],
    ['with curl', 'curl -fsS "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/collaborators/$WHO"'],
  ])('the check is recognised %s', (_name, call) => {
    const f = upstream(call);
    expect(SEVERITY_RANK[f!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it.each([
    [
      'request fields (gh api -f, a POST)',
      'gh api "repos/$GITHUB_REPOSITORY/collaborators/$WHO" -f permission=push --silent',
    ],
    ['--method PUT', 'gh api --method PUT "repos/$GITHUB_REPOSITORY/collaborators/$WHO" --silent'],
    [
      'curl --request PUT',
      'curl --request PUT "$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/collaborators/$WHO"',
    ],
  ])('a call with %s is a write, not a check', (_name, call) => {
    const f = upstream(call);
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });

  // The same job shape with the call made from a script step.
  const scripted = (body: string) =>
    analyzeWorkflow(
      '.github/workflows/x.yml',
      sub(
        read('script-gate-positive.yml'),
        /            const res = await github\.rest\.repos\.getCollaboratorPermissionLevel\(\{\n(?: {14}.*\n)+            \}\);\n            core\.setOutput\(.*\n/,
        body
      )
    );

  it('the octokit call (checkCollaborator) in a script step is a check', () => {
    const f = scripted(
      [
        '            const res = await github.rest.repos.checkCollaborator({ ...context.repo, username: who });',
        '            core.setOutput("is_writer", res.status === 204 ? "true" : "false");',
        '',
      ].join('\n')
    );
    expect(SEVERITY_RANK[f!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it.each([
    [
      'a route string',
      "await github.request('PUT /repos/{owner}/{repo}/collaborators/{username}', { ...context.repo, username: who });",
    ],
    [
      'a method option',
      "await github.request({\n              method: 'PUT',\n              url: '/repos/{owner}/{repo}/collaborators/{username}',\n            });",
    ],
  ])('an invitation written as %s is a write, not a check', (_name, call) => {
    const f = scripted(
      [`            ${call}`, '            core.setOutput("is_writer", "true");', ''].join('\n')
    );
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });
});

describe('G3a: allow-users on codex-action', () => {
  it('"*" on a stranger-firable trigger: anyone starts the agent, at least medium', () => {
    expect(rank('codex-star-issues.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    const s = signals('codex-star-issues.yml');
    expect(s).toMatch(/allow-users: "\*"/);
    expect(s).toMatch(/any user can trigger the agent/);
    expect(s).toMatch(/no effective actor gate/);
    expect(s).not.toMatch(/allowed_non_write_users/);
  });

  it('bound to the user who fired the event is "*" in effect', () => {
    expect(rank('codex-actor-bound-issues.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('codex-actor-bound-issues.yml')).toMatch(/triggering user's own login/);
  });

  it('a named list keeps the check: advisory at most, with the list named as a mitigation', () => {
    expect(rank('codex-list-issues.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(mitigations('codex-list-issues.yml')).toMatch(/scoped to a list/);
  });

  it('a list on one step is no mitigation while another step is open', () => {
    const y = sub(
      read('codex-star-issues.yml'),
      /      - uses: openai\/codex-action@v1\n/,
      [
        '      - uses: openai/codex-action@v1',
        '        with:',
        '          openai-api-key: ${{ secrets.OPENAI_API_KEY }}',
        '          prompt: "Sort the labels."',
        '          allow-users: "alice"',
        '      - uses: openai/codex-action@v1',
        '',
      ].join('\n')
    );
    const f = analyzeWorkflow('.github/workflows/x.yml', y);
    expect(f!.signals.join(' | ')).toMatch(/allow-users: "\*"/);
    expect((f!.mitigations ?? []).join(' | ')).not.toMatch(/scoped to a list/);
  });

  it('"*" on a trigger no stranger fires reaches nothing: advisory at most', () => {
    expect(rank('codex-star-dispatch.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(signals('codex-star-dispatch.yml')).not.toMatch(/any user can trigger/);
  });

  it('"*" with a read-only sandbox and no token: open, but not above medium', () => {
    const r = rank('codex-star-read-only.yml');
    expect(r).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(r).toBeLessThanOrEqual(SEVERITY_RANK.medium);
  });

  it('the fix is about the Codex step, not a Claude document', () => {
    const fix = ci2('codex-star-issues.yml')?.fix ?? '';
    expect(fix).toMatch(/allow-users/);
    expect(fix).not.toMatch(/claude-code-action/);
  });

  it('the explanation names the Codex input, not the Claude one', () => {
    const saw = (ci2('codex-star-issues.yml')?.explain?.saw ?? []).join(' ');
    expect(saw).toMatch(/allow-users: "\*"/);
    expect(saw).not.toMatch(/allowed_non_write_users/);
  });
});

describe("G3b: codex-action's own write check", () => {
  it('holds a default step even when the issue text is in the prompt: advisory at most', () => {
    expect(rank('codex-default-prompt-untrusted.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(signals('codex-default-prompt-untrusted.yml')).not.toMatch(/no effective actor gate/);
    expect(mitigations('codex-default-prompt-untrusted.yml')).toMatch(
      /codex-action gates the agent to write-access users by default/
    );
  });

  it('holds a default step with no untrusted text in the prompt too', () => {
    expect(rank('codex-default-issues.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('is not credited to a third-party build', () => {
    expect(rank('codex-third-party-prompt-untrusted.yml')).toBeGreaterThanOrEqual(
      SEVERITY_RANK.medium
    );
    const s = signals('codex-third-party-prompt-untrusted.yml');
    expect(s).toMatch(/no effective actor gate/);
    expect(s).toMatch(/third-party build of codex-action/);
  });

  it('is not credited to the Codex CLI in a run step', () => {
    expect(rank('codex-cli-run.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('codex-cli-run.yml')).toMatch(/no effective actor gate/);
  });

  it("is not credited when the job runs the PR's code before the Codex step", () => {
    expect(rank('codex-default-after-head-use.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('codex-default-after-head-use.yml')).toMatch(
      /write check runs after the job has checked out and used the PR's code/
    );
  });

  it('is credited when the PR head is checked out but nothing runs before the check', () => {
    expect(rank('codex-default-head-no-use.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  // What runs between the checkout and the Codex step decides: only a command that may execute
  // the checked-out files makes the action's check too late.
  const between = (run: string) =>
    analyzeWorkflow(
      '.github/workflows/x.yml',
      sub(
        read('codex-default-after-head-use.yml'),
        '      - run: npm ci\n',
        `      - run: |\n${run
          .split('\n')
          .map((l) => `          ${l}`)
          .join('\n')}\n`
      )
    );
  const late = /write check runs after the job has checked out and used the PR's code/;

  it.each([
    ['a test with a redirect', 'if [ -f package.json ]; then\n  echo found 2>&1\nfi'],
    ['a loop over git output', 'for f in $(git diff --name-only HEAD~1); do\n  echo "$f"\ndone'],
    ['a git fetch', 'git fetch --no-tags origin \\\n  main \\\n  +refs/pull/1/head'],
    ['git and echo', 'SHA=$(git rev-parse HEAD)\necho "sha=$SHA" >> "$GITHUB_OUTPUT"'],
    ['a comment and gh', '# fetch the PR\ngh pr view 1 --json title | jq -r .title'],
  ])('is credited when only %s runs in between', (_name, run) => {
    const f = between(run);
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(f!.signals.join(' | ')).not.toMatch(late);
  });

  it.each([
    ['a command after `if`', 'if npm run build; then\n  echo ok\nfi'],
    ['a command after a quoted env prefix', 'CI="1" npm ci'],
    ['a process substitution', 'cat <(./prepare.sh)'],
    ['a background command', 'git status & ./serve.sh'],
    ['a write to GITHUB_ENV', 'cat .env.ci >> "$GITHUB_ENV"'],
    ['a write to GITHUB_PATH', 'echo "$PWD/bin" >> "$GITHUB_PATH"'],
    ['a PATH that points into the checkout', 'export PATH="$PWD/bin:$PATH"\ngit status'],
    ['an install', 'npm install'],
    ['a script of the checkout', './scripts/setup.sh'],
    ['a build after a harmless command', 'echo building && make all'],
    ['a command substitution that runs code', 'echo "$(npm test)"'],
    ['a pipe into a shell', 'cat setup.sh | bash'],
    ['an interpreter', 'python3 tools/prepare.py'],
    ['a sourced file', 'source ./env.sh'],
  ])('is not credited when %s runs in between', (_name, run) => {
    const f = between(run);
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(f!.signals.join(' | ')).toMatch(late);
  });
});

describe('G3b: what the check of an action does not cover', () => {
  const late = /write check runs after the job has checked out and used the PR's code/;
  const withStep = (step: string) =>
    analyzeWorkflow(
      '.github/workflows/x.yml',
      sub(read('codex-default-after-head-use.yml'), '      - run: npm ci\n', step)
    );

  it.each([
    [
      'a dependency-installing setup action',
      '      - uses: ruby/setup-ruby@v1\n        with:\n          bundler-cache: true\n',
    ],
    [
      'an image build',
      '      - uses: docker/build-push-action@v6\n        with:\n          context: .\n',
    ],
    [
      'a script step',
      "      - uses: actions/github-script@v7\n        with:\n          script: require('./tools/prepare.js')\n",
    ],
  ])('%s between the checkout and the Codex step may run the PR code', (_name, step) => {
    const f = withStep(step);
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(f!.signals.join(' | ')).toMatch(late);
  });

  it('a runner setup action in between runs nothing of the PR', () => {
    const f = withStep(
      "      - uses: actions/setup-node@v4\n        with:\n          node-version: '22'\n"
    );
    expect(SEVERITY_RANK[f!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('allow-bots on a workflow a dispatch can start is not held by the check', () => {
    expect(rank('codex-bots-dispatch.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('codex-bots-dispatch.yml')).toMatch(/no effective actor gate/);
  });

  it('allow-bots on entity events only is held: the actor there is a person', () => {
    expect(rank('codex-bots-entity-only.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('an agent step that runs BEFORE the action step is not covered by its check', () => {
    expect(rank('codex-cli-before-action.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('codex-cli-before-action.yml')).toMatch(/no effective actor gate/);
  });

  // Known limit, on purpose: a conditional agent step is decided by its own `if:` (often a step
  // output computed for same-repository branches only), which is not read here.
  it('an earlier agent step with an if: of its own does not undo the check', () => {
    const y = sub(
      read('codex-cli-before-action.yml'),
      '      - env:\n          OPENAI_API_KEY:',
      "      - if: steps.surface.outputs.testable == 'true'\n        env:\n          OPENAI_API_KEY:"
    );
    const f = analyzeWorkflow('.github/workflows/x.yml', y);
    expect(SEVERITY_RANK[f!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('an action step whose failure is ignored stops nothing after it', () => {
    const y = sub(
      sub(
        read('codex-cli-before-action.yml'),
        /      - env:\n          OPENAI_API_KEY: .*\n        run: \|\n.*\n/,
        ''
      ),
      '          prompt: "Summarise the triage."\n',
      [
        '          prompt: "Summarise the triage."',
        '        continue-on-error: true',
        '      - env:',
        '          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}',
        '        run: |',
        '          codex exec --dangerously-bypass-approvals-and-sandbox "Triage: ${{ github.event.issue.title }} ${{ github.event.issue.body }}"',
        '',
      ].join('\n')
    );
    expect(y).toMatch(/continue-on-error: true/);
    const f = analyzeWorkflow('.github/workflows/x.yml', y);
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    // Without the flag the failed check ends the job before the CLI step.
    const g = analyzeWorkflow(
      '.github/workflows/x.yml',
      sub(y, '        continue-on-error: true\n', '')
    );
    expect(SEVERITY_RANK[g!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });
});

describe('CI-4 follows the same gates', () => {
  const withSecret = (f: string) =>
    analyzeWorkflowSecrets(
      '.github/workflows/x.yml',
      sub(
        read(f),
        '          GH_TOKEN: ${{ github.token }}',
        '          GH_TOKEN: ${{ github.token }}\n          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}'
      )
    );

  it('an extra secret behind a default codex-action step is a hardening note, not an alert', () => {
    const f = withSecret('codex-default-prompt-untrusted.yml');
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
  });

  it('the same secret behind allow-users "*" with a full shell is an alert', () => {
    const f = withSecret('codex-star-issues.yml');
    expect(f).not.toBeNull();
    expect(SEVERITY_RANK[f!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });
});
