// CI-2 over-grades on defended agent workflows (design: scanner-ci2-c4-c6-design.md, fw#481 C4
// and C6). WRITTEN BEFORE THE IMPLEMENTATION.
//
// C4-a: run-gemini-cli tool grants (`coreTools`, `tools.core`) were not read.
// C4-b: codex-action's built-in `permission-profile: ":read-only"` was not a read-only sandbox.
// C4-c: an agent whose known tools can only produce text, with no secret in its environment,
//       scored medium on reach alone.
// C6-a: an allow-list of author IDs in the job `if:` was not a gate.
// C6-b: a job `if:` that gates every privileged event, leaving only plain `pull_request` open,
//       was treated as privileged.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici';
import fs from 'fs';
import path from 'path';
import { analyzeWorkflow } from '../ci-check/workflows';
import { SEVERITY_RANK } from '../ci-check/types';
import { fetchGitHubTree } from '../ci-check/fetch';
import { scanTree } from '../ci-check';

const FX = path.join(__dirname, 'fixtures', 'ci-check', 'defended-agents');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');
const ci2 = (f: string) => analyzeWorkflow(`.github/workflows/${f}`, read(f));
const rank = (f: string) => {
  const r = ci2(f);
  return r ? SEVERITY_RANK[r.severity] : -1;
};
const signals = (f: string) => (ci2(f)?.signals ?? []).join(' | ');
const mitigations = (f: string) => (ci2(f)?.mitigations ?? []).join(' | ');
const TEXT_ONLY = /can only produce text/;

describe('C4-a: Gemini tool grants are read', () => {
  it('a gh write command with an issue-write token stays medium and is named', () => {
    expect(rank('gemini-shell-gh-edit.yml')).toBe(SEVERITY_RANK.medium);
    expect(signals('gemini-shell-gh-edit.yml')).toMatch(/gh issue edit/);
    expect(signals('gemini-shell-gh-edit.yml')).not.toMatch(TEXT_ONLY);
  });

  it('a read-only tool list can only produce text: advisory', () => {
    expect(rank('gemini-read-only.yml')).toBe(SEVERITY_RANK.advisory);
    expect(signals('gemini-read-only.yml')).toMatch(TEXT_ONLY);
  });

  it('no tool list is unknown, not "no tools": unchanged', () => {
    expect(rank('gemini-no-settings.yml')).toBe(SEVERITY_RANK.medium);
    expect(signals('gemini-no-settings.yml')).not.toMatch(TEXT_ONLY);
  });
});

describe('C4-b and C4-c: Codex read-only profile', () => {
  it('the built-in read-only profile with no secret in the environment: advisory', () => {
    expect(rank('codex-profile-read-only.yml')).toBe(SEVERITY_RANK.advisory);
    expect(signals('codex-profile-read-only.yml')).toMatch(TEXT_ONLY);
  });

  it('a flag that only tests whether a secret is set is not a secret', () => {
    expect(rank('codex-secret-flag.yml')).toBe(SEVERITY_RANK.advisory);
  });

  it('a named profile is unknown: unchanged', () => {
    expect(rank('codex-profile-named.yml')).toBe(SEVERITY_RANK.medium);
    expect(signals('codex-profile-named.yml')).not.toMatch(TEXT_ONLY);
  });

  it('a read-only sandbox with a secret in the job environment is not lowered', () => {
    expect(rank('codex-read-only-with-secret.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('codex-read-only-with-secret.yml')).not.toMatch(TEXT_ONLY);
  });
});

describe('C4-c: Claude with read tools only', () => {
  it('Read and Grep with a read-only token: advisory', () => {
    expect(rank('claude-read-tools.yml')).toBe(SEVERITY_RANK.advisory);
    expect(signals('claude-read-tools.yml')).toMatch(TEXT_ONLY);
  });

  it("a checkout at the root loads the repository's own settings: unknown, unchanged", () => {
    expect(rank('claude-read-tools-checkout.yml')).toBe(SEVERITY_RANK.medium);
    expect(signals('claude-read-tools-checkout.yml')).not.toMatch(TEXT_ONLY);
  });

  it('a checkout at the root with --setting-sources user: advisory', () => {
    expect(rank('claude-read-tools-setting-sources.yml')).toBe(SEVERITY_RANK.advisory);
  });

  it('a gh comment tool with an issue-write token: unchanged', () => {
    expect(rank('claude-comment-tool.yml')).toBe(SEVERITY_RANK.medium);
    expect(signals('claude-comment-tool.yml')).not.toMatch(TEXT_ONLY);
  });
});

describe('C6-a: author IDs in the job if', () => {
  it('a literal list of IDs is a gate', () => {
    expect(rank('author-ids-literal.yml')).toBeLessThanOrEqual(SEVERITY_RANK.advisory);
    expect(signals('author-ids-literal.yml')).not.toMatch(/no effective actor gate/);
    expect(mitigations('author-ids-literal.yml')).toMatch(/actor-gated/);
  });

  it('a list in a repository variable is not', () => {
    expect(rank('author-ids-vars.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('author-ids-vars.yml')).toMatch(/no effective actor gate/);
  });

  it('a block list is not', () => {
    expect(rank('author-ids-negated.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
    expect(signals('author-ids-negated.yml')).toMatch(/no effective actor gate/);
  });
});

describe('C6-b: a gate that covers every privileged event', () => {
  it('open only on plain pull_request: advisory', () => {
    expect(rank('per-event-gate.yml')).toBe(SEVERITY_RANK.advisory);
    expect(signals('per-event-gate.yml')).toMatch(/fork PRs run with a read-only token/);
  });

  it('an open comment command stays privileged', () => {
    expect(rank('per-event-open.yml')).toBeGreaterThanOrEqual(SEVERITY_RANK.medium);
  });
});

// C6-c: a job environment that requires a reviewer holds every run until someone approves it.
// The rule lives in the repository settings; the hosted scan and the Action ask GitHub.
describe('C6-c: protected environments', () => {
  const withEnv = (f: string, env: { protected: ReadonlySet<string> } | null) =>
    analyzeWorkflow(`.github/workflows/${f}`, read(f), undefined, undefined, undefined, env);
  const isProtected = { protected: new Set(['external-review']) };
  const notProtected = { protected: new Set<string>() };

  it('a protected environment holds the job: advisory, and says why', () => {
    const r = withEnv('env-literal.yml', isProtected)!;
    expect(r.severity).toBe('advisory');
    expect((r.mitigations ?? []).join(' | ')).toMatch(/requires a reviewer to approve each run/);
  });

  it('an environment GitHub says is open changes nothing and adds no line', () => {
    const r = withEnv('env-literal.yml', notProtected)!;
    expect(SEVERITY_RANK[r.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
    expect((r.mitigations ?? []).join(' | ')).not.toMatch(/environment/);
  });

  it('not read: unchanged grade, with a line that the rule was not visible', () => {
    const r = withEnv('env-literal.yml', null)!;
    expect(SEVERITY_RANK[r.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
    expect((r.mitigations ?? []).join(' | ')).toMatch(/not visible to this scan/);
  });

  it('every path held: still reported, as an advisory note', () => {
    const r = withEnv('env-all-held.yml', isProtected);
    expect(r?.severity).toBe('advisory');
    expect((r?.mitigations ?? []).join(' | ')).toMatch(/requires a reviewer/);
  });

  it('an environment picked by event holds that event only', () => {
    expect(withEnv('env-by-event.yml', isProtected)!.severity).toBe('advisory');
    expect(
      SEVERITY_RANK[withEnv('env-by-event.yml', notProtected)!.severity]
    ).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });
});

describe('C6-c: the GitHub reader asks about the environments of agent jobs', () => {
  let prev: Dispatcher;
  let agent: MockAgent;
  const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');
  const wf = read('env-literal.yml');
  const ENV_PATH = '/repos/o/{repo}/environments/external-review';

  beforeAll(() => {
    prev = getGlobalDispatcher();
    agent = new MockAgent();
    agent.disableNetConnect();
    setGlobalDispatcher(agent);
    const api = agent.get('https://api.github.com');
    for (const repo of ['guarded', 'open', 'unclear']) {
      api
        .intercept({ path: `/repos/o/${repo}/git/trees/HEAD?recursive=1`, method: 'GET' })
        .reply(200, {
          tree: [
            {
              path: '.github/workflows/review.yml',
              mode: '100644',
              type: 'blob',
              sha: 'w1',
              size: wf.length,
            },
          ],
          truncated: false,
        })
        .persist();
      api
        .intercept({ path: `/repos/o/${repo}/git/blobs/w1`, method: 'GET' })
        .reply(200, { sha: 'w1', encoding: 'base64', content: b64(wf), size: wf.length })
        .persist();
    }
    api
      .intercept({ path: ENV_PATH.replace('{repo}', 'guarded'), method: 'GET' })
      .reply(200, {
        name: 'external-review',
        protection_rules: [
          {
            type: 'required_reviewers',
            prevent_self_review: false,
            reviewers: [{ type: 'Team', reviewer: { id: 1 } }],
          },
        ],
      })
      .persist();
    api
      .intercept({ path: ENV_PATH.replace('{repo}', 'open'), method: 'GET' })
      .reply(404, { message: 'Not Found' })
      .persist();
    api
      .intercept({ path: ENV_PATH.replace('{repo}', 'unclear'), method: 'GET' })
      .reply(500, 'oops')
      .persist();
  });
  afterAll(async () => {
    setGlobalDispatcher(prev);
    await agent.close();
  });

  const ci2Of = (t: Awaited<ReturnType<typeof fetchGitHubTree>>) =>
    scanTree(t).findings.find((f) => f.rule === 'CI-2.injectable-workflow');

  it('a reviewers rule is read and holds the job', async () => {
    const t = await fetchGitHubTree('o', 'guarded');
    expect(t.environments).toEqual({ protected: ['external-review'] });
    expect(ci2Of(t)?.severity).toBe('advisory');
  });

  it('an environment that does not exist is read as open', async () => {
    const t = await fetchGitHubTree('o', 'open');
    expect(t.environments).toEqual({ protected: [] });
    expect(SEVERITY_RANK[ci2Of(t)!.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
  });

  it('an unclear answer credits nothing and says the rule was not visible', async () => {
    const t = await fetchGitHubTree('o', 'unclear');
    expect(t.environments).toBeUndefined();
    const f = ci2Of(t)!;
    expect(SEVERITY_RANK[f.severity]).toBeGreaterThanOrEqual(SEVERITY_RANK.high);
    expect((f.mitigations ?? []).join(' | ')).toMatch(/not visible to this scan/);
  });
});
