// S.3 — interpreter, network, shell and `gh` grants are broad
// (design: scanner-gaps-code-design.md §S.3, 2026-10-09). WRITTEN BEFORE THE IMPLEMENTATION.
//
// gradeBroadGrant knew only `Bash`, `Bash(*`, `Bash(git:`, `Write`, `Edit`. Committed configs in
// hand-verified repositories pre-approve `Bash(python -c:*)`, `Bash(PYTHONPATH=… python:*)`,
// `Bash(npx:*)`, `Bash(curl:*)`, `Bash(gh:*)`: each runs any code or reaches any host an
// injected instruction names, without a prompt. A grant is broad only when it ENDS in a wildcard:
// an exact command (`Bash(python3 -c "import sys")`) approves that one command and nothing else.

import { describe, it, expect } from 'vitest';
import { analyzeAgentConfig, analyzeSkillGrants, gradeBroadGrant } from '../ci-check/agent-config';

const broadOf = (allow: string[]) => gradeBroadGrant(allow, [])?.broad ?? [];

describe('S.3 — newly broad grants', () => {
  const positives = [
    'Bash(python -c:*)',
    'Bash(python3:*)',
    'Bash(python3 *)',
    'Bash(PYTHONPATH=core:exports python:*)',
    'Bash(node:*)',
    'Bash(npx:*)',
    'Bash(uv run:*)',
    'Bash(curl:*)',
    'Bash(curl *)',
    'Bash(gh *)',
    'Bash(gh:*)',
    'Bash(source:*)',
    'Bash(xargs:*)',
  ];
  for (const g of positives)
    it(`${g} is broad, medium (not an unrestricted shell)`, () => {
      const r = gradeBroadGrant([g], []);
      expect(r?.broad).toEqual([g]);
      expect(r?.high).toBe(false);
    });

  it('a settings.json with `Bash(python -c:*)` yields CI-1.broad-allow medium', () => {
    const f = analyzeAgentConfig(
      '.claude/settings.local.json',
      JSON.stringify({ permissions: { allow: ['Bash(npm test:*)', 'Bash(python -c:*)'] } })
    ).find((x) => x.rule === 'CI-1.broad-allow');
    expect(f?.severity).toBe('medium');
    expect(f!.signals.join(' ')).toContain('Bash(python -c:*)');
  });

  it('a slash command granting `Bash(python3:*)` yields CI-1.skill-allowed-tools', () => {
    const md =
      '---\nallowed-tools: Bash(gh issue view:*), Bash(python3:*), Bash(gh issue comment:*)\n---\nRun the checker.\n';
    const f = analyzeSkillGrants('.claude/commands/dedupe.md', md);
    expect(f.map((x) => x.rule)).toContain('CI-1.skill-allowed-tools');
  });
});

describe('S.3 — what stays not broad', () => {
  const negatives = [
    'Bash(python -m pytest:*)',
    'Bash(npm run build)',
    'Bash(pnpm test:*)',
    'Bash(npx prettier:*)',
    'Bash(python3 -c "import sys; print(1)")',
    'Bash(PYRIGHT_PYTHON_IGNORE_WARNINGS=1 uv run pyright *)',
    'Bash(curl -s https://api.example.com/health)',
    'Bash(gh api repos/o/r/issues:*)',
    // The common read grant; getsentry/sentry's committed config (the low-FP fixture) has it.
    'Bash(gh api:*)',
    'Bash(gh issue view:*)',
    'Bash(python3)',
  ];
  for (const g of negatives)
    it(`${g} is not broad`, () => {
      expect(broadOf([g])).toEqual([]);
    });

  it('an unrestricted shell is still high', () => {
    expect(gradeBroadGrant(['Bash'], [])?.high).toBe(true);
  });
});
