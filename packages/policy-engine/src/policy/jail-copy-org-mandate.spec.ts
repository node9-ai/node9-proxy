import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import type { SmartRule } from '../types';

// ─────────────────────────────────────────────────────────────────────────────
// A COPY REVIEW MUST NOT SILENCE AN ORG BLOCK
//
// /code-review, cross-file tracer (2026-09-12). Stage 4 returned the credential
// copy review from tier 2, ahead of the smart-rules tier. Before stage 4 the
// AST tier said nothing about `cp ~/.ssh/id_rsa /tmp/k`, so an org or user jail
// rule blocking that path -- `node9 jail add ~/.ssh`, or managedConfig.jailPaths,
// both emitted as a pinned, verb-agnostic pathRule -- fired and BLOCKED. After
// stage 4 the review returned first and the org's hard block never spoke: a
// fleet mandate downgraded to a prompt a user can click through.
//
// Two verdicts on one input resolve by MAX, never by order. A tier-2 BLOCK
// still returns immediately (a permissive user rule must not bypass it); a
// tier-2 REVIEW is carried to the tier-3 candidate set, where strictestVerdict
// lets a stricter rule win and a permissive `allow` rule cannot silence it.
// ─────────────────────────────────────────────────────────────────────────────

const K = '/home/u/.ssh/id_rsa';

/** The shape `pathRules` emits for a jail path: verb-agnostic regex over the
 *  raw command, pinned when it comes from the fleet. */
const orgBlock: SmartRule = {
  name: 'org:block-path-home-u-ssh-bash',
  tool: 'Bash',
  verdict: 'block',
  reason: 'Org policy: ~/.ssh is jailed',
  pinned: true,
  conditions: [
    { field: 'command', op: 'matches', value: '(^|[\\s/\\\\])\\.ssh([\\s/\\\\]|$)', flags: 'i' },
  ],
} as unknown as SmartRule;

const allowCp: SmartRule = {
  name: 'user:allow-cp',
  tool: 'Bash',
  verdict: 'allow',
  reason: 'user rule',
  conditions: [{ field: 'command', op: 'matches', value: '^cp\\b', flags: 'i' }],
} as unknown as SmartRule;

function cfg(rules: SmartRule[]): PolicyConfig {
  return {
    policy: {
      sandboxPaths: [],
      dangerousWords: [],
      ignoredTools: [],
      smartRules: rules,
      toolInspection: { bash: 'command' },
      dlp: { enabled: false, scanIgnoredTools: false },
    },
    settings: { mode: 'standard' },
  } as unknown as PolicyConfig;
}

const decide = (rules: SmartRule[], command: string) =>
  evaluatePolicy(cfg(rules), 'Bash', { command }, { agent: 'claude' }, {});

describe('a credential-copy review does not pre-empt a stricter rule', () => {
  it('controls: the copy alone is a review, and the org rule alone fires', async () => {
    expect((await decide([], `cp ${K} /tmp/k`)).decision).toBe('review');
    expect((await decide([orgBlock], `ls ${K}`)).decision).toBe('block');
  });

  it('with an org block on the same path, a copy is a BLOCK attributed to the org rule', async () => {
    const v = await decide([orgBlock], `cp ${K} /tmp/k`);
    expect(v.decision).toBe('block');
    expect(v.ruleName).toBe('org:block-path-home-u-ssh-bash');
  });

  it('the same for an archive of the jailed directory', async () => {
    expect((await decide([orgBlock], `tar czf /tmp/s.tgz /home/u/.ssh`)).decision).toBe('block');
  });

  it('a permissive user rule cannot silence the built-in copy review', async () => {
    const v = await decide([allowCp], `cp ${K} /tmp/k`);
    expect(v.decision).toBe('review');
    expect(v.ruleName).toBe('shield:project-jail:review-copy-ssh');
  });

  it('a READ block still returns at tier 2, ahead of any user rule (unchanged)', async () => {
    const v = await decide([allowCp], `cat ${K}`);
    expect(v.decision).toBe('block');
    expect(v.tier).toBe(2);
  });

  it('an ordinary copy is still allowed with the org rule present', async () => {
    expect((await decide([orgBlock], `cp /home/u/p/a.txt /tmp/b`)).decision).toBe('allow');
  });
});
