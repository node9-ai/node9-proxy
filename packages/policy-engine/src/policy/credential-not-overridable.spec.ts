// A credential-file block is not overridable (node9Firewall#441, founder
// decision a, 2026-11-07). With a person able to approve, the host softens
// every block into an override card where Enter means Allow; for `.env`,
// ~/.ssh and ~/.aws that put a secret one reflexive Enter away. The engine
// marks these blocks `overridable: false`, which the host's
// mayDowngradeHardBlock already honours. Other block rules (block-rm-rf-home)
// keep the card.

import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import projectJail from '../shields/builtin/project-jail.json';
import type { SmartRule } from '../types';

const config = (checks: Record<string, string> = {}): PolicyConfig =>
  ({
    policy: {
      sandboxPaths: [],
      dangerousWords: [],
      ignoredTools: [],
      smartRules: [
        ...(projectJail.smartRules as SmartRule[]),
        {
          name: 'block-rm-rf-home',
          tool: 'bash',
          conditions: [{ field: 'command', op: 'matches', value: 'rm\\s+-rf\\s+~' }],
          verdict: 'block',
          reason: 'rm -rf in home',
        },
      ],
      toolInspection: { bash: 'command' },
      dlp: { enabled: false, scanIgnoredTools: false },
      checks,
    },
    settings: { mode: 'standard' },
  }) as unknown as PolicyConfig;

const verdict = (tool: string, args: unknown, checks?: Record<string, string>) =>
  evaluatePolicy(config(checks), tool, args, { agent: 'claude' }, {});

describe('credential-file blocks cannot be overridden', () => {
  it.each<[string, string, unknown]>([
    ['cat .env', 'Bash', { command: 'cat .env' }],
    ['cat ~/.ssh/id_rsa', 'Bash', { command: 'cat ~/.ssh/id_rsa' }],
    ['cat ~/.aws/credentials', 'Bash', { command: 'cat ~/.aws/credentials' }],
    ['inline python reading .env', 'Bash', { command: `python3 -c "print(open('.env').read())"` }],
    ['Read .env', 'Read', { file_path: '/home/u/p/.env' }],
    ['Read ~/.ssh/id_rsa', 'Read', { file_path: '/home/u/.ssh/id_rsa' }],
    ['Read ~/.aws/credentials', 'Read', { file_path: '/home/u/.aws/credentials' }],
  ])('%s', async (_name, tool, args) => {
    const v = await verdict(tool, args);
    expect(v.decision).toBe('block');
    expect(v.checkId).toBe('data.credential-files');
    expect(v.overridable).toBe(false);
  });

  // data.credential-files-other is not in the checks map; a block there comes
  // from the project-jail rule's own verdict being raised to block.
  it('covers the other credential files when their rule is raised to block', async () => {
    const raised = config();
    raised.policy.smartRules = raised.policy.smartRules.map((r) =>
      r.name === 'shield:project-jail:review-read-credentials-any-tool'
        ? { ...r, verdict: 'block' as const }
        : r
    );
    const v = await evaluatePolicy(
      raised,
      'Read',
      { file_path: '/home/u/.docker/config.json' },
      { agent: 'claude' },
      {}
    );
    expect(v.decision).toBe('block');
    expect(v.checkId).toBe('data.credential-files-other');
    expect(v.overridable).toBe(false);
  });
});

describe('other verdicts keep their override path', () => {
  it('rm -rf in home stays overridable', async () => {
    const v = await verdict('Bash', { command: 'rm -rf ~/projects/old-app' });
    expect(v.decision).toBe('block');
    expect(v.overridable).not.toBe(false);
  });

  it('a credential review is not a block and is not marked', async () => {
    const v = await verdict('Bash', { command: 'cat ~/.docker/config.json' });
    expect(v.decision).toBe('review');
    expect(v.overridable).toBeUndefined();
  });

  it('names known only at run time keep the card when set to block', async () => {
    const v = await verdict(
      'Bash',
      { command: 'find . -type f | xargs cat' },
      {
        'data.credential-files-unknown': 'block',
      }
    );
    expect(v.decision).toBe('block');
    expect(v.overridable).not.toBe(false);
  });
});
