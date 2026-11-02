// The credential jail must see a read however the file name reaches the
// reader. Found 2026-11-02 in the Claude desktop app: at Standard,
//   for f in .env fe/.env be/.env; do sed -E 's/=.+/=<set>/' "$f"; done
// read three .env files and was allowed. The jail read the reader's operands
// as written; the structural file-access walk, which already resolves loop
// variables, globs, $PWD and find -exec, was not consulted.
// Design: docs/roadmap/active/jail-indirect-reads-code-design.md.
//
// Rows assert at evaluatePolicy, the layer that gates.

import { describe, it, expect } from 'vitest';
import { evaluatePolicy, type PolicyConfig } from './index';
import projectJail from '../shields/builtin/project-jail.json';
import type { SmartRule } from '../types';

const config: PolicyConfig = {
  policy: {
    sandboxPaths: [],
    dangerousWords: [],
    ignoredTools: [],
    smartRules: projectJail.smartRules as SmartRule[],
    toolInspection: { bash: 'command', shell: 'command', run_shell_command: 'command' },
    dlp: { enabled: false, scanIgnoredTools: false },
  },
  settings: { mode: 'standard' },
} as unknown as PolicyConfig;

async function G(command: string): Promise<string> {
  const v = await evaluatePolicy(config, 'Bash', { command }, { agent: 'claude' }, {});
  return String(v.decision);
}

describe('step 1: names the file-access walk already resolves', () => {
  it.each([
    ['the founder case', `for f in .env fe/.env be/.env; do sed -E 's/=.+/=<set>/' "$f"; done`],
    ['a loop over one name', 'for f in .env; do cat "$f"; done'],
    ['a loop whose second item is jailed', 'for f in a .env; do cat "$f"; done'],
    ['a loop over a glob', 'for f in .e*; do cat "$f"; done'],
    ['a glob', 'cat .e*'],
    ['a one-character glob', 'cat .en?'],
    ['a bracket glob', 'cat .en[v]'],
    ['$PWD', 'cat "$PWD/.env"'],
    ['find -exec', 'find . -name .env -exec cat {} \;'],
  ])('blocks %s', async (_name, command) => {
    expect(await G(command)).toBe('block');
  });

  it('covers .ssh and .aws the same way', async () => {
    expect(await G('for f in ~/.ssh/id_rsa; do cat "$f"; done')).toBe('block');
    expect(await G('for f in ~/.aws/*; do cat "$f"; done')).toBe('block');
    expect(await G('cat ~/.ssh/id_*')).toBe('block');
  });
});

describe('the exemptions and everyday commands stay allowed', () => {
  it.each([
    'for f in .env.example; do cat "$f"; done',
    'for f in .env.test; do cat "$f"; done',
    'for f in src/*.ts; do wc -l "$f"; done',
    'cat *',
    'cat *.json',
    'ls .env',
    'ls -la .e*',
    'find . -name .env',
    'grep -r TODO .',
    'cat package.json',
  ])('allows %s', async (command) => {
    expect(await G(command)).not.toBe('block');
  });
});
