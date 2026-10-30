// A git hook disarmed through a file operation (node9Firewall#413 part 2).
// Rows written from the category: removed, moved away, truncated, emptied,
// made inert by an edit; and the legitimate twins: a hook written with real
// content, an append, a read, a file elsewhere.
import { describe, it, expect } from 'vitest';
import { collectFileAccesses } from './protected-access';
import { evaluateGitHooksFileAccess, hookTextRunsNothing } from './git-hooks';
import type { CatalogSettings } from '../catalog';

const ctx = { cwd: '/home/u/repo', homeDirs: ['/home/u'] };
const settings = (mode = 'standard'): CatalogSettings => ({ mode });

function shell(command: string, mode?: string) {
  const accesses = collectFileAccesses('Bash', { command }, ctx);
  return evaluateGitHooksFileAccess({ command }, accesses, ctx, settings(mode), true);
}
function tool(name: string, args: Record<string, unknown>, mode?: string) {
  const accesses = collectFileAccesses(name, args, ctx);
  return evaluateGitHooksFileAccess(args, accesses, ctx, settings(mode), false);
}

describe('hookTextRunsNothing', () => {
  it.each([
    '',
    '\n\n',
    '#!/bin/sh\n',
    '#!/bin/sh\nexit 0\n',
    '#!/usr/bin/env sh\n# disabled\ntrue\n',
    'exit\n',
    ':\n',
    '#!/bin/sh\nset -e\nexit 0\n',
  ])('%j runs nothing', (text) => {
    expect(hookTextRunsNothing(text)).toBe(true);
  });
  it.each([
    '#!/bin/sh\nnpm test\n',
    '#!/bin/sh\n. "$(dirname "$0")/_/husky.sh"\nnpx lint-staged\n',
    'exit 1\n',
    '#!/bin/sh\nexit 0\nnpm test\n',
  ])('%j runs something', (text) => {
    expect(hookTextRunsNothing(text)).toBe(false);
  });
});

describe('a hook disarmed from the shell', () => {
  it.each([
    'rm .git/hooks/pre-commit',
    'rm -f .husky/pre-commit',
    'rm -rf .husky',
    'rm -rf .git/hooks',
    'mv .git/hooks/pre-commit .git/hooks/pre-commit.off',
    'mv .husky /tmp/husky-backup',
    ': > .husky/pre-commit',
    'echo "" > .git/hooks/pre-push',
    'echo "exit 0" > .husky/pre-commit',
    'truncate -s 0 .husky/pre-commit',
    'cp /dev/null .git/hooks/pre-commit',
    'tee .husky/pre-commit < /dev/null',
    'rm /home/u/repo/.git/hooks/pre-commit',
    'rm ~/repo/.husky/pre-commit',
    'cd .husky && rm pre-commit',
  ])('%s', (cmd) => {
    const v = shell(cmd);
    expect(v?.decision, cmd).toBe('review');
    expect(v?.ruleName).toBe('review-git-hooks-bypass');
    expect(v?.checkId).toBe('commands.git-hooks-bypass');
  });

  it.each([
    'cat .git/hooks/pre-commit',
    'ls -la .husky',
    'echo "npm test" >> .husky/pre-commit',
    'tee -a .husky/pre-commit <<< "npm test"',
    'touch .husky/pre-commit',
    'rm -rf node_modules',
    'rm .github/hooks.md',
    'rm hooks/pre-commit',
    'rm .huskyrc',
    'cp .husky/pre-commit /tmp/backup',
  ])('%s stays clean', (cmd) => {
    expect(shell(cmd), cmd).toBeNull();
  });
});

describe('a hook disarmed through a file tool', () => {
  it('Write with text that runs nothing', () => {
    const v = tool('Write', { file_path: '.husky/pre-commit', content: '#!/bin/sh\nexit 0\n' });
    expect(v?.decision).toBe('review');
    expect(v?.reason).toContain('emptied');
  });
  it('Write with an empty file', () => {
    expect(tool('Write', { file_path: '.git/hooks/pre-push', content: '' })?.decision).toBe(
      'review'
    );
  });
  it('Edit that puts exit 0 on its own line', () => {
    const v = tool('Edit', {
      file_path: '.husky/pre-commit',
      old_string: 'npm test',
      new_string: 'exit 0\nnpm test',
    });
    expect(v?.decision).toBe('review');
  });
  it('Edit that empties the hook', () => {
    expect(
      tool('Edit', { file_path: '.husky/pre-commit', old_string: 'npm test', new_string: '' })
        ?.decision
    ).toBe('review');
  });
  it('MultiEdit with one disarming edit', () => {
    const v = tool('MultiEdit', {
      file_path: '.husky/pre-commit',
      edits: [
        { old_string: 'a', new_string: 'b' },
        { old_string: 'npm test', new_string: 'true' },
      ],
    });
    expect(v?.decision).toBe('review');
  });
  it('str_replace_based_edit_tool create with an inert file', () => {
    const v = tool('str_replace_based_edit_tool', {
      command: 'create',
      path: '.git/hooks/pre-commit',
      file_text: '#!/bin/sh\n',
    });
    expect(v?.decision).toBe('review');
  });

  it.each([
    ['Write', { file_path: '.husky/pre-commit', content: '#!/bin/sh\nnpm test\n' }],
    ['Write', { file_path: '.husky/pre-commit', content: '#!/bin/sh\nnpx lint-staged\nexit 0\n' }],
    [
      'Edit',
      { file_path: '.husky/pre-commit', old_string: 'npm test', new_string: 'npm run lint' },
    ],
    [
      'Edit',
      {
        file_path: '.husky/pre-commit',
        old_string: 'a',
        new_string: 'if [ -z "$CI" ]; then exit 0; fi',
      },
    ],
    ['Write', { file_path: 'src/hooks/useThing.ts', content: '' }],
    ['Write', { file_path: '.github/workflows/ci.yml', content: '' }],
    ['Read', { file_path: '.husky/pre-commit' }],
  ])('%s %j stays clean', (name, args) => {
    expect(tool(name, args as Record<string, unknown>)).toBeNull();
  });
});

describe('the check value', () => {
  it('Soft logs, Strict blocks and is not overridable, off is silent', () => {
    const soft = shell('rm .husky/pre-commit', 'soft');
    expect(soft?.decision).toBe('allow');
    expect(soft?.logged).toBe(true);
    const strict = shell('rm .husky/pre-commit', 'strict');
    expect(strict?.decision).toBe('block');
    expect(strict?.overridable).toBe(false);
    const off = evaluateGitHooksFileAccess(
      { command: 'rm .husky/pre-commit' },
      collectFileAccesses('Bash', { command: 'rm .husky/pre-commit' }, ctx),
      ctx,
      { mode: 'standard', checks: { 'commands.git-hooks-bypass': 'off' } } as CatalogSettings,
      true
    );
    expect(off).toBeNull();
  });
});
