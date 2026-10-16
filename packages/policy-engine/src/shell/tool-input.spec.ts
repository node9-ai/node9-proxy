import { describe, expect, it } from 'vitest';
import { resolveShellInput, shellRuleArgs } from './tool-input';
import { collectFileAccesses } from '../files/protected-access';

describe('shell input resolution', () => {
  it('supports explicit nested script mappings', () => {
    expect(
      resolveShellInput(
        'mcp__ci__run',
        { input: { script: 'ls' } },
        {
          mcp__ci__run: { kind: 'shell', field: 'input.script' },
        }
      )
    ).toEqual({ kind: 'shell', fieldPath: 'input.script', command: 'ls' });
  });
  it('keeps native commands authoritative', () => {
    expect(
      resolveShellInput(
        'Bash',
        { command: 'ls', decoy: 'echo safe' },
        {
          Bash: { kind: 'shell', field: 'decoy' },
        }
      )
    ).toMatchObject({ kind: 'shell', command: 'ls' });
  });
  it.each([{ command: ['ls'] }, {}, { command: 'ls', cmd: 'pwd' }])(
    'reports unsupported or ambiguous commands',
    (args) => {
      expect(resolveShellInput('mcp__ops__exec', args).kind).toBe('uninspectable');
    }
  );
  it('respects explicit SQL semantics and does not inspect free-form command fields', () => {
    expect(
      resolveShellInput(
        'mcp__db__exec',
        { query: 'select 1' },
        {
          mcp__db__exec: 'query',
        }
      ).kind
    ).toBe('not-shell');
    expect(resolveShellInput('send_message', { command: 'ls' }).kind).toBe('not-shell');
    expect(resolveShellInput('mcp__ops__exec_extra', { command: 'ls' }).kind).toBe('not-shell');
  });
  it('projects only Bash aliases and preserves custom-tool arguments', () => {
    const args = { cmd: 'ls' };
    expect(shellRuleArgs('exec', args, 'bash')).toEqual({ cmd: 'ls', command: 'ls' });
    expect(shellRuleArgs('exec', args, 'exec')).toBe(args);
    expect(shellRuleArgs('exec', args, '*')).toBe(args);
  });
  it('routes resolved commands to protected-file operation extraction', () => {
    expect(collectFileAccesses('exec', { cmd: 'cat /etc/shadow' })).toMatchObject([
      { operation: 'read', path: '/etc/shadow' },
    ]);
  });
});
