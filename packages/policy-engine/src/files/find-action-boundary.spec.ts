import { describe, expect, it } from 'vitest';
import { collectFileAccesses, evaluateProtectedFileAccess } from './protected-access';

const context = { cwd: '/work', homeDirs: ['/home/u'] };
describe('find executable action boundaries', () => {
  it.each([
    'find /workspace -maxdepth 1 -type f -exec mv {} / \\;',
    'find /workspace -atime -1 -type f -exec mv {} / \\;',
    'find /workspace -exec mv {} / + -print',
  ])('does not classify the destination as a removal source: %s', (command) => {
    const accesses = collectFileAccesses('Bash', { command }, context);
    expect(accesses.some((a) => a.operation === 'remove' && a.path === '/')).toBe(false);
    expect(evaluateProtectedFileAccess(accesses, context, {})).toBeNull();
  });
  it.each([
    'find /work -exec true {} \\; -exec rm /etc/passwd \\;',
    'find /work -exec mv /etc/passwd /tmp/backup \\;',
    'sudo find /work -exec cp /tmp/passwd /etc \\;',
    'find /etc -name passwd -exec rm {} \\;',
  ])('retains protected operations in every action: %s', (command) => {
    expect(
      evaluateProtectedFileAccess(collectFileAccesses('Bash', { command }, context), context, {})
        ?.decision
    ).toBe('block');
  });
});
