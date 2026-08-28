import { describe, it, expect, afterEach, vi } from 'vitest';
import { locatorCommand, shellInvocation } from '../utils/platform-shell';

// Founder QA 2026-08-28 on Windows: `node9 <cmd>` died with
//   Error: spawn /bin/bash ENOENT
// because the proxy hardcoded a POSIX shell, and the executable probe ran
// `which`, which does not exist there either. Both are one definition now.
// process.platform is read-only, so each case redefines it and restores after.
function withPlatform(value: NodeJS.Platform, fn: () => void) {
  const original = Object.getOwnPropertyDescriptor(process, 'platform')!;
  Object.defineProperty(process, 'platform', { value, configurable: true });
  try {
    fn();
  } finally {
    Object.defineProperty(process, 'platform', original);
  }
}

describe('locatorCommand', () => {
  it('uses where on Windows and which elsewhere', () => {
    withPlatform('win32', () => expect(locatorCommand()).toBe('where'));
    withPlatform('linux', () => expect(locatorCommand()).toBe('which'));
    withPlatform('darwin', () => expect(locatorCommand()).toBe('which'));
  });
});

describe('shellInvocation', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('never returns a POSIX shell path on Windows (the ENOENT crash)', () => {
    withPlatform('win32', () => {
      const { file, args } = shellInvocation('echo hi');
      expect(file).not.toContain('/bin/');
      expect(args).toContain('echo hi');
    });
  });

  it('honours ComSpec, falling back to cmd.exe', () => {
    withPlatform('win32', () => {
      vi.stubEnv('ComSpec', 'C:\\Windows\\System32\\cmd.exe');
      expect(shellInvocation('dir').file).toBe('C:\\Windows\\System32\\cmd.exe');
      vi.stubEnv('ComSpec', '');
      expect(shellInvocation('dir').file).toBe('cmd.exe');
    });
  });

  it('passes /d on Windows so registry AutoRun cannot run first', () => {
    withPlatform('win32', () => {
      // AutoRun executes before the user's command — a governed shell must not
      // hand it an unexamined pre-command.
      expect(shellInvocation('dir').args[0]).toBe('/d');
    });
  });

  it('uses bash on POSIX — sh is dash on many systems', () => {
    withPlatform('linux', () => {
      expect(shellInvocation('echo hi')).toEqual({
        file: '/bin/bash',
        args: ['-c', 'echo hi'],
      });
    });
  });

  it('keeps the command as ONE argument so quoting survives', () => {
    const cmd = 'echo "a b" && ls';
    withPlatform('win32', () =>
      expect(shellInvocation(cmd).args.filter((a) => a === cmd)).toHaveLength(1)
    );
    withPlatform('linux', () =>
      expect(shellInvocation(cmd).args.filter((a) => a === cmd)).toHaveLength(1)
    );
  });
});
