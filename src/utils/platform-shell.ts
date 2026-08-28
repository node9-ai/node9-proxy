// Platform primitives for locating a command and invoking a shell.
//
// Both existed inline in more than one place and both were Unix-only, which is
// the same bug twice: `which` does not exist on Windows (cmd printed
// "'which' is not recognized" and callers read the failure as "not found"), and
// `/bin/bash` does not exist there at all — `node9 <cmd>` crashed with
// `spawn /bin/bash ENOENT` on every Windows machine (founder QA 2026-08-28).
// One definition each, so a third caller cannot reintroduce either.

/** The command that resolves an executable's path on this platform. */
export function locatorCommand(): string {
  return process.platform === 'win32' ? 'where' : 'which';
}

/**
 * How to run `command` through a shell here.
 *
 * POSIX: bash, not /bin/sh — sh is dash on many systems and drops bash
 * builtins and bash-specific syntax.
 * Windows: ComSpec (cmd.exe). `/d` skips AutoRun commands from the registry,
 * which would otherwise execute before the user's command; `/s /c` keeps the
 * rest of the line intact so quoting survives.
 */
export function shellInvocation(command: string): { file: string; args: string[] } {
  if (process.platform === 'win32') {
    return {
      file: process.env.ComSpec || 'cmd.exe',
      args: ['/d', '/s', '/c', command],
    };
  }
  return { file: '/bin/bash', args: ['-c', command] };
}
