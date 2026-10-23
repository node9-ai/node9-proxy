// fw#372 A7: an UNQUOTED Windows drive path reaches the jail with its
// backslashes. POSIX word resolution read `\U` as an escape, so
// `cat C:\Users\x\.ssh\id_rsa` handed the matcher `C:Usersx.sshid_rsa` and
// the key was allowed; the quoted spelling was closed earlier (JAIL-19). The
// gauntlet pinned the gap with it.fails rows; those markers come off with this.
import { describe, it, expect } from 'vitest';
import { analyzeFsOperation } from '../shell/index';

const v = (cmd: string) => {
  const r = analyzeFsOperation(cmd);
  return r ? `${r.verdict}:${r.ruleName}` : null;
};

describe('unquoted Windows drive paths in the jail', () => {
  it.each([
    ['cat C:\\Users\\x\\.ssh\\id_rsa', 'block:shield:project-jail:block-read-ssh'],
    ['cat C:\\Users\\x\\.aws\\credentials', 'block:shield:project-jail:block-read-aws'],
    ['cat C:\\proj\\.env', 'block:shield:project-jail:block-read-env'],
    ['type D:\\Users\\x\\.ssh\\id_rsa', 'block:shield:project-jail:block-read-ssh'],
    ['cp C:\\Users\\x\\.ssh\\id_rsa D:\\k', 'review:shield:project-jail:review-copy-ssh'],
  ])('%s', (cmd, expected) => {
    expect(v(cmd)).toBe(expected);
  });

  it('the quoted spelling and the forward-slash spelling keep their verdicts', () => {
    expect(v('cat "C:\\Users\\x\\.ssh\\id_rsa"')).toBe('block:shield:project-jail:block-read-ssh');
    expect(v('cat C:/Users/x/.ssh/id_rsa')).toBe('block:shield:project-jail:block-read-ssh');
  });

  it('an ordinary Windows path, and a drive path that is data, stay quiet', () => {
    expect(v('cat C:\\Users\\x\\notes.txt')).toBeNull();
    expect(v('echo C:\\Users\\x\\.ssh\\id_rsa')).toBeNull();
    expect(v('cat .ssh\\id_rsa')).toBeNull(); // no drive: the POSIX reading (`.sshid_rsa`) stands
  });
});
