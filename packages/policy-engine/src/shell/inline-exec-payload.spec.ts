// fw#372 X2: a shell's LITERAL -c payload is judged by its content, not
// reviewed as inline code on sight. The review stays for a dynamic payload,
// for one that runs a positional or evals, and for one that itself runs
// inline code that needs a review (fw#385: inline code is judged by what it
// does, so `sh -c 'python3 -c "print(1)"'` is ordinary). The jail and the
// other tiers keep reading the payload.
import { describe, it, expect } from 'vitest';
import { detectInlineExec } from './index';
import { evaluatePolicy } from '../policy';
import { DEFAULT_CONFIG } from '../../../../src/config';

const gate = (command: string) =>
  evaluatePolicy(DEFAULT_CONFIG, 'Bash', { command }, { agent: 'Claude Code' });

describe('a literal sh -c payload', () => {
  it.each([
    "sh -c 'ls -la'",
    'bash -c "npm run build && npm test"',
    "find . -name '*.log' -exec sh -c 'gzip \"$1\"' _ {} \\;",
    "sudo sh -c 'echo 1 > /proc/sys/vm/drop_caches'",
    "zsh -lc 'echo $PATH'",
  ])('%s is not inline code', (command) => {
    expect(detectInlineExec(command)).toBe(false);
  });

  it.each([
    'sh -c \'python3 -c "import os; os.remove(1)"\'',
    'sh -c "$CMD"',
    'bash -c \'eval "$x"\'',
    'sh -c \'"$0" "$@"\' prog a',
    'sh -c \'exec "$1"\' _ ls',
    "bash -c 'source ./env.sh && run'",
    'sh -c \'node -e "require(1).execSync(2)"\'',
    'bash -c "cat <<EOF | python3\nprint(1)\nEOF"',
  ])('%s still needs the review', (command) => {
    expect(detectInlineExec(command)).toBe(true);
  });

  it.each(['sh -c \'python3 -c "print(1)"\'', 'sh -c \'node -e "process.exit(1)"\''])(
    '%s runs ordinary inline code and needs no review (fw#385)',
    (command) => {
      expect(detectInlineExec(command)).toBe(false);
    }
  );

  it('the gate agrees: an ordinary payload passes, a nested dangerous one is reviewed', async () => {
    expect((await gate("sh -c 'ls -la'")).decision).toBe('allow');
    expect((await gate("find . -name '*.log' -exec sh -c 'gzip \"$1\"' _ {} \\;")).decision).toBe(
      'allow'
    );
    expect((await gate('sh -c \'python3 -c "print(1)"\'')).decision).toBe('allow');
    const nested = await gate('sh -c \'python3 -c "import os; os.system(1)"\'');
    expect(nested.decision).toBe('review');
    expect(nested.checkId).toBe('commands.inline-exec');
    expect((await gate('sh -c "$CMD"')).decision).not.toBe('allow');
  });

  it('the other interpreters are unchanged', () => {
    expect(detectInlineExec("python3 -c 'print(1)'")).toBe(true);
    expect(detectInlineExec("node -e 'console.log(1)'")).toBe(true);
    expect(detectInlineExec('python3 script.py -c cfg')).toBe(false);
  });
});
