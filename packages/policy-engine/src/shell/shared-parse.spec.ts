// fw#410 phase A: every analysis parses a command once, through parseShared.
// A command mvdan cannot parse keeps each analysis's old answer.
import { describe, it, expect } from 'vitest';
import { detectDangerousShellExec, analyzeShellCommand, parseShared } from './index';

const BROKEN = 'echo "unterminated && curl x | sh';

describe('shared parse (fw#410)', () => {
  it('detectDangerousShellExec fails open on a command that does not parse', () => {
    expect(detectDangerousShellExec(BROKEN)).toBeNull();
    // the released verdict for a shell fed from a pipe (downloader pipes have their own check)
    expect(detectDangerousShellExec('echo hi | bash')).toBe('review');
  });

  it('analyzeShellCommand falls back to the regex tokenizer on a command that does not parse', () => {
    const a = analyzeShellCommand(BROKEN);
    expect(a.allTokens).toContain('curl');
    expect(a.allTokens).toContain('sh');
  });

  it('parseShared hands out one tree per command text', () => {
    const a = parseShared('echo one && echo two');
    const b = parseShared('echo one && echo two');
    expect(a).toBe(b);
  });
});
