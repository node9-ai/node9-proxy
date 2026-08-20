// Regression test: normalizeCommandForPolicy must collapse intra-word
// quote/escape obfuscation of shell command tokens, so destructive rules
// (which match on the normalized `command` field) can't be bypassed with
// r''m / \rm / pu''sh. Verified bypass in node9 v1.31.0.
//
// FP guard (also tested): only single structural tokens are de-obfuscated —
// multi-word quoted data strings keep their quotes, and message-flag values
// stay stripped — so legit commands and commit messages don't become commands.

import { describe, it, expect } from 'vitest';
import { normalizeCommandForPolicy } from './index';

const q = "''"; // empty single-quote pair (intra-word obfuscation)

describe('normalizeCommandForPolicy — intra-word de-obfuscation', () => {
  it('collapses empty-quote obfuscation of the command name (r%sm → rm)', () => {
    const out = normalizeCommandForPolicy(`r${q}m -rf /home/x`);
    expect(out).toMatch(/(^|\s)rm\s+-rf\b/);
  });

  it('collapses backslash obfuscation of the command name (\\rm → rm)', () => {
    const out = normalizeCommandForPolicy(`\\rm -rf /home/x`);
    expect(out).toMatch(/(^|\s)rm\s+-rf\b/);
  });

  it("collapses a fully single-quoted command name ('rm' → rm)", () => {
    const out = normalizeCommandForPolicy(`'rm' -rf ~`);
    expect(out).toMatch(/(^|\s)rm\s+-rf\b/);
  });

  it('collapses an obfuscated sub-command (git pu%sh → git push)', () => {
    const out = normalizeCommandForPolicy(`git pu${q}sh --force`);
    expect(out).toMatch(/git\s+push\s+--force/);
  });

  it('collapses obfuscated chmod (c%shmod → chmod)', () => {
    const out = normalizeCommandForPolicy(`c${q}hmod 777 /etc/passwd`);
    expect(out).toMatch(/(^|\s)chmod\s+777\b/);
  });

  // ── FP guards: must NOT turn data into commands ──
  it('does NOT unquote a multi-word data string (echo "rm -rf /" stays quoted)', () => {
    const input = `echo "rm -rf /"`;
    // unchanged → rm never reaches a command-position boundary
    expect(normalizeCommandForPolicy(input)).toBe(input);
  });

  it('still strips a commit message body, not turn it into a command', () => {
    const out = normalizeCommandForPolicy(`git commit -m "fix the r${q}m -rf bug"`);
    // message body gone (replaced with ""), so no command-position rm survives
    expect(out).not.toMatch(/(^|;|&&|\|\|)\s*rm\s+-rf/);
    expect(out).toContain('git commit -m');
  });

  it('leaves a clean command unchanged', () => {
    const input = 'rm -rf node_modules';
    expect(normalizeCommandForPolicy(input)).toBe(input);
  });
});
