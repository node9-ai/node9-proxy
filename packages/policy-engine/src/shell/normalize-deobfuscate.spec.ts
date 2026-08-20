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

// ── Windows absolute paths are DATA, not obfuscation ─────────────────────────
// The de-obfuscation rewrite resolves each token's POSIX semantics, where `\\`
// is an escape — so an UNQUOTED Windows path "resolved" to a separator-less
// string (D:\\a\\x → D:ax) and every command-field path rule (the credential
// jail above all) silently stopped matching. Found by the Windows CI on
// 2026-08-19: `jail add` promised BLOCK while `cat D:\\...\\key.txt` ALLOWED.
// A drive-anchored or UNC token cannot be `\\rm`-style obfuscation, so it is
// left exactly as written; the jail regex matches `\\` via its [/\\] class.
describe('windows absolute paths survive normalization', () => {
  const WIN = 'D:\\a\\_temp\\7628637e-da97\\node9-jail\\.secrets\\key.txt';

  it('an unquoted drive-anchored path keeps its separators', () => {
    expect(normalizeCommandForPolicy(`cat ${WIN}`)).toBe(`cat ${WIN}`);
  });

  it('a UNC path keeps its separators', () => {
    const unc = '\\\\fileserver\\secrets\\key.txt';
    expect(normalizeCommandForPolicy(`type ${unc}`)).toBe(`type ${unc}`);
  });

  it('a lowercase drive letter is a drive too', () => {
    expect(normalizeCommandForPolicy('cat c:\\temp\\x.txt')).toBe('cat c:\\temp\\x.txt');
  });

  it('drive-anchoring does NOT shelter real obfuscation', () => {
    // The skip is anchored on `<letter>:[\\/]` / UNC — a bare `\\rm` matches
    // neither, so the de-obfuscation this rewrite exists for is untouched.
    expect(normalizeCommandForPolicy('\\rm -rf /tmp/x')).toBe('rm -rf /tmp/x');
    expect(normalizeCommandForPolicy("r''m -rf /tmp/x")).toBe('rm -rf /tmp/x');
  });

  it('a POSIX escaped space is still honoured (not mistaken for a path)', () => {
    expect(normalizeCommandForPolicy('cat foo\\ bar')).toBe('cat foo\\ bar');
  });
});
