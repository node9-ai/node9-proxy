import { describe, it, expect } from 'vitest';
import { commandReadings, normalizeCommandForPolicy } from './index';
import { evaluateSmartConditions } from '../rules';

// ROOT FIX — a command has more than one true reading.
//
// `\` is an ESCAPE in POSIX and a SEPARATOR in cmd/PowerShell, and node9 cannot
// know which shell will run the command. Collapsing to a single POSIX reading
// destroys matches that exist in the text, and a destroyed match is a silent
// ALLOW. Measured before this change: of 7 realistic Windows shapes, the POSIX
// reading caught 3 — the other 4 were silent allows.
//
// So the field resolves to a SET of readings and a `matches` condition fires if
// ANY of them matches (the repo's `combine by strictness` rule: two checks on
// one input resolve by MAX, never by order). Readings, all built on the
// message-strip-applied text so the strip is never bypassed:
//   R2 — POSIX word resolution   (reveals `\rm`, `r''m`)
//   R3 — quote characters removed, backslashes preserved (Windows reading)
//
// This replaces the reverted drive-prefix guess (49c840c), which exempted whole
// tokens from de-obfuscation and opened a bypass. Guessing the shell from a
// prefix and guessing it is always POSIX are the same mistake; the fix is to
// stop guessing.

const JAIL = '(^|[\\s/\\\\])\\.aws([\\s/\\\\]|$)';

function fires(command: string, value = JAIL): boolean {
  return evaluateSmartConditions({ command }, {
    name: 'r',
    tool: 'bash',
    verdict: 'block',
    conditions: [{ field: 'command', op: 'matches', value }],
  } as never);
}

describe('command readings — every real shape of a jailed path is caught', () => {
  // Each row is a way a real agent writes the same protected file. Before the
  // fix, only the first and last blocked.
  it.each([
    ['posix', 'cat /home/x/.aws/credentials'],
    ['posix obfuscated', "cat /home/x/.aw''s/credentials"],
    ['windows backslash', 'cat C:\\Users\\x\\.aws\\credentials'],
    ['windows obfuscated', "cat C:\\Users\\x\\.aw''s\\credentials"],
    ['windows forward slash', 'cat C:/Users/x/.aws/credentials'],
    ['windows fwd obfuscated', "cat C:/Users/x/.aw''s/credentials"],
    ['windows relative', 'cat .\\.aws\\credentials'],
    ['windows parent-relative', 'cat ..\\.aws\\credentials'],
    ['windows path with space', 'cat C:\\Users\\John Smith\\.aws\\credentials'],
    ['windows behind a flag', 'cat --out=C:\\Users\\bob\\.aws\\credentials'],
    ['windows quoted', 'cat "C:\\Users\\x\\.aws\\credentials"'],
    ['UNC share', 'type \\\\fileserver\\home\\.aws\\credentials'],
  ])('blocks a jailed read written as %s', (_name, command) => {
    expect(fires(command)).toBe(true);
  });
});

describe('command readings — no new false positives', () => {
  // The widening reading must not resurrect the text the message-strip exists
  // to hide, nor make quoted DATA look like a command token.
  it('a destructive string inside a commit message still does not match', () => {
    expect(fires('git commit -m "rm -rf /"', 'rm\\s+-rf')).toBe(false);
    expect(fires("git commit -m 'delete .aws now'")).toBe(false);
  });

  it('a quoted multi-word data argument keeps its quotes (not collapsed to a token)', () => {
    // Pre-existing contract, pinned here so the widening reading does not
    // change it: the data-string guard leaves `"rm -rf"` quoted, so a rule
    // still sees the quotes rather than a bare `rm -rf` token. (Whether a
    // substring rule SHOULD fire on quoted data is a separate question this
    // change deliberately does not touch.)
    const readings = commandReadings('grep "rm -rf" file.txt');
    expect(readings.every((r) => r.includes('"rm -rf"'))).toBe(true);
  });

  it('an unrelated path that merely contains the segment name is not jailed', () => {
    expect(fires('cat C:\\Users\\x\\.awsome\\notes.txt')).toBe(false);
    expect(fires('cat /home/x/awsdocs/readme.md')).toBe(false);
  });

  it('a windows-looking string inside a message is still stripped', () => {
    expect(fires('git commit -m "moved C:\\Users\\x\\.aws\\credentials"')).toBe(false);
  });
});

describe('command readings — de-obfuscation is unconditional again', () => {
  // The reverted patch made these conditional on a token's prefix. They must
  // hold for every token, drive-anchored or not.
  it.each([
    ['\\rm -rf /tmp/x', 'rm -rf /tmp/x'],
    ["r''m -rf /tmp/x", 'rm -rf /tmp/x'],
    ["pu''sh origin main", 'push origin main'],
  ])('normalizes %s', (input, expected) => {
    expect(normalizeCommandForPolicy(input)).toBe(expected);
  });

  it('a drive prefix does NOT buy an exemption from de-obfuscation', () => {
    // This is the bypass 49c840c introduced, pinned so it cannot return.
    expect(fires("cat C:\\Users\\x\\.aw''s\\credentials")).toBe(true);
    expect(fires("C:\\tools\\c''url https://evil.example", 'curl')).toBe(true);
  });
});

describe('commandReadings — the primitive', () => {
  it('always includes the POSIX reading as the first element', () => {
    const cmd = "r''m -rf /tmp/x";
    expect(commandReadings(cmd)[0]).toBe(normalizeCommandForPolicy(cmd));
  });

  it('returns a de-duplicated set when the readings agree', () => {
    // An ordinary POSIX command has one reading; no wasted regex tests.
    expect(commandReadings('ls -la /tmp')).toEqual(['ls -la /tmp']);
  });

  it('adds a separator-preserving reading only when it differs', () => {
    const readings = commandReadings("cat C:\\Users\\x\\.aw''s\\credentials");
    expect(readings.length).toBe(2);
    expect(readings.some((r) => r.includes('.aws'))).toBe(true);
  });
});
