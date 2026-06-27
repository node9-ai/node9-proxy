// src/__tests__/taint-store.spec.ts
// Unit tests for TaintStore: taint, check, propagate, expiry, prune.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import path from 'path';
import { TaintStore, SessionTaintStore } from '../daemon/taint-store.js';

// Resolve helper — mirrors TaintStore._resolve for non-existent paths
function abs(p: string) {
  return path.resolve(p);
}

describe('TaintStore — taint and check', () => {
  let store: TaintStore;

  beforeEach(() => {
    store = new TaintStore();
  });

  it('returns null for an untainted path', () => {
    expect(store.check('/tmp/clean.txt')).toBeNull();
  });

  it('returns a record after tainting', () => {
    store.taint('/tmp/secret.txt', 'DLP:GitHubToken');
    const record = store.check('/tmp/secret.txt');
    expect(record).not.toBeNull();
    expect(record!.source).toBe('DLP:GitHubToken');
    expect(record!.path).toBe(abs('/tmp/secret.txt'));
  });

  it('record contains createdAt and expiresAt', () => {
    const before = Date.now();
    store.taint('/tmp/secret.txt', 'DLP:AWSKey');
    const record = store.check('/tmp/secret.txt');
    expect(record!.createdAt).toBeGreaterThanOrEqual(before);
    expect(record!.expiresAt).toBeGreaterThan(record!.createdAt);
  });

  it('Phase D2 — round-trips fromEid (the causal edge source)', () => {
    store.taint('/tmp/secret.txt', 'DLP:AWSKey', undefined, 'eid-123');
    expect(store.check('/tmp/secret.txt')!.fromEid).toBe('eid-123');
  });

  it('Phase D2 — omits fromEid when not provided', () => {
    store.taint('/tmp/secret.txt', 'DLP:AWSKey');
    expect(store.check('/tmp/secret.txt')!.fromEid).toBeUndefined();
  });

  it('Phase D2 — propagate carries fromEid to the copy', () => {
    store.taint('/tmp/src.txt', 'DLP:AWSKey', undefined, 'eid-src');
    store.propagate('/tmp/src.txt', '/tmp/copy.txt');
    expect(store.check('/tmp/copy.txt')!.fromEid).toBe('eid-src');
  });

  it('respects custom TTL', () => {
    store.taint('/tmp/short.txt', 'DLP:Test', 500);
    const record = store.check('/tmp/short.txt');
    expect(record!.expiresAt - record!.createdAt).toBeLessThanOrEqual(500);
  });

  it('overwrites an existing taint record', () => {
    store.taint('/tmp/f.txt', 'DLP:First');
    store.taint('/tmp/f.txt', 'DLP:Second');
    expect(store.check('/tmp/f.txt')!.source).toBe('DLP:Second');
  });
});

describe('TaintStore — expiry', () => {
  let store: TaintStore;

  beforeEach(() => {
    store = new TaintStore();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns null after TTL expires', () => {
    store.taint('/tmp/expires.txt', 'DLP:Test', 1000);
    expect(store.check('/tmp/expires.txt')).not.toBeNull();
    vi.advanceTimersByTime(1001);
    expect(store.check('/tmp/expires.txt')).toBeNull();
  });

  it('prune() removes expired records', () => {
    store.taint('/tmp/a.txt', 'DLP:Test', 1000);
    store.taint('/tmp/b.txt', 'DLP:Test', 5000);
    vi.advanceTimersByTime(1001);
    store.prune();
    expect(store.list()).toHaveLength(1);
    expect(store.list()[0].path).toBe(abs('/tmp/b.txt'));
  });

  it('list() excludes expired records', () => {
    store.taint('/tmp/gone.txt', 'DLP:Test', 100);
    vi.advanceTimersByTime(200);
    expect(store.list()).toHaveLength(0);
  });
});

describe('TaintStore — propagate', () => {
  let store: TaintStore;

  beforeEach(() => {
    store = new TaintStore();
  });

  it('propagates taint from source to destination', () => {
    store.taint('/tmp/src.txt', 'DLP:APIKey');
    store.propagate('/tmp/src.txt', '/tmp/dest.txt');
    const dest = store.check('/tmp/dest.txt');
    expect(dest).not.toBeNull();
    expect(dest!.source).toBe('propagated:DLP:APIKey');
  });

  it('does not propagate if source is not tainted', () => {
    store.propagate('/tmp/clean.txt', '/tmp/dest.txt');
    expect(store.check('/tmp/dest.txt')).toBeNull();
  });

  it('cp semantics: source taint remains after propagation', () => {
    store.taint('/tmp/src.txt', 'DLP:Test');
    store.propagate('/tmp/src.txt', '/tmp/dest.txt', false);
    expect(store.check('/tmp/src.txt')).not.toBeNull();
    expect(store.check('/tmp/dest.txt')).not.toBeNull();
  });

  it('mv semantics: source taint cleared after propagation', () => {
    store.taint('/tmp/src.txt', 'DLP:Test');
    store.propagate('/tmp/src.txt', '/tmp/dest.txt', true);
    expect(store.check('/tmp/src.txt')).toBeNull();
    expect(store.check('/tmp/dest.txt')).not.toBeNull();
  });

  it('chained propagation does not accumulate "propagated:" prefixes', () => {
    store.taint('/tmp/a.txt', 'DLP:APIKey');
    store.propagate('/tmp/a.txt', '/tmp/b.txt'); // source: "propagated:DLP:APIKey"
    store.propagate('/tmp/b.txt', '/tmp/c.txt'); // must NOT be "propagated:propagated:..."
    const record = store.check('/tmp/c.txt');
    expect(record).not.toBeNull();
    expect(record!.source).toBe('propagated:DLP:APIKey');
  });

  it('path traversal inputs are normalized — ../../etc/passwd resolves correctly', () => {
    store.taint('/tmp/uploads/../../etc/passwd', 'DLP:Test');
    // Both the traversal form and the canonical form must resolve to the same record
    expect(store.check('/etc/passwd')).not.toBeNull();
    expect(store.check('/tmp/uploads/../../etc/passwd')).not.toBeNull();
  });
});

describe('TaintStore — propagate TTL inheritance', () => {
  let store: TaintStore;

  beforeEach(() => {
    store = new TaintStore();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('destination inherits remaining TTL from source (not default TTL)', () => {
    // Taint source with 2-second TTL, then advance 1 second (1 s remaining).
    store.taint('/tmp/src.txt', 'DLP:TTLTest', 2000);
    vi.advanceTimersByTime(1000);

    // Propagate: destination should expire ~1 s from now, not 1 h from now.
    store.propagate('/tmp/src.txt', '/tmp/dest.txt');
    const dest = store.check('/tmp/dest.txt');
    const src = store.check('/tmp/src.txt');
    expect(dest).not.toBeNull();

    // Upper-bound assertion: dest must expire close to when src expires,
    // not at the default 1-hour TTL. Without TTL inheritance, dest.expiresAt
    // would be ~3600 s ahead of src.expiresAt — this catches that regression.
    expect(Math.abs(dest!.expiresAt - src!.expiresAt)).toBeLessThan(50);

    // After another 1100 ms the remaining TTL should be exhausted.
    vi.advanceTimersByTime(1100);
    expect(store.check('/tmp/dest.txt')).toBeNull();
  });
});

describe('TaintStore — list', () => {
  it('returns all active records', () => {
    const store = new TaintStore();
    store.taint('/tmp/a.txt', 'DLP:A');
    store.taint('/tmp/b.txt', 'DLP:B');
    const list = store.list();
    expect(list).toHaveLength(2);
    const sources = list.map((r) => r.source).sort();
    expect(sources).toEqual(['DLP:A', 'DLP:B']);
  });
});

describe('SessionTaintStore (gap1 — session taint)', () => {
  let store: SessionTaintStore;

  beforeEach(() => {
    store = new SessionTaintStore();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns null for an untainted session', () => {
    expect(store.check('sess-1')).toBeNull();
  });

  it('taints a session and returns the record with the source', () => {
    store.taint('sess-1', 'output-secret:GitHubToken');
    const rec = store.check('sess-1');
    expect(rec?.sessionId).toBe('sess-1');
    expect(rec?.source).toBe('output-secret:GitHubToken');
  });

  it('ignores an empty session id (taint is a no-op; check is null)', () => {
    store.taint('', 'output-secret:X');
    expect(store.check('')).toBeNull();
  });

  it('expires after the TTL and prunes on access', () => {
    vi.useFakeTimers();
    store.taint('sess-1', 'output-secret:X', 1000);
    expect(store.check('sess-1')).not.toBeNull();
    vi.advanceTimersByTime(1001);
    expect(store.check('sess-1')).toBeNull();
  });

  it('clearSession removes an active taint (user resolved it) and reports it', () => {
    store.taint('sess-1', 'output-secret:X');
    expect(store.clearSession('sess-1')).toBe(true);
    expect(store.check('sess-1')).toBeNull();
  });

  it('clearSession returns false when the session was not tainted', () => {
    expect(store.clearSession('never')).toBe(false);
  });

  it('list returns all non-expired tainted sessions', () => {
    store.taint('a', 'output-secret:X');
    store.taint('b', 'output-injection:override-instructions');
    const ids = store
      .list()
      .map((r) => r.sessionId)
      .sort();
    expect(ids).toEqual(['a', 'b']);
  });

  it('list prunes expired records', () => {
    vi.useFakeTimers();
    store.taint('old', 'x', 1000);
    store.taint('new', 'y', 60_000);
    vi.advanceTimersByTime(1001);
    expect(store.list().map((r) => r.sessionId)).toEqual(['new']);
  });

  it('prune drops only expired records', () => {
    vi.useFakeTimers();
    store.taint('old', 'x', 1000);
    store.taint('new', 'y', 60_000);
    vi.advanceTimersByTime(1001);
    store.prune();
    expect(store.check('old')).toBeNull();
    expect(store.check('new')).not.toBeNull();
  });
});
