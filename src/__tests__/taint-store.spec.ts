// src/__tests__/taint-store.spec.ts
// Unit tests for TaintStore: taint, check, propagate, expiry, prune.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import path from 'path';
import { TaintStore } from '../daemon/taint-store.js';

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
