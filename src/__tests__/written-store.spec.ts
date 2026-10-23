// src/__tests__/written-store.spec.ts
// Unit tests for SessionWriteStore (fw#372 A3): record, check, expiry, cap.
import { describe, it, expect, vi, afterEach } from 'vitest';
import path from 'path';
import { SessionWriteStore, MAX_WRITTEN } from '../daemon/written-store.js';

afterEach(() => vi.useRealTimers());

describe('SessionWriteStore', () => {
  it('answers only for paths it recorded, resolved', () => {
    const s = new SessionWriteStore();
    s.record(['/tmp/p/run.sh']);
    expect(s.check(['/tmp/p/run.sh', '/tmp/p/other.sh'])).toEqual([path.resolve('/tmp/p/run.sh')]);
    expect(s.check(['/tmp/p/../p/run.sh'])).toEqual([path.resolve('/tmp/p/run.sh')]);
    expect(s.check([])).toEqual([]);
  });

  it('a record expires', () => {
    vi.useFakeTimers();
    const s = new SessionWriteStore();
    s.record(['/tmp/p/run.sh'], 1000);
    expect(s.check(['/tmp/p/run.sh'])).toHaveLength(1);
    vi.advanceTimersByTime(1001);
    expect(s.check(['/tmp/p/run.sh'])).toEqual([]);
    expect(s.size()).toBe(0);
  });

  it('keeps at most MAX_WRITTEN entries, dropping the oldest', () => {
    const s = new SessionWriteStore();
    s.record(Array.from({ length: MAX_WRITTEN + 5 }, (_, i) => `/tmp/w/f${i}`));
    expect(s.size()).toBe(MAX_WRITTEN);
    expect(s.check(['/tmp/w/f0'])).toEqual([]);
    expect(s.check([`/tmp/w/f${MAX_WRITTEN + 4}`])).toHaveLength(1);
  });

  it('ignores an empty or absurd path and prunes on request', () => {
    vi.useFakeTimers();
    const s = new SessionWriteStore();
    s.record(['', 'x'.repeat(5000), '/tmp/ok'], 10);
    expect(s.size()).toBe(1);
    vi.advanceTimersByTime(11);
    s.prune();
    expect(s.size()).toBe(0);
  });
});
