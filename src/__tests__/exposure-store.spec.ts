// Design 4.1, test row T1: the session exposure store.
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  SessionExposureStore,
  MAX_SOURCES,
  MAX_VALUES,
  SESSION_EXPOSURE_TTL_MS,
} from '../daemon/exposure-store';

afterEach(() => vi.useRealTimers());

describe('SessionExposureStore', () => {
  it('is exposed only after a source was read; mentions alone do not expose', () => {
    const s = new SessionExposureStore();
    s.mention('a', ['email:dani@example.com']);
    expect(s.check('a')).toBeNull();
    expect(s.list()).toEqual([]);
    s.mark('a', { tool: 'WebFetch', at: 1 }, ['host:evil.test']);
    const r = s.check('a');
    expect(r?.sources.map((x) => x.tool)).toEqual(['WebFetch']);
    expect(r?.destinations).toEqual(['host:evil.test']);
    expect(r?.userMentioned).toEqual(['email:dani@example.com']);
  });

  it('merges destinations across reads and caps them', () => {
    const s = new SessionExposureStore();
    s.mark('a', { tool: 'mcp__gmail__get_message', server: 'gmail', at: 1 }, ['email:x@y.z']);
    s.mark('a', { tool: 'mcp__gmail__get_message', server: 'gmail', at: 2 }, [
      'email:x@y.z',
      'iban:GB1',
    ]);
    expect(s.check('a')?.destinations.sort()).toEqual(['email:x@y.z', 'iban:GB1']);
    s.mark(
      'a',
      { tool: 'WebFetch', at: 3 },
      Array.from({ length: 500 }, (_, i) => `host:h${i}.x`)
    );
    expect(s.check('a')?.destinations.length).toBe(MAX_VALUES);
  });

  it('keeps the newest sources only', () => {
    const s = new SessionExposureStore();
    for (let i = 0; i < MAX_SOURCES + 5; i++) s.mark('a', { tool: `t${i}`, at: i });
    const r = s.check('a')!;
    expect(r.sources.length).toBe(MAX_SOURCES);
    expect(r.sources[0].tool).toBe('t5');
  });

  it('approve records keys; a dead session cannot be approved', () => {
    const s = new SessionExposureStore();
    expect(s.approve('a', ['x|y'])).toBe(false);
    s.mark('a', { tool: 'WebFetch', at: 1 });
    expect(s.approve('a', ['mcp__gmail__send_email|email:x@y.z'])).toBe(true);
    expect(s.check('a')?.approved).toEqual(['mcp__gmail__send_email|email:x@y.z']);
  });

  it('expires on the TTL and refreshes on every read', () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);
    const s = new SessionExposureStore();
    s.mark('a', { tool: 'WebFetch', at: 1 });
    vi.setSystemTime(1_000_000 + SESSION_EXPOSURE_TTL_MS - 1000);
    expect(s.check('a')).not.toBeNull();
    s.mark('a', { tool: 'WebFetch', at: 2 });
    vi.setSystemTime(1_000_000 + SESSION_EXPOSURE_TTL_MS + 1000);
    expect(s.check('a')).not.toBeNull();
    vi.setSystemTime(1_000_000 + 2 * SESSION_EXPOSURE_TTL_MS + 1000);
    expect(s.check('a')).toBeNull();
    expect(s.list()).toEqual([]);
  });

  it('clear and empty ids', () => {
    const s = new SessionExposureStore();
    s.mark('', { tool: 'WebFetch', at: 1 });
    expect(s.list()).toEqual([]);
    s.mark('a', { tool: 'WebFetch', at: 1 });
    expect(s.clearSession('a')).toBe(true);
    expect(s.clearSession('a')).toBe(false);
  });
});
