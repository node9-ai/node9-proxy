import { describe, it, expect } from 'vitest';
import { resolvePinned } from './index';
import type { SmartRule } from '../types';

const rule = (over: Partial<SmartRule>): SmartRule => ({
  tool: 'bash',
  conditions: [],
  verdict: 'allow',
  ...over,
});

describe('resolvePinned (pinned-only conflict engine)', () => {
  it('returns undefined for no matches', () => {
    expect(resolvePinned([])).toBeUndefined();
  });

  it('ZERO-REGRESSION: with nothing pinned, returns the FIRST match', () => {
    // This is the whole safety guarantee — identical to the old `.find()`.
    const r = resolvePinned([
      rule({ name: 'a', verdict: 'allow' }),
      rule({ name: 'b', verdict: 'block' }),
    ]);
    expect(r?.name).toBe('a'); // first wins, NOT most-restrictive
  });

  it('a single pinned rule wins over a non-pinned earlier match', () => {
    const r = resolvePinned([
      rule({ name: 'local-allow', verdict: 'allow' }),
      rule({ name: 'org:pinned-block', verdict: 'block', pinned: true }),
    ]);
    expect(r?.name).toBe('org:pinned-block');
  });

  it('a pinned ALLOW still wins over a non-pinned block (manager keep-mine)', () => {
    const r = resolvePinned([
      rule({ name: 'local-block', verdict: 'block' }),
      rule({ name: 'org:pinned-allow', verdict: 'allow', pinned: true }),
    ]);
    expect(r?.verdict).toBe('allow');
    expect(r?.name).toBe('org:pinned-allow');
  });

  it('among multiple pinned rules, the strictest wins', () => {
    const r = resolvePinned([
      rule({ name: 'pin-allow', verdict: 'allow', pinned: true }),
      rule({ name: 'pin-block', verdict: 'block', pinned: true }),
      rule({ name: 'pin-review', verdict: 'review', pinned: true }),
    ]);
    expect(r?.verdict).toBe('block');
    expect(r?.name).toBe('pin-block');
  });

  it('ties among pinned keep the first', () => {
    const r = resolvePinned([
      rule({ name: 'first', verdict: 'block', pinned: true }),
      rule({ name: 'second', verdict: 'block', pinned: true }),
    ]);
    expect(r?.name).toBe('first');
  });
});
