import { describe, it, expect } from 'vitest';
import { agoLabel } from '../lib/relative-time';

const NOW = Date.parse('2026-07-14T12:00:00.000Z');
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString();

describe('agoLabel', () => {
  it('renders sub-minute as "just now"', () => {
    expect(agoLabel(iso(30_000), NOW)).toBe('just now');
  });
  it('renders minutes', () => {
    expect(agoLabel(iso(4 * 60_000), NOW)).toBe('4 min ago');
  });
  it('renders hours with pluralization', () => {
    expect(agoLabel(iso(60 * 60_000), NOW)).toBe('1 hour ago');
    expect(agoLabel(iso(3 * 60 * 60_000), NOW)).toBe('3 hours ago');
  });
  it('renders days with pluralization', () => {
    expect(agoLabel(iso(24 * 60 * 60_000), NOW)).toBe('1 day ago');
    expect(agoLabel(iso(7 * 24 * 60 * 60_000), NOW)).toBe('7 days ago');
  });
  it('guards against future/invalid timestamps', () => {
    expect(agoLabel(iso(-5000), NOW)).toBe('just now');
    expect(agoLabel('not-a-date', NOW)).toBe('just now');
  });
});
