/**
 * Regression coverage for the dashboard's quit-key dispatch.
 *
 * Background: previously, an active approval card or filter-input mode
 * could swallow `q` and even `Ctrl+C`, leaving users stuck staring at
 * the dashboard until the daemon's own approvalTimeoutMs fired. The
 * shouldQuit() helper centralises the rules so we can test them without
 * mounting App.tsx (which would need full SSE / cost-loader plumbing).
 */
import { describe, expect, it } from 'vitest';

import { shouldQuit } from '../tui/dashboard/App';

describe('shouldQuit', () => {
  it('quits on plain q outside filter input mode', () => {
    expect(shouldQuit('q', {}, { filterInputMode: false })).toBe(true);
  });

  it('does NOT quit on q while typing into the filter (q is a printable char there)', () => {
    expect(shouldQuit('q', {}, { filterInputMode: true })).toBe(false);
  });

  it('quits on Ctrl+C even when typing into the filter', () => {
    expect(shouldQuit('c', { ctrl: true }, { filterInputMode: true })).toBe(true);
  });

  it('quits on Ctrl+C in normal mode too', () => {
    expect(shouldQuit('c', { ctrl: true }, { filterInputMode: false })).toBe(true);
  });

  it('does not quit on plain c (no ctrl modifier)', () => {
    expect(shouldQuit('c', {}, { filterInputMode: false })).toBe(false);
  });

  it('does not quit on unrelated keys', () => {
    expect(shouldQuit('a', {}, { filterInputMode: false })).toBe(false);
    expect(shouldQuit('1', {}, { filterInputMode: false })).toBe(false);
    expect(shouldQuit('', { ctrl: true }, { filterInputMode: false })).toBe(false);
  });
});
