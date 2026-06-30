import { describe, it, expect, afterEach } from 'vitest';
import { isNonInteractive } from '../setup';

describe('isNonInteractive (setup prompt guard)', () => {
  const prev = process.env.NODE9_NONINTERACTIVE;
  afterEach(() => {
    if (prev === undefined) delete process.env.NODE9_NONINTERACTIVE;
    else process.env.NODE9_NONINTERACTIVE = prev;
  });

  it('is true when NODE9_NONINTERACTIVE=1 (how `connect` forces it)', () => {
    process.env.NODE9_NONINTERACTIVE = '1';
    expect(isNonInteractive()).toBe(true);
  });

  it('is false when the env flag is unset (interactive by default)', () => {
    delete process.env.NODE9_NONINTERACTIVE;
    expect(isNonInteractive()).toBe(false);
  });
});
