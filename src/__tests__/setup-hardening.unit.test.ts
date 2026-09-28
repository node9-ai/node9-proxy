import { describe, expect, it } from 'vitest';
import { mayChangeService, SetupError } from '../cli/interactive';

describe('login service needs a person at a real terminal', () => {
  it('a terminal outside CI may install it, including init --recommended', () => {
    expect(mayChangeService({ stdoutTTY: true, ci: false })).toBe(true);
  });
  it('CI never touches it, even with a terminal attached', () => {
    expect(mayChangeService({ stdoutTTY: true, ci: true })).toBe(false);
  });
  it('a pipe, a Docker build or an agent never touches it', () => {
    expect(mayChangeService({ stdoutTTY: false, ci: false })).toBe(false);
  });
  it('--skip-setup never touches it', () => {
    expect(mayChangeService({ stdoutTTY: true, ci: false, skipSetup: true })).toBe(false);
  });
});

describe('SetupError', () => {
  it('is an Error the setup commands can tell apart from a crash', () => {
    const e = new SetupError('fix this');
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('SetupError');
    expect(e.message).toBe('fix this');
  });
});
