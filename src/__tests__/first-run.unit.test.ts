import { describe, expect, it } from 'vitest';
import { shouldOfferFirstRun, type FirstRunEnv } from '../cli/first-run';
import { isCI } from '../cli/interactive';
const fresh: FirstRunEnv = {
  stdinTTY: true,
  stdoutTTY: true,
  ci: false,
  hasConfig: false,
  hasCredentials: false,
};
describe('first-run eligibility', () => {
  it('offers setup on a fresh interactive terminal', () =>
    expect(shouldOfferFirstRun(fresh)).toBe(true));
  it.each([
    { stdinTTY: false },
    { stdoutTTY: false },
    { ci: true },
    { hasConfig: true },
    { hasCredentials: true },
  ])('does not offer setup with %j', (override) =>
    expect(shouldOfferFirstRun({ ...fresh, ...override })).toBe(false)
  );
  it.each(['1', 'true', 'yes'])('recognizes CI=%s', (CI) => expect(isCI({ CI })).toBe(true));
  it.each(['0', 'false', 'no', ''])('recognizes disabled CI=%s', (CI) =>
    expect(isCI({ CI })).toBe(false)
  );
});
