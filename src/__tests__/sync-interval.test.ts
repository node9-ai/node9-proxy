// Unit: resolveSyncIntervalMs — the cloud-sync cadence resolver.
// Pure (no timers/I/O): seconds wins over hours, hours over default, all clamped.
import { describe, it, expect } from 'vitest';
import { resolveSyncIntervalMs, pickSyncIntervalMs } from '../daemon/sync';

const HOUR = 60 * 60 * 1000;

describe('resolveSyncIntervalMs', () => {
  it('defaults to 5h when nothing is set', () => {
    expect(resolveSyncIntervalMs({})).toBe(5 * HOUR);
  });

  it('uses cloudSyncIntervalHours when set (no seconds)', () => {
    expect(resolveSyncIntervalMs({ cloudSyncIntervalHours: 2 })).toBe(2 * HOUR);
  });

  it('seconds wins over hours', () => {
    expect(
      resolveSyncIntervalMs({
        cloudSyncIntervalSeconds: 20,
        cloudSyncIntervalHours: 5,
      })
    ).toBe(20 * 1000);
  });

  it('allows a fast 20s interval (the incident use case)', () => {
    expect(resolveSyncIntervalMs({ cloudSyncIntervalSeconds: 20 })).toBe(20_000);
  });

  it('clamps below the 15s floor (no API hammering)', () => {
    expect(resolveSyncIntervalMs({ cloudSyncIntervalSeconds: 1 })).toBe(15_000);
    expect(resolveSyncIntervalMs({ cloudSyncIntervalSeconds: 0.001 })).toBe(15_000);
  });

  it('clamps above the 24h ceiling', () => {
    expect(resolveSyncIntervalMs({ cloudSyncIntervalHours: 999 })).toBe(24 * HOUR);
  });
});

describe('pickSyncIntervalMs — cloud cadence wins (Phase 4)', () => {
  it('uses the cloud-pushed hours over local config', () => {
    expect(pickSyncIntervalMs(3, { cloudSyncIntervalSeconds: 20 })).toBe(3 * HOUR);
  });

  it('clamps the cloud value into [15s, 24h]', () => {
    expect(pickSyncIntervalMs(999, {})).toBe(24 * HOUR);
  });

  it('falls back to local config when no cloud value', () => {
    expect(pickSyncIntervalMs(undefined, { cloudSyncIntervalSeconds: 20 })).toBe(20_000);
  });

  it('ignores a non-finite cloud value (falls back)', () => {
    expect(pickSyncIntervalMs(NaN, { cloudSyncIntervalHours: 2 })).toBe(2 * HOUR);
  });
});
