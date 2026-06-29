// Unit: resolveSyncIntervalMs — the cloud-sync cadence resolver.
// Pure (no timers/I/O): seconds wins over hours, hours over default, all clamped.
import { describe, it, expect } from 'vitest';
import { resolveSyncIntervalMs } from '../daemon/sync';

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
