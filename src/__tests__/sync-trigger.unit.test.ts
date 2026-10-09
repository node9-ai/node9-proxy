import { describe, expect, it, vi } from 'vitest';
import { createSyncTrigger } from '../daemon/sync-trigger';

describe('shared daemon sync trigger', () => {
  it('coalesces invalidations into one follow-up without overlapping the scheduled fetch', async () => {
    let release!: () => void;
    const first = new Promise<void>((resolve) => {
      release = resolve;
    });
    const sync = vi.fn().mockReturnValueOnce(first).mockResolvedValue(undefined);
    const trigger = createSyncTrigger(sync);
    const running = trigger(false);
    expect(trigger()).toBe(running);
    expect(trigger()).toBe(running);
    expect(sync).toHaveBeenCalledTimes(1);
    release();
    await running;
    expect(sync).toHaveBeenCalledTimes(2);
    await trigger(false);
    expect(sync).toHaveBeenCalledTimes(3);
  });
  it('releases the guard after failure', async () => {
    const sync = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValue(undefined);
    const trigger = createSyncTrigger(sync);
    await expect(trigger()).rejects.toThrow('offline');
    await trigger();
    expect(sync).toHaveBeenCalledTimes(2);
  });
});
