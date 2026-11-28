// A snapshot push asked for between policy syncs (daemon/push-soon.ts).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createPushSoon, PUSH_SOON_DELAY_MS, PUSH_SOON_MIN_GAP_MS } from '../daemon/push-soon';

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe('createPushSoon', () => {
  it('pushes once, a short time after a burst of requests', async () => {
    const push = vi.fn().mockResolvedValue(true);
    const request = createPushSoon(push);
    request();
    await vi.advanceTimersByTimeAsync(30_000);
    request(); // the next round of the index, 30 s later
    request();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_DELAY_MS - 30_000 - 1);
    expect(push).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(push).toHaveBeenCalledTimes(1);
  });

  it('never pushes twice within the minimum gap, and still sends the later change', async () => {
    const push = vi.fn().mockResolvedValue(true);
    const request = createPushSoon(push);
    request();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_DELAY_MS);
    expect(push).toHaveBeenCalledTimes(1);
    // A change two minutes later waits for the gap since the last push.
    await vi.advanceTimersByTimeAsync(120_000);
    request();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_MIN_GAP_MS - 120_000 - 1);
    expect(push).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(push).toHaveBeenCalledTimes(2);
    // Long after: the short delay again, not the gap.
    await vi.advanceTimersByTimeAsync(PUSH_SOON_MIN_GAP_MS * 3);
    request();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_DELAY_MS);
    expect(push).toHaveBeenCalledTimes(3);
  });

  it('a request made while the push runs schedules the next one', async () => {
    let release!: () => void;
    const push = vi
      .fn()
      .mockReturnValueOnce(new Promise<boolean>((r) => (release = () => r(true))))
      .mockResolvedValue(true);
    const request = createPushSoon(push);
    request();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_DELAY_MS);
    request(); // the push collected before this change
    release();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_MIN_GAP_MS);
    expect(push).toHaveBeenCalledTimes(2);
  });

  it('a push that sent nothing (no key yet) does not hold the next one back', async () => {
    const push = vi.fn().mockResolvedValueOnce(false).mockResolvedValue(true);
    const request = createPushSoon(push);
    request();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_DELAY_MS);
    // node9 login, then a new server: the short delay, not the gap.
    request();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_DELAY_MS);
    expect(push).toHaveBeenCalledTimes(2);
  });

  it('a failing push does not stop the next one', async () => {
    const push = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValue(true);
    const request = createPushSoon(push);
    request();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_DELAY_MS);
    request();
    await vi.advanceTimersByTimeAsync(PUSH_SOON_MIN_GAP_MS);
    expect(push).toHaveBeenCalledTimes(2);
  });

  it('does not keep the process alive', () => {
    const request = createPushSoon(vi.fn().mockResolvedValue(true));
    request();
    expect(vi.getTimerCount()).toBe(1);
    // unref'd: Node exits with it pending (checked by the timer's own flag).
    const spy = vi.spyOn(globalThis, 'setTimeout');
    createPushSoon(vi.fn().mockResolvedValue(true))();
    const timer = spy.mock.results[0]?.value as { hasRef?: () => boolean };
    expect(timer.hasRef?.()).toBe(false);
  });
});
