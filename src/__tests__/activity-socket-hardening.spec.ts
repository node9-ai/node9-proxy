/**
 * Unit tests for the activity-socket hardening helpers (Layer 1 + circuit breaker).
 *
 * Layer 1: bind failures must be loud — write to ~/.node9/hook-debug.log
 * unconditionally so silent listen() failures stop being invisible.
 *
 * Layer 2: rebind attempts are rate-limited via a circuit breaker —
 * max 5 attempts in any 60s window, otherwise we stop and emit
 * 'flight-recorder-down' over SSE so tail surfaces it to the user.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  __activitySocketTestHooks as h,
  ACTIVITY_REBIND_MAX_ATTEMPTS,
  ACTIVITY_REBIND_WINDOW_MS,
} from '../daemon/state.js';

describe('activity socket — circuit breaker', () => {
  beforeEach(() => {
    h.resetCircuitBreaker();
  });

  it('allows up to ACTIVITY_REBIND_MAX_ATTEMPTS attempts within the window', () => {
    const now = 1_000_000;
    for (let i = 0; i < ACTIVITY_REBIND_MAX_ATTEMPTS; i++) {
      expect(h.shouldRebind(now + i * 100)).toBe(true);
    }
  });

  it('trips after exceeding the limit in the window', () => {
    const now = 1_000_000;
    for (let i = 0; i < ACTIVITY_REBIND_MAX_ATTEMPTS; i++) {
      h.shouldRebind(now + i);
    }
    expect(h.shouldRebind(now + 1000)).toBe(false);
    expect(h.isCircuitTripped()).toBe(true);
  });

  it('resets the attempt counter once the window slides past', () => {
    const t0 = 1_000_000;
    for (let i = 0; i < ACTIVITY_REBIND_MAX_ATTEMPTS; i++) {
      h.shouldRebind(t0 + i);
    }
    // Past the window — old attempts age out, fresh attempt is allowed
    const tFar = t0 + ACTIVITY_REBIND_WINDOW_MS + 1;
    expect(h.shouldRebind(tFar)).toBe(true);
  });

  it('stays tripped once tripped — does not auto-recover even after window slides', () => {
    const t0 = 1_000_000;
    // Trip the breaker
    for (let i = 0; i <= ACTIVITY_REBIND_MAX_ATTEMPTS; i++) {
      h.shouldRebind(t0 + i);
    }
    expect(h.isCircuitTripped()).toBe(true);
    // Even far in the future, breaker stays tripped (manual restart required)
    expect(h.shouldRebind(t0 + ACTIVITY_REBIND_WINDOW_MS * 10)).toBe(false);
  });
});

// Review of 2026-11-06 (low 3): once the breaker had tripped, the 2 s probe kept
// running and logged "circuit breaker tripped" on every tick (about 43,000
// lines a day). The trip now stops the probe.
describe('activity socket — the probe stops when the breaker trips', () => {
  beforeEach(() => {
    h.resetCircuitBreaker();
  });

  it('a tripped rebind stops the health probe', () => {
    h.startProbeForTest();
    expect(h.isProbeRunning()).toBe(true);
    const t0 = Date.now();
    for (let i = 0; i <= ACTIVITY_REBIND_MAX_ATTEMPTS; i++) h.shouldRebind(t0 + i);
    h.attemptRebindForTest('test');
    expect(h.isProbeRunning()).toBe(false);
  });
});

// Code review of 2026-11-06 (lows 1 and 2): a pid of 0 or -1 in daemon.pid
// read as "another live daemon" (process.kill(0|-1, 0) does not throw), and a
// daemon that yielded to another stopped probing for good, so it never took
// the socket back after the other one exited.
describe('activity socket — yielding to another daemon', () => {
  beforeEach(() => {
    h.resetCircuitBreaker();
  });

  it('a pid outside the valid range is never another live daemon', () => {
    for (const pid of [0, -1, 2 ** 22 + 1, 1.5]) expect(h.isLiveOtherDaemonPid(pid)).toBe(false);
    expect(h.isLiveOtherDaemonPid(process.pid)).toBe(false);
  });

  it('yielding keeps the probe running, so the socket comes back later', () => {
    h.startProbeForTest();
    h.yieldForTest();
    expect(h.isProbeRunning()).toBe(true);
  });
});
