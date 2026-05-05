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
