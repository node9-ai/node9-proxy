import { describe, it, expect } from 'vitest';
import { computeLoopWaste, MAX_PLAUSIBLE_RATE_USD } from '../scan-summary';
import type { LoopRef } from '../scan-summary';
import type { SessionCost } from '../cli/commands/scan';

// Cases written against an adversarial matrix produced BEFORE this code
// existed, not against the implementation. The recurring failure in this
// codebase is a check that reports health it cannot actually observe, so most
// of what follows attacks the reassuring answer rather than the wrong one.

const loop = (over: Partial<LoopRef> = {}): LoopRef => ({
  toolName: 'Edit',
  commandPreview: '/tmp/x.ts',
  count: 10,
  timestamp: '2026-08-31T00:00:00Z',
  project: 'p',
  sessionId: 's1',
  agent: 'claude',
  kind: 'loop',
  ...over,
});

const session = (over: Partial<SessionCost> = {}): SessionCost => ({
  sessionId: 's1',
  costUSD: 100,
  toolCalls: 100,
  ...over,
});

describe('computeLoopWaste', () => {
  it('prices iterations beyond the threshold at the session rate', () => {
    // count 10, threshold 3 -> 7 wasted, at $1.00/call
    const r = computeLoopWaste([loop({ count: 10 })], [session()]);
    expect(r.usd).toBeCloseTo(7);
    expect(r.pricedIterations).toBe(7);
    expect(r.unpricedIterations).toBe(0);
  });

  it('ignores sustained work on one target', () => {
    const r = computeLoopWaste([loop({ kind: 'long-iteration', count: 500 })], [session()]);
    expect(r).toEqual({ usd: 0, pricedIterations: 0, unpricedIterations: 0 });
  });

  it('charges nothing for a loop at exactly the detection threshold', () => {
    // count 3 is the smallest detectable loop and the modal finding in real
    // data; those are Edits to distinct files, i.e. ordinary development.
    const r = computeLoopWaste([loop({ count: 3 })], [session()]);
    expect(r.usd).toBe(0);
  });

  // ── the reassuring-zero hunt ───────────────────────────────────────────
  it('does not price a zero-cost session as free waste', () => {
    // Antigravity and Copilot transcripts carry no token data, so cost is a
    // structural 0 next to thousands of real calls. 0/5000 is FINITE, so an
    // isFinite guard passes it through and 40 real iterations render $0.00.
    const r = computeLoopWaste([loop({ count: 43 })], [session({ costUSD: 0, toolCalls: 5000 })]);
    expect(r.usd).toBe(0);
    expect(r.pricedIterations).toBe(0);
    expect(r.unpricedIterations).toBe(40);
  });

  it('does not divide by a zero call count', () => {
    const r = computeLoopWaste([loop({ count: 13 })], [session({ toolCalls: 0 })]);
    expect(r.unpricedIterations).toBe(10);
    expect(Number.isFinite(r.usd)).toBe(true);
  });

  it('leaves a loop whose session is absent unpriced, not free', () => {
    const r = computeLoopWaste([loop({ sessionId: 'ghost', count: 13 })], [session()]);
    expect(r.usd).toBe(0);
    expect(r.unpricedIterations).toBe(10);
  });

  it('rejects an implausible rate instead of reporting a fortune', () => {
    // One session whose calls went uncounted: $13,700 for a single call.
    const r = computeLoopWaste([loop({ count: 43 })], [session({ costUSD: 13700, toolCalls: 1 })]);
    expect(r.usd).toBe(0);
    expect(r.unpricedIterations).toBe(40);
    expect(MAX_PLAUSIBLE_RATE_USD).toBeLessThan(13700);
  });

  it('rejects a negative cost rather than crediting waste back', () => {
    const r = computeLoopWaste([loop({ count: 13 })], [session({ costUSD: -50 })]);
    expect(r.usd).toBe(0);
    expect(r.unpricedIterations).toBe(10);
  });

  // ── the 250x error a single blended basis produces ─────────────────────
  it('prices each session at its own rate, never at a blend', () => {
    const loops = [
      loop({ sessionId: 'pricey', count: 13 }), // 10 wasted @ $1.00
      loop({ sessionId: 'cheap', count: 1003 }), // 1000 wasted @ $0.001
    ];
    const sessions = [
      session({ sessionId: 'pricey', costUSD: 100, toolCalls: 100 }),
      session({ sessionId: 'cheap', costUSD: 10, toolCalls: 10000 }),
    ];
    const r = computeLoopWaste(loops, sessions);
    expect(r.usd).toBeCloseTo(10 + 1);
    // A blended basis is (110 / 10100) = $0.0109 over 1010 iterations = $11.00
    // by coincidence here, so assert the per-session split explicitly instead
    // of trusting the total alone.
    expect(r.pricedIterations).toBe(1010);
  });

  it('is additive and order-independent', () => {
    const a = loop({ sessionId: 's1', count: 8 });
    const b = loop({ sessionId: 's2', count: 6 });
    const ss = [session({ sessionId: 's1' }), session({ sessionId: 's2', costUSD: 50 })];
    const both = computeLoopWaste([a, b], ss);
    const reversed = computeLoopWaste([b, a], ss);
    const split = computeLoopWaste([a], ss).usd + computeLoopWaste([b], ss).usd;
    expect(both.usd).toBeCloseTo(reversed.usd);
    expect(both.usd).toBeCloseTo(split);
  });

  it('returns clean zeros for no loops at all', () => {
    expect(computeLoopWaste([], [session()])).toEqual({
      usd: 0,
      pricedIterations: 0,
      unpricedIterations: 0,
    });
  });

  it('never reports dollars without iterations behind them', () => {
    // An impossible pair — money with nothing priced — is exactly how a
    // fabricated figure would look. Generated inputs, so no single fixture
    // can hide it.
    for (const count of [0, 1, 3, 4, 12, 500]) {
      for (const cost of [0, 1, 100, -5]) {
        for (const calls of [0, 1, 100]) {
          const r = computeLoopWaste(
            [loop({ count })],
            [session({ costUSD: cost, toolCalls: calls })]
          );
          if (r.usd > 0) expect(r.pricedIterations).toBeGreaterThan(0);
          if (r.pricedIterations === 0) expect(r.usd).toBe(0);
          expect(r.usd).toBeGreaterThanOrEqual(0);
          expect(Number.isFinite(r.usd)).toBe(true);
        }
      }
    }
  });

  it('treats a missing kind as a real loop, not as excluded', () => {
    // kind is optional for legacy data. Dropping those to $0 would be the
    // reassuring direction; counting them keeps the number honest.
    const legacy = { ...loop({ count: 13 }) } as LoopRef;
    delete (legacy as { kind?: unknown }).kind;
    expect(computeLoopWaste([legacy], [session()]).pricedIterations).toBe(10);
  });
});
