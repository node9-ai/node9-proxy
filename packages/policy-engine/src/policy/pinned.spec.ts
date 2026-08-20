import { describe, it, expect } from 'vitest';
import { resolvePinned, evaluatePolicy } from './index';
import type { SmartRule } from '../types';

const rule = (over: Partial<SmartRule>): SmartRule => ({
  tool: 'bash',
  conditions: [],
  verdict: 'allow',
  ...over,
});

describe('resolvePinned (pinned-only conflict engine)', () => {
  it('returns undefined for no matches', () => {
    expect(resolvePinned([])).toBeUndefined();
  });

  it('ZERO-REGRESSION: with nothing pinned, returns the FIRST match', () => {
    // This is the whole safety guarantee — identical to the old `.find()`.
    const r = resolvePinned([
      rule({ name: 'a', verdict: 'allow' }),
      rule({ name: 'b', verdict: 'block' }),
    ]);
    expect(r?.name).toBe('a'); // first wins, NOT most-restrictive
  });

  it('a single pinned rule wins over a non-pinned earlier match', () => {
    const r = resolvePinned([
      rule({ name: 'local-allow', verdict: 'allow' }),
      rule({ name: 'org:pinned-block', verdict: 'block', pinned: true }),
    ]);
    expect(r?.name).toBe('org:pinned-block');
  });

  it('a pinned ALLOW still wins over a non-pinned block (manager keep-mine)', () => {
    const r = resolvePinned([
      rule({ name: 'local-block', verdict: 'block' }),
      rule({ name: 'org:pinned-allow', verdict: 'allow', pinned: true }),
    ]);
    expect(r?.verdict).toBe('allow');
    expect(r?.name).toBe('org:pinned-allow');
  });

  it('among multiple pinned rules, the strictest wins', () => {
    const r = resolvePinned([
      rule({ name: 'pin-allow', verdict: 'allow', pinned: true }),
      rule({ name: 'pin-block', verdict: 'block', pinned: true }),
      rule({ name: 'pin-review', verdict: 'review', pinned: true }),
    ]);
    expect(r?.verdict).toBe('block');
    expect(r?.name).toBe('pin-block');
  });

  it('ties among pinned keep the first', () => {
    const r = resolvePinned([
      rule({ name: 'first', verdict: 'block', pinned: true }),
      rule({ name: 'second', verdict: 'block', pinned: true }),
    ]);
    expect(r?.name).toBe('first');
  });
});

describe('AST suppression vs a pinned mandate (evaluatePolicy)', () => {
  const cfg = (chmod: 'off' | undefined, pinned: boolean) => ({
    policy: {
      sandboxPaths: [],
      dangerousWords: [],
      ignoredTools: [],
      toolInspection: { bash: 'command' },
      smartRules: [
        {
          name: 'shield:filesystem:review-chmod-777',
          tool: 'bash',
          conditions: [
            { field: 'command', op: 'matches', value: 'chmod\\s+(777|a\\+rwx)', flags: 'i' },
          ],
          conditionMode: 'all',
          verdict: 'review',
          reason: 'world-writable chmod requires review',
          ...(pinned ? { pinned: true } : {}),
        } as SmartRule,
      ],
      dlp: { enabled: false, scanIgnoredTools: false },
      ...(chmod ? { commandChecks: { chmod } } : {}),
    },
    settings: { mode: 'standard' },
  });
  const CHMOD = { command: 'chmod 777 /tmp/x' };

  it("chmod:'off' + PINNED shield rule → the mandate outlives the knob and speaks", async () => {
    const v = await evaluatePolicy(cfg('off', true), 'bash', CHMOD, { agent: 'claude' }, {});
    expect(v.decision).toBe('review');
    expect(v.ruleName).toBe('shield:filesystem:review-chmod-777');
  });

  it("chmod:'off' + unpinned twin → family-off silences BOTH tiers (no FP resurrection)", async () => {
    const v = await evaluatePolicy(cfg('off', false), 'bash', CHMOD, { agent: 'claude' }, {});
    expect(v.decision).toBe('allow');
  });

  it('chmod active → AST owns it; even a pinned twin stays suppressed (no double-fire)', async () => {
    const v = await evaluatePolicy(cfg(undefined, true), 'bash', CHMOD, { agent: 'claude' }, {});
    expect(v.decision).toBe('review');
    expect(v.blockedByLabel ?? '').toContain('AST');
  });
});
