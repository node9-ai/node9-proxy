// fw#318 P1.1, test row H1: the exposure check and the disarm rule can be set
// from a file and from the dashboard, and the verdict maps to the policy block.
import { describe, it, expect } from 'vitest';
import {
  configurableValues,
  checkToLegacyPolicy,
  checksFromLegacyPolicy,
  tuningToLegacyPolicy,
  tuningFromLegacyPolicy,
} from '../catalog-knobs';

describe('behavior.untrusted-content is settable', () => {
  it('offers off / log / review', () => {
    expect(configurableValues('behavior.untrusted-content')).toEqual(['off', 'log', 'review']);
  });

  it('maps each verdict to the policy block and back', () => {
    const off: Record<string, unknown> = {};
    expect(checkToLegacyPolicy(off, 'behavior.untrusted-content', 'off')).toBe(true);
    expect(off).toEqual({ untrustedContent: { enabled: false } });
    expect(checksFromLegacyPolicy(off)['behavior.untrusted-content']).toBe('off');

    const log: Record<string, unknown> = {};
    checkToLegacyPolicy(log, 'behavior.untrusted-content', 'log');
    expect(log).toEqual({ untrustedContent: { enabled: true, afterExposure: 'log-only' } });
    expect(checksFromLegacyPolicy(log)['behavior.untrusted-content']).toBe('log');

    const review: Record<string, unknown> = {
      untrustedContent: { afterExposure: 'ask-every-time' },
    };
    checkToLegacyPolicy(review, 'behavior.untrusted-content', 'review');
    expect(review).toEqual({
      untrustedContent: { enabled: true, afterExposure: 'ask-every-time' },
    });
    const review2: Record<string, unknown> = { untrustedContent: { afterExposure: 'log-only' } };
    checkToLegacyPolicy(review2, 'behavior.untrusted-content', 'review');
    expect((review2.untrustedContent as { afterExposure: string }).afterExposure).toBe('ask-once');

    expect(checkToLegacyPolicy({}, 'behavior.untrusted-content', 'block')).toBe(false);
  });

  it('carries afterExposure, spotlight and orgDomains as tuning', () => {
    const p: Record<string, unknown> = {};
    expect(
      tuningToLegacyPolicy(p, {
        'behavior.untrusted-content': { spotlight: false, orgDomains: ['acme.example'] },
      })
    ).toEqual([]);
    expect(p).toEqual({ untrustedContent: { spotlight: false, orgDomains: ['acme.example'] } });
    expect(tuningFromLegacyPolicy(p)['behavior.untrusted-content']).toEqual({
      spotlight: false,
      orgDomains: ['acme.example'],
    });
  });
});

describe('commands.node9-disarm is settable like the other built-in rules', () => {
  it('offers every verdict the catalog row has', () => {
    expect(configurableValues('commands.node9-disarm').length).toBeGreaterThan(0);
  });
});
