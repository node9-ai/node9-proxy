import { describe, it, expect } from 'vitest';
import {
  modeRank,
  resolveManagedMode,
  applyManagedEgress,
  applyManagedDlp,
  applyManagedApprovers,
} from '../config/managed';
import { extractManagedConfig } from '../daemon/sync';

const localEgress = (
  over: Partial<{
    enabled: boolean;
    mode: string;
    allow: string[];
    deny: string[];
    allowPrivate: boolean;
  }> = {}
) => ({
  enabled: false,
  mode: 'review',
  allow: ['local.example.com'],
  deny: [],
  allowPrivate: true,
  ...over,
});

const localDlp = (over: Partial<{ enabled: boolean; pii: string }> = {}) => ({
  enabled: true,
  scanIgnoredTools: true,
  pii: 'off' as string,
  ...over,
});

describe('managed mode (baseline+lock)', () => {
  it('ranks modes weakest→strictest', () => {
    expect(modeRank('observe')).toBeLessThan(modeRank('audit'));
    expect(modeRank('audit')).toBeLessThan(modeRank('standard'));
    expect(modeRank('standard')).toBeLessThan(modeRank('strict'));
    expect(modeRank('nonsense')).toBe(-1);
  });

  describe('baseline (unlocked) — cloud is a floor a dev can only tighten', () => {
    it('raises a weaker local mode up to the cloud floor', () => {
      // dev=observe, org=standard → bumped to standard
      expect(resolveManagedMode('observe', 'standard', false)).toBe('standard');
    });
    it('keeps a stricter local mode (a careful dev stays safer)', () => {
      // dev=strict, org=standard → keeps strict (the Ben case)
      expect(resolveManagedMode('strict', 'standard', false)).toBe('strict');
    });
    it('equal local stays put', () => {
      expect(resolveManagedMode('standard', 'standard', false)).toBe('standard');
    });
  });

  describe('locked — cloud wins outright', () => {
    it('forces a stricter local mode down to the locked value', () => {
      // dev=strict, org=standard, LOCKED → forced to standard
      expect(resolveManagedMode('strict', 'standard', true)).toBe('standard');
    });
    it('forces a weaker local mode up to the locked value', () => {
      expect(resolveManagedMode('observe', 'standard', true)).toBe('standard');
    });
  });

  it('ignores an unrankable cloud value (never weakens/breaks enforcement)', () => {
    expect(resolveManagedMode('strict', 'garbage', false)).toBe('strict');
    expect(resolveManagedMode('strict', 'garbage', true)).toBe('strict');
  });
});

describe('managed egress (baseline+lock) — M2b', () => {
  it('enabled is force-on: a managed true turns egress on', () => {
    const out = applyManagedEgress(localEgress({ enabled: false }), { enabled: true }, []);
    expect(out.enabled).toBe(true);
  });

  it('enabled force-on never turns a locally-enabled egress off', () => {
    // managed enabled omitted → local stays; managed true → stays on
    expect(applyManagedEgress(localEgress({ enabled: true }), { enabled: true }, []).enabled).toBe(
      true
    );
  });

  it('egress mode: raises a weaker local mode up to the cloud floor', () => {
    const out = applyManagedEgress(localEgress({ mode: 'off' }), { mode: 'review' }, []);
    expect(out.mode).toBe('review');
  });

  it('egress mode: keeps a stricter local mode (dev can be safer)', () => {
    const out = applyManagedEgress(localEgress({ mode: 'block' }), { mode: 'review' }, []);
    expect(out.mode).toBe('block');
  });

  it('egress mode: a locked value wins outright over a stricter local', () => {
    const out = applyManagedEgress(localEgress({ mode: 'block' }), { mode: 'review' }, [
      'egressMode',
    ]);
    expect(out.mode).toBe('review');
  });

  it('leaves untouched local fields (allow/deny) intact', () => {
    const out = applyManagedEgress(localEgress(), { enabled: true, mode: 'block' }, []);
    expect(out.allow).toEqual(['local.example.com']);
    expect(out.deny).toEqual([]);
    expect(out.allowPrivate).toBe(true);
  });

  it('ignores an unrankable managed egress mode', () => {
    const out = applyManagedEgress(localEgress({ mode: 'block' }), { mode: 'garbage' }, []);
    expect(out.mode).toBe('block');
  });

  it('allow: a managed allowlist REPLACES the local one (org owns it)', () => {
    const out = applyManagedEgress(localEgress(), { allow: ['api.node9.ai'] }, []);
    expect(out.allow).toEqual(['api.node9.ai']);
  });

  it('allow: an empty managed allowlist leaves the local one untouched', () => {
    const out = applyManagedEgress(localEgress(), { allow: [] }, []);
    expect(out.allow).toEqual(['local.example.com']);
  });

  it('deny: a managed denylist UNIONS with the local one (tightens)', () => {
    const out = applyManagedEgress(
      localEgress({ deny: ['bad.local'] }),
      { deny: ['evil.example.com', 'bad.local'] },
      []
    );
    expect(out.deny.sort()).toEqual(['bad.local', 'evil.example.com']);
  });

  it('allowPrivate: a managed false forces private access off', () => {
    const out = applyManagedEgress(
      localEgress({ allowPrivate: true }),
      { allowPrivate: false },
      []
    );
    expect(out.allowPrivate).toBe(false);
  });

  it('allowPrivate: a managed true leaves a stricter local false', () => {
    const out = applyManagedEgress(
      localEgress({ allowPrivate: false }),
      { allowPrivate: true },
      []
    );
    expect(out.allowPrivate).toBe(false);
  });

  it('allowPrivate: a locked value wins outright', () => {
    const out = applyManagedEgress(localEgress({ allowPrivate: false }), { allowPrivate: true }, [
      'egressAllowPrivate',
    ]);
    expect(out.allowPrivate).toBe(true);
  });
});

describe('managed dlp (baseline+lock) — M2c', () => {
  it('enabled is force-on', () => {
    expect(applyManagedDlp(localDlp({ enabled: false }), { enabled: true }, []).enabled).toBe(true);
  });

  it('pii: raises off → block (the cloud floor)', () => {
    expect(applyManagedDlp(localDlp({ pii: 'off' }), { pii: 'block' }, []).pii).toBe('block');
  });

  it('pii: keeps a stricter local block over a cloud off (dev can be safer)', () => {
    expect(applyManagedDlp(localDlp({ pii: 'block' }), { pii: 'off' }, []).pii).toBe('block');
  });

  it('pii: a locked value wins over a stricter local', () => {
    expect(applyManagedDlp(localDlp({ pii: 'block' }), { pii: 'off' }, ['dlpPii']).pii).toBe('off');
  });

  it('leaves untouched local fields (scanIgnoredTools) intact', () => {
    const out = applyManagedDlp(localDlp(), { enabled: true, pii: 'block' }, []);
    expect(out.scanIgnoredTools).toBe(true);
  });

  it('ignores an unrankable managed pii', () => {
    expect(applyManagedDlp(localDlp({ pii: 'block' }), { pii: 'garbage' }, []).pii).toBe('block');
  });
});

describe('managed approvers (Preferences)', () => {
  const local = { native: true, browser: false, cloud: false, terminal: true };

  it('replaces present managed fields, keeps the rest (org owns the surface)', () => {
    const out = applyManagedApprovers(local, { cloud: true, terminal: false });
    expect(out).toEqual({ native: true, browser: false, cloud: true, terminal: false });
  });

  it('an empty managed object leaves local untouched', () => {
    expect(applyManagedApprovers(local, {})).toEqual(local);
  });

  it('a managed false forces a surface off', () => {
    expect(applyManagedApprovers(local, { terminal: false }).terminal).toBe(false);
  });
});

describe('extractManagedConfig — reviewChannel + approvalTimeoutMs (Preferences v2)', () => {
  it('keeps a valid reviewChannel + numeric timeout', () => {
    const out = extractManagedConfig({
      managedConfig: { reviewChannel: 'ask', approvalTimeoutMs: 30000, locked: [] },
    });
    expect(out?.reviewChannel).toBe('ask');
    expect(out?.approvalTimeoutMs).toBe(30000);
  });

  it('keeps a valid injectionScan (coerced to known fields)', () => {
    const out = extractManagedConfig({
      managedConfig: {
        injectionScan: { enabled: true, minConfidence: 'high', allow: ['Bash'] },
        locked: [],
      },
    });
    expect(out?.injectionScan).toEqual({
      enabled: true,
      minConfidence: 'high',
      allow: ['Bash'],
    });
  });

  it('keeps trustedHosts (string-filtered)', () => {
    const out = extractManagedConfig({
      managedConfig: {
        trustedHosts: ['*.corp.com', 42 as unknown as string, 'api.corp.com', '*.com'],
        locked: [],
      },
    });
    // *.com dropped (too broad); non-strings dropped
    expect(out?.trustedHosts).toEqual(['*.corp.com', 'api.corp.com']);
  });

  it('keeps jailPaths (coerced, empty-path + junk-verdict handled)', () => {
    const out = extractManagedConfig({
      managedConfig: {
        jailPaths: [
          { path: '~/.secrets', verdict: 'review' },
          { path: '  ', verdict: 'block' },
          { path: '~/.aws', verdict: 'bogus' },
        ],
        locked: [],
      },
    });
    expect(out?.jailPaths).toEqual([
      { path: '~/.secrets', verdict: 'review' },
      { path: '~/.aws', verdict: 'block' },
    ]);
  });

  it('keeps loopDetection + skillPinning (coerced)', () => {
    const out = extractManagedConfig({
      managedConfig: {
        loopDetection: { enabled: true, threshold: 99999, windowSeconds: 0 },
        skillPinning: { enabled: true, mode: 'bogus', roots: ['a', ' ', 'b'] },
        locked: [],
      },
    });
    expect(out?.loopDetection).toEqual({
      enabled: true,
      threshold: 1000,
      windowSeconds: 1,
    });
    expect(out?.skillPinning).toEqual({
      enabled: true,
      mode: 'warn',
      roots: ['a', ' ', 'b'], // string-filtered only; BE resolver dedupes/trims
    });
  });

  it('drops an invalid reviewChannel and a negative timeout', () => {
    const out = extractManagedConfig({
      managedConfig: { reviewChannel: 'bogus', approvalTimeoutMs: -1, locked: [] },
    });
    expect(out).toBeUndefined();
  });
});
