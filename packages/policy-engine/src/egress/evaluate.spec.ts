// GAP-5 Phase 2 — egress destination policy evaluation.

import { describe, it, expect } from 'vitest';
import { evaluateEgress, hostMatches, isPrivateHost, type EgressPolicy } from './index';
import type { ShellDestination } from '../shell';

const dest = (host: string, binary = 'curl'): ShellDestination => ({ host, binary, raw: host });
const policy = (over: Partial<EgressPolicy> = {}): EgressPolicy => ({
  enabled: true,
  mode: 'review',
  allow: [],
  deny: [],
  allowPrivate: true,
  ...over,
});

describe('hostMatches', () => {
  it('exact, wildcard-apex, wildcard-subdomain, and "*"', () => {
    expect(hostMatches('github.com', 'github.com')).toBe(true);
    expect(hostMatches('api.github.com', '*.github.com')).toBe(true);
    expect(hostMatches('github.com', '*.github.com')).toBe(true); // apex via *.
    expect(hostMatches('a.b.github.com', '*.github.com')).toBe(true);
    expect(hostMatches('evil.com', '*.github.com')).toBe(false);
    expect(hostMatches('anything.test', '*')).toBe(true);
  });
});

describe('isPrivateHost', () => {
  it('flags loopback / RFC1918 / .local', () => {
    expect(isPrivateHost('localhost')).toBe(true);
    expect(isPrivateHost('127.0.0.1')).toBe(true);
    expect(isPrivateHost('10.0.0.5')).toBe(true);
    expect(isPrivateHost('192.168.1.10')).toBe(true);
    expect(isPrivateHost('172.16.0.1')).toBe(true);
    expect(isPrivateHost('db.local')).toBe(true);
    expect(isPrivateHost('evil.com')).toBe(false);
    expect(isPrivateHost('172.32.0.1')).toBe(false); // outside RFC1918
  });
});

describe('evaluateEgress', () => {
  it('returns null when disabled (even for unknown hosts)', () => {
    expect(evaluateEgress([dest('evil.com')], policy({ enabled: false }))).toBeNull();
  });

  it('unknown host → review (default mode)', () => {
    const v = evaluateEgress([dest('evil.com')], policy());
    expect(v?.verdict).toBe('review');
    expect(v?.host).toBe('evil.com');
  });

  it('unknown host → block when mode=block', () => {
    expect(evaluateEgress([dest('evil.com')], policy({ mode: 'block' }))?.verdict).toBe('block');
  });

  it('unknown host → null when mode=off (but still enabled for deny)', () => {
    expect(evaluateEgress([dest('evil.com')], policy({ mode: 'off' }))).toBeNull();
  });

  it('default allowlist passes (github, npm, anthropic) → null', () => {
    expect(evaluateEgress([dest('api.github.com')], policy())).toBeNull();
    expect(evaluateEgress([dest('registry.npmjs.org')], policy())).toBeNull();
    expect(evaluateEgress([dest('api.anthropic.com')], policy())).toBeNull();
  });

  it('user allowlist passes', () => {
    expect(
      evaluateEgress([dest('internal.corp.com')], policy({ allow: ['*.corp.com'] }))
    ).toBeNull();
  });

  it('deny list blocks — even when also private / mode off', () => {
    expect(
      evaluateEgress([dest('10.0.0.5')], policy({ deny: ['10.0.0.5'], mode: 'off' }))?.verdict
    ).toBe('block');
  });

  it('private hosts pass by default; blocked if allowPrivate=false', () => {
    expect(evaluateEgress([dest('localhost')], policy())).toBeNull();
    expect(evaluateEgress([dest('localhost')], policy({ allowPrivate: false }))?.verdict).toBe(
      'review'
    );
  });

  it('mixed destinations: a deny anywhere wins over an allowed one', () => {
    const v = evaluateEgress(
      [dest('api.github.com'), dest('evil.com')],
      policy({ deny: ['evil.com'] })
    );
    expect(v?.verdict).toBe('block');
    expect(v?.host).toBe('evil.com');
  });

  it('mixed: block-mode unknown wins over a later review-only path', () => {
    const v = evaluateEgress(
      [dest('a.unknown.test'), dest('b.unknown.test')],
      policy({ mode: 'block' })
    );
    expect(v?.verdict).toBe('block');
  });
});
