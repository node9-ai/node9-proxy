// Unit tests for the sandbox firewall allowlist compiler — the security-critical
// core. The SaaS-host invariant (fix #1) and deny-wins are the load-bearing ones.

import { describe, it, expect } from 'vitest';
import { compileAllowlist, isValidHost, NODE9_SAAS_HOSTS } from '../firewall';

const base = {
  agent: 'claude' as const,
  sandboxAllow: [] as string[],
  configAllow: [] as string[],
  configDeny: [] as string[],
};

describe('compileAllowlist', () => {
  it('always includes the agent provider host', () => {
    expect(compileAllowlist(base).allow).toContain('api.anthropic.com');
    expect(compileAllowlist({ ...base, agent: 'codex' }).allow).toContain('api.openai.com');
  });

  it('merges sandbox allow + config egress allow', () => {
    const r = compileAllowlist({
      ...base,
      sandboxAllow: ['api.github.com'],
      configAllow: ['registry.npmjs.org'],
    });
    expect(r.allow).toEqual(['api.anthropic.com', 'api.github.com', 'registry.npmjs.org']);
  });

  it('NEVER allowlists a node9 SaaS host, even if explicitly requested (fix #1)', () => {
    for (const saas of NODE9_SAAS_HOSTS) {
      const r = compileAllowlist({ ...base, sandboxAllow: [saas] });
      expect(r.allow).not.toContain(saas);
      expect(r.denied).toContain(saas);
    }
  });

  it('deny wins over allow', () => {
    const r = compileAllowlist({
      ...base,
      sandboxAllow: ['api.github.com'],
      configDeny: ['api.github.com'],
    });
    expect(r.allow).not.toContain('api.github.com');
    expect(r.denied).toContain('api.github.com');
  });

  it('rejects invalid hosts (junk / scheme / path / port) instead of passing them through', () => {
    const r = compileAllowlist({
      ...base,
      sandboxAllow: ['https://evil.com', 'a b', 'host:1234', 'foo/bar', ''],
    });
    expect(r.allow).toEqual(['api.anthropic.com']); // only the valid provider host
    expect(r.rejected).toContain('https://evil.com');
    expect(r.rejected).toContain('host:1234');
  });

  it('dedupes and sorts deterministically', () => {
    const r = compileAllowlist({
      ...base,
      sandboxAllow: ['b.com', 'a.com', 'b.com'],
      configAllow: ['a.com'],
    });
    expect(r.allow).toEqual(['a.com', 'api.anthropic.com', 'b.com']);
  });

  it('is case-insensitive', () => {
    const r = compileAllowlist({ ...base, sandboxAllow: ['API.GitHub.com'] });
    expect(r.allow).toContain('api.github.com');
  });
});

describe('isValidHost', () => {
  it('accepts normal hostnames', () => {
    expect(isValidHost('api.github.com')).toBe(true);
    expect(isValidHost('registry.npmjs.org')).toBe(true);
    expect(isValidHost('a.b.c.example.co')).toBe(true);
  });
  it('rejects schemes, paths, ports, whitespace, empty, single labels', () => {
    for (const bad of ['https://x.com', 'x.com/y', 'x.com:443', 'a b', '', 'localhost', '..']) {
      expect(isValidHost(bad)).toBe(false);
    }
  });
});
