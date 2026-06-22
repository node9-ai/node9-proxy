// Unit tests for sandbox config merge — defaults, validation, and the fix-#1
// guard that NODE9_API_KEY can never be passed into the box.

import { describe, it, expect } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { mergeSandboxConfig, defaultSandboxConfig, scaffoldSandboxYaml } from '../config';

describe('mergeSandboxConfig', () => {
  it('returns sensible defaults for claude', () => {
    const c = mergeSandboxConfig({}, 'claude');
    expect(c.agent).toBe('claude');
    expect(c.outbound.mode).toBe('block');
    expect(c.outbound.allow).toContain('api.anthropic.com');
    expect(c.env.pass).toEqual(['ANTHROPIC_API_KEY']);
    expect(c.node9.approvals).toEqual({
      terminal: true,
      native: false,
      browser: false,
      cloud: false,
    });
  });

  it('STRIPS NODE9_API_KEY / NODE9_API_URL from env.pass (fix #1)', () => {
    const c = mergeSandboxConfig(
      { env: { pass: ['ANTHROPIC_API_KEY', 'NODE9_API_KEY', 'NODE9_API_URL', 'GITHUB_TOKEN'] } },
      'claude'
    );
    expect(c.env.pass).toEqual(['ANTHROPIC_API_KEY', 'GITHUB_TOKEN']);
    expect(c.env.pass).not.toContain('NODE9_API_KEY');
    expect(c.env.pass).not.toContain('NODE9_API_URL');
  });

  it('rejects an unsupported agent', () => {
    expect(() => mergeSandboxConfig({ agent: 'gpt5' }, 'claude')).toThrow(/unsupported agent/);
  });

  it('honors explicit overrides', () => {
    const c = mergeSandboxConfig(
      {
        agent: 'codex',
        workspace: { mode: 'ro' },
        runtime: { engine: 'podman', rebuild: 'always' },
        outbound: { allow: ['api.github.com'] },
        node9: { approvals: { terminal: false, cloud: true } },
      },
      'claude'
    );
    expect(c.agent).toBe('codex');
    expect(c.workspace.mode).toBe('ro');
    expect(c.runtime.engine).toBe('podman');
    expect(c.runtime.rebuild).toBe('always');
    expect(c.outbound.allow).toEqual(['api.github.com']);
    expect(c.node9.approvals.terminal).toBe(false);
    expect(c.node9.approvals.cloud).toBe(true);
  });

  it('codex defaults use the openai provider host + key', () => {
    const c = defaultSandboxConfig('codex');
    expect(c.outbound.allow).toContain('api.openai.com');
    expect(c.env.pass).toEqual(['OPENAI_API_KEY']);
  });

  it('scaffold YAML is parseable and never lists NODE9_API_KEY in env.pass', () => {
    const y = scaffoldSandboxYaml('claude');
    expect(y).toContain('agent: claude');
    const parsed = parseYaml(y) as { env: { pass: string[] } };
    expect(parsed.env.pass).not.toContain('NODE9_API_KEY');
  });
});
