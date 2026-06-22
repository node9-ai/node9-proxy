// Unit tests for the pure docker-run arg builder.

import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { buildRunArgs, agentCredentialsMount } from '../runtime';
import { defaultSandboxConfig } from '../config';

const mk = (overrides: Partial<Parameters<typeof buildRunArgs>[0]> = {}) =>
  buildRunArgs({
    config: defaultSandboxConfig('claude'),
    workspaceHostPath: '/home/me/proj',
    dataHostPath: '/home/me/proj/.node9/sandbox/data',
    allowlistHostPath: '/home/me/proj/.node9/sandbox/allowed-domains.txt',
    agentArgs: [],
    ...overrides,
  });

describe('buildRunArgs', () => {
  afterEach(() => vi.unstubAllEnvs());

  it('gives the container NET_ADMIN (root entrypoint seals iptables)', () => {
    expect(mk()).toContain('--cap-add=NET_ADMIN');
  });

  it('mounts workspace, node9 data, and the allowlist (ro)', () => {
    const a = mk().join(' ');
    expect(a).toContain('/home/me/proj:/workspace:rw');
    expect(a).toContain(':/home/agent/.node9');
    expect(a).toMatch(/allowed-domains\.txt:.*:ro/);
  });

  it('passes through only env vars that are actually set on the host', () => {
    vi.stubEnv('ANTHROPIC_API_KEY', 'sk-test');
    const a = mk().join(' ');
    expect(a).toContain('-e ANTHROPIC_API_KEY');
  });

  it('does NOT pass an env var that is unset on the host', () => {
    vi.stubEnv('ANTHROPIC_API_KEY', '');
    vi.unstubAllEnvs();
    delete process.env.ANTHROPIC_API_KEY;
    expect(mk().join(' ')).not.toContain('-e ANTHROPIC_API_KEY');
  });

  it('publishes declared ports and appends agent args last', () => {
    const cfg = defaultSandboxConfig('claude');
    cfg.inbound.expose = ['127.0.0.1:3000:3000'];
    const a = mk({ config: cfg, agentArgs: ['--resume'] });
    expect(a).toContain('127.0.0.1:3000:3000');
    expect(a[a.length - 1]).toBe('--resume');
    expect(a.indexOf('node9-sandbox:local')).toBeLessThan(a.indexOf('--resume'));
  });

  it('is --rm -it (disposable, interactive)', () => {
    const a = mk();
    expect(a).toContain('--rm');
    expect(a).toContain('-it');
    expect(a[0]).toBe('run');
  });

  it('mounts ONLY the credential file (rw) — not the whole ~/.claude dir', () => {
    const credPath = path.join(os.homedir(), '.claude', '.credentials.json');
    vi.spyOn(fs, 'existsSync').mockImplementation((p) => p === credPath);
    const a = mk().join(' ');
    expect(a).toContain(`${credPath}:/home/agent/.claude/.credentials.json`);
    // The whole dir must NOT be mounted (that would mask the box's node9 hooks).
    expect(a).not.toContain(`${path.join(os.homedir(), '.claude')}:/home/agent/.claude `);
    // rw (no :ro suffix)
    expect(a).not.toContain(`${credPath}:/home/agent/.claude/.credentials.json:ro`);
  });

  it('skips the credential mount when the host file is absent', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);
    expect(mk().join(' ')).not.toContain('.credentials.json');
  });

  it('skips the credential mount when mountAgentCredentials is false', () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    const cfg = defaultSandboxConfig('claude');
    cfg.node9.mountAgentCredentials = false;
    expect(mk({ config: cfg }).join(' ')).not.toContain('.credentials.json');
  });
});

describe('agentCredentialsMount', () => {
  it('maps each agent to its credential FILE (not the whole dir)', () => {
    expect(agentCredentialsMount('claude').target).toBe('/home/agent/.claude/.credentials.json');
    expect(agentCredentialsMount('codex').target).toBe('/home/agent/.codex/auth.json');
    expect(agentCredentialsMount('claude').hostPath).toBe(
      path.join(os.homedir(), '.claude', '.credentials.json')
    );
  });
});
