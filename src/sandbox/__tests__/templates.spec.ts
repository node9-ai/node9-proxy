// Unit tests for the generated container artifacts — assert the security shape of
// the rendered strings (no Docker needed in CI).

import { describe, it, expect } from 'vitest';
import { renderDockerfile, renderEntrypoint } from '../templates';
import { defaultSandboxConfig } from '../config';

const claude = defaultSandboxConfig('claude');
const codex = defaultSandboxConfig('codex');

describe('renderDockerfile', () => {
  it('installs the wall tooling, the agent CLI, and node9 (pinned)', () => {
    const df = renderDockerfile(claude, '1.39.0');
    expect(df).toMatch(/ipset/);
    expect(df).toMatch(/iptables/);
    expect(df).toContain('@anthropic-ai/claude-code');
    expect(df).toContain('node9-ai@1.39.0');
    expect(df).toContain('node9 agents add claude');
  });

  it('uses the codex package for codex', () => {
    expect(renderDockerfile(codex, '1.39.0')).toContain('@openai/codex');
  });

  it('runs the agent as a non-root user', () => {
    expect(renderDockerfile(claude, '1.39.0')).toMatch(/useradd .* agent/);
  });
});

describe('renderEntrypoint', () => {
  const sh = renderEntrypoint(claude);

  it('seals iptables deny-by-default (all three chains DROP)', () => {
    expect(sh).toContain('iptables -P INPUT   DROP');
    expect(sh).toContain('iptables -P FORWARD DROP');
    expect(sh).toContain('iptables -P OUTPUT  DROP');
  });

  it('only allows the resolved allowlist ipset for egress', () => {
    expect(sh).toContain('--match-set node9_allowed dst -j ACCEPT');
  });

  it('starts the node9 daemon and execs the agent as the non-root user', () => {
    expect(sh).toContain('node9 daemon --background');
    expect(sh).toContain('gosu "$RUN_AS_USER"');
    expect(sh).toContain('exec claude');
  });

  it('fails closed if the allowlist file is missing/empty', () => {
    expect(sh).toContain('[[ -s "$DOMAINS_FILE" ]]');
    expect(sh).toContain('allowed-domains.txt');
    expect(sh).toMatch(/missing\/empty/);
  });

  it('never references the node9 SaaS key', () => {
    expect(sh).not.toContain('NODE9_API_KEY');
  });
});
