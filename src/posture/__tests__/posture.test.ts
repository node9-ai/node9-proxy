// Unit tests for the posture checks + scoring.
//
// Covers: egress verdict logic, score mapping, and the secrets check against
// a planted fake secret in an isolated temp HOME — including the invariant
// that the secret VALUE is never surfaced in a finding.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { evaluateEgressConfig } from '../egress';
import { scorePosture } from '../score';
import { checkSecrets } from '../secrets';
import { parsePublicListeners } from '../containment';
import { checkSupplyChain } from '../supply-chain';
import { checkCoverage } from '../coverage';
import type { Finding } from '../types';

// A fake token assembled at runtime — matches the DLP "GitHub Token" pattern
// once joined, but no secret-shaped literal appears in this source file.
const FAKE_TOKEN = ['ghp', '_', 'A1b2C3d4E5f6', 'G7h8I9j0K1l2', 'M3n4O5p6Q7r8'].join('');

describe('evaluateEgressConfig', () => {
  it('flags HIGH when egress is disabled', () => {
    const f = evaluateEgressConfig({ enabled: false, mode: 'off' });
    expect(f?.severity).toBe('high');
    expect(f?.category).toBe('Egress');
  });

  it('flags HIGH when enabled but mode is off', () => {
    const f = evaluateEgressConfig({ enabled: true, mode: 'off' });
    expect(f?.severity).toBe('high');
  });

  it('flags MEDIUM in review mode (logged, not blocked)', () => {
    const f = evaluateEgressConfig({ enabled: true, mode: 'review' });
    expect(f?.severity).toBe('medium');
  });

  it('passes (null) when locked to block', () => {
    const f = evaluateEgressConfig({ enabled: true, mode: 'block' });
    expect(f).toBeNull();
  });
});

describe('scorePosture', () => {
  const mk = (severity: Finding['severity']): Finding => ({
    category: 'X',
    severity,
    title: 't',
    detail: [],
  });

  it('a clean run (no findings) scores 100/good', () => {
    expect(scorePosture([], 3)).toEqual({ score: 100, tier: 'good' });
  });

  it('any critical finding lands in the critical tier', () => {
    const { tier } = scorePosture([mk('critical')], 3);
    expect(tier).toBe('critical');
  });

  it('a single high finding lands at-risk (not critical)', () => {
    const { tier } = scorePosture([mk('high')], 3);
    expect(tier).toBe('at-risk');
  });

  it('advisory findings do not deduct', () => {
    expect(scorePosture([mk('advisory')], 3)).toEqual({ score: 100, tier: 'good' });
  });
});

describe('checkSecrets', () => {
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'posture-secrets-'));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('flags a plaintext secret in a .env file as critical', () => {
    fs.writeFileSync(path.join(home, '.env'), `GITHUB_TOKEN=${FAKE_TOKEN}\n`);
    const findings = checkSecrets({ home, cwd: home });
    const crit = findings.find((f) => f.severity === 'critical');
    expect(crit).toBeDefined();
    expect(crit?.category).toBe('Secrets');
  });

  it('never leaks the secret value into the finding', () => {
    fs.writeFileSync(path.join(home, '.env'), `GITHUB_TOKEN=${FAKE_TOKEN}\n`);
    const findings = checkSecrets({ home, cwd: home });
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain(FAKE_TOKEN);
  });

  it('flags credential material (~/.ssh/id_rsa) as high', () => {
    fs.mkdirSync(path.join(home, '.ssh'));
    // Existence is what's checked; contents are irrelevant (and kept innocuous).
    fs.writeFileSync(path.join(home, '.ssh', 'id_rsa'), 'placeholder');
    const findings = checkSecrets({ home, cwd: home });
    const high = findings.find((f) => f.severity === 'high');
    expect(high).toBeDefined();
    expect(high?.title).toContain('credential file');
  });

  it('returns no findings on a clean home', () => {
    const findings = checkSecrets({ home, cwd: home });
    expect(findings).toEqual([]);
  });
});

describe('parsePublicListeners', () => {
  it('extracts ports bound to 0.0.0.0 in LISTEN state', () => {
    const text = [
      '  sl  local_address rem_address   st',
      '   0: 00000000:1F90 00000000:0000 0A 00000000:00000000', // 0.0.0.0:8080 LISTEN
      '   1: 0100007F:0050 00000000:0000 0A 00000000:00000000', // 127.0.0.1:80 LISTEN (loopback → excluded)
      '   2: 00000000:0016 00000000:0000 01 00000000:00000000', // 0.0.0.0:22 ESTABLISHED (not LISTEN → excluded)
    ].join('\n');
    expect(parsePublicListeners(text)).toEqual([8080]); // 0x1F90
  });

  it('handles the tcp6 all-zero address form', () => {
    const text = [
      'header',
      '   0: 00000000000000000000000000000000:13A4 00000000000000000000000000000000:0000 0A x',
    ].join('\n');
    expect(parsePublicListeners(text)).toEqual([5028]); // 0x13A4
  });

  it('returns [] on empty or malformed input', () => {
    expect(parsePublicListeners('')).toEqual([]);
    expect(parsePublicListeners('header only\nshort line')).toEqual([]);
  });
});

describe('checkSupplyChain', () => {
  let home: string;
  // claude's MCP config path (from the agent-wiring registry).
  const mcpFile = () => path.join(home, '.claude.json');

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'posture-mcp-'));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('flags an unmanaged MCP server (runs outside node9) as medium', () => {
    fs.writeFileSync(
      mcpFile(),
      JSON.stringify({ mcpServers: { weather: { command: 'node', args: ['s.js'] } } })
    );
    const findings = checkSupplyChain({ home, cwd: home });
    const f = findings.find((x) => x.category === 'Supply chain' && x.severity === 'medium');
    expect(f).toBeDefined();
    expect(f?.title).toContain('run outside node9');
  });

  it('does not flag a node9-wrapped MCP server', () => {
    fs.writeFileSync(
      mcpFile(),
      JSON.stringify({ mcpServers: { safe: { command: 'node9', args: ['mcp-wrap'] } } })
    );
    expect(checkSupplyChain({ home, cwd: home })).toEqual([]);
  });

  it('flags a server launched from an untrusted path (/tmp) as high', () => {
    fs.writeFileSync(
      mcpFile(),
      JSON.stringify({ mcpServers: { sketchy: { command: '/tmp/mcp-server' } } })
    );
    const findings = checkSupplyChain({ home, cwd: home });
    expect(findings.some((f) => f.severity === 'high' && /untrusted path/.test(f.title))).toBe(
      true
    );
  });

  it('returns no findings when no MCP servers are configured', () => {
    expect(checkSupplyChain({ home, cwd: home })).toEqual([]);
  });
});

describe('checkCoverage', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'posture-cov-'));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('reports critical when node9 is not in-path for any agent', () => {
    const findings = checkCoverage({ home, cwd: home });
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe('Coverage');
    expect(findings[0].severity).toBe('critical');
  });
});
