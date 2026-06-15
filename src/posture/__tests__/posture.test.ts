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
import { parseListeners, classifyListener } from '../inbound';
import { checkSupplyChain } from '../supply-chain';
import { checkCoverage } from '../coverage';
import { deriveHeadline } from '../headline';
import { renderPosture } from '../render';
import type { Finding, PostureResult, Severity } from '../types';

// Compact finding builder for headline tests.
const f = (category: string, severity: Severity = 'high'): Finding => ({
  category,
  severity,
  title: `${category} finding`,
  detail: [],
  fix: `fix ${category}`,
});

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

describe('parseListeners', () => {
  // Real /proc/net/tcp columns: sl local rem st tx:rx tr:tm retr uid timeout inode
  const row = (local: string, st: string, inode: string) =>
    `   0: ${local} 00000000:0000 ${st} 00000000:00000000 00:00000000 00000000  1000        0 ${inode} 1 ...`;

  it('extracts {port, inode} for 0.0.0.0 LISTEN sockets only', () => {
    const text = [
      '  sl  local_address rem_address   st ...',
      row('00000000:1F90', '0A', '54321'), // 0.0.0.0:8080 LISTEN → kept
      row('0100007F:0050', '0A', '11111'), // 127.0.0.1:80 LISTEN → loopback excluded
      row('00000000:0016', '01', '22222'), // 0.0.0.0:22 ESTABLISHED → not LISTEN excluded
    ].join('\n');
    expect(parseListeners(text)).toEqual([{ port: 8080, inode: '54321' }]); // 0x1F90
  });

  it('handles the tcp6 all-zero address form', () => {
    const text = ['header', row('00000000000000000000000000000000:13A4', '0A', '99999')].join('\n');
    expect(parseListeners(text)).toEqual([{ port: 5028, inode: '99999' }]); // 0x13A4
  });

  it('returns [] on empty or malformed input', () => {
    expect(parseListeners('')).toEqual([]);
    expect(parseListeners('header only\nshort line')).toEqual([]);
  });
});

describe('classifyListener', () => {
  it('labels a known service port even when the process is unknown', () => {
    expect(classifyListener(5432, null)).toEqual({ kind: 'service', label: 'PostgreSQL on :5432' });
    expect(classifyListener(6379, null)).toEqual({ kind: 'service', label: 'Redis on :6379' });
  });

  it('labels a DB by process name on a non-standard port', () => {
    const c = classifyListener(7777, { comm: 'postgres', cmdline: '/usr/bin/postgres' });
    expect(c).toEqual({ kind: 'service', label: 'PostgreSQL on :7777' });
  });

  it('claims "agent" only when a listener ties to the named agent', () => {
    const proc = { comm: 'python3', cmdline: 'python3 /opt/hermes/bot.py --webhook' };
    expect(classifyListener(8443, proc, 'hermes').kind).toBe('agent');
    // same process, no agent name → not an agent claim
    expect(classifyListener(8443, proc).kind).toBe('unknown');
  });

  it('falls back to unknown (no pilot claim) for an unrecognized listener', () => {
    const c = classifyListener(9999, { comm: 'myserver', cmdline: 'myserver' });
    expect(c).toEqual({ kind: 'unknown', label: 'myserver on :9999' });
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

describe('deriveHeadline', () => {
  it('narrates the exfiltration chain when secrets + egress are both open', () => {
    const h = deriveHeadline([f('Secrets', 'critical'), f('Egress'), f('Isolation', 'advisory')]);
    expect(h).not.toBeNull();
    expect(h?.risk).toMatch(/read the credentials/i);
    expect(h?.risk).toMatch(/send them to any host/i);
    expect(h?.risk).toMatch(/no container/i); // isolation woven in
  });

  it('makes egress the first action (close the exit breaks the chain)', () => {
    const h = deriveHeadline([f('Secrets', 'critical'), f('Egress')]);
    expect(h?.action).toMatch(/lock egress/i);
  });

  it('prioritizes "node9 setup" when node9 is not wired, over any other fix', () => {
    const h = deriveHeadline([f('Secrets', 'critical'), f('Egress'), f('Coverage', 'critical')]);
    expect(h?.action).toMatch(/node9 setup/i);
  });

  it('calls out observe mode as the action when node9 only watches', () => {
    const h = deriveHeadline([f('Egress'), f('Coverage', 'high')]);
    expect(h?.action).toMatch(/enforcing mode/i);
  });

  it('returns null when only advisory findings exist (no scary chain)', () => {
    expect(
      deriveHeadline([f('Isolation', 'advisory'), f('Network exposure', 'advisory')])
    ).toBeNull();
  });

  it('returns null for a clean run', () => {
    expect(deriveHeadline([])).toBeNull();
  });
});

describe('renderPosture grouping', () => {
  const result = (findings: Finding[]): PostureResult => ({
    agent: 'agent on this host',
    findings,
    passedCategories: [],
    headline: deriveHeadline(findings),
    score: 50,
    tier: 'at-risk',
    checksRun: 8,
  });

  it('groups into the exfiltration chain when secrets + egress are both present', () => {
    const out = renderPosture(result([f('Secrets', 'critical'), f('Egress'), f('Privilege')]));
    expect(out).toContain('── the exfiltration chain ──');
    expect(out).toContain('── other findings ──');
    // Chain (Secrets, Egress) renders before the other finding (Privilege).
    expect(out.indexOf('Secrets')).toBeLessThan(out.indexOf('Egress'));
    expect(out.indexOf('Egress')).toBeLessThan(out.indexOf('Privilege'));
  });

  it('does not group (flat list) when the chain is not active', () => {
    const out = renderPosture(result([f('Egress'), f('Privilege')]));
    expect(out).not.toContain('exfiltration chain');
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
