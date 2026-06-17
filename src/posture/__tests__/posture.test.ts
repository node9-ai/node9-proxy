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
import { parseListeners, classifyListener, buildNetworkFix } from '../inbound';
import { checkSupplyChain, isNode9Managed } from '../supply-chain';
import { checkCoverage } from '../coverage';
import { deriveHeadline } from '../headline';
import { renderPosture } from '../render';
import { runChecks, dropEnforcementRedundant } from '../index';
import { coverageFromVerdict, annotateCoverage, egressCoverage } from '../enforcement';
import type { CheckContext, Finding, PostureCheck, PostureResult, Severity } from '../types';

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

  it('review mode emits a covered-candidate finding (approval-gated when enforcing)', () => {
    // Review approval-gates outbound at runtime, so like the block finding it's
    // a coverage-probed candidate that drops when open (not-enforcing) — never a
    // standalone "logged but not blocked" red row.
    const f = evaluateEgressConfig({ enabled: true, mode: 'review' });
    expect(f?.severity).toBe('medium');
    expect(f.coverageProbe).toEqual({ kind: 'egress' });
    expect(f.redundantWhenOpen).toBe(true);
  });

  it('emits a covered-candidate finding when locked to block (consistency fix)', () => {
    // Always returns a finding now; coverage (annotateCoverage) decides
    // covered-vs-open so a locked + enforcing egress renders 🟢 covered.
    const f = evaluateEgressConfig({ enabled: true, mode: 'block' });
    expect(f.category).toBe('Egress');
    expect(f.coverageProbe).toEqual({ kind: 'egress' });
    expect(f.owner).toBe('node9');
  });

  it('carries plain-language what/why/who (Phase B)', () => {
    const f = evaluateEgressConfig({ enabled: false, mode: 'off' });
    expect(f?.what).toBeTruthy();
    expect(f?.why).toBeTruthy();
    expect(f?.who).toBeTruthy();
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

  it('does not over-claim agent for a short/generic --agent name', () => {
    const node = { comm: 'node', cmdline: 'node server.js' };
    // 'js' is < 4 chars → too generic to attribute
    expect(classifyListener(3000, node, 'js').kind).not.toBe('agent');
  });

  it('requires a word/path boundary, not a bare substring, to attribute', () => {
    const thermal = { comm: 'thermald', cmdline: '/usr/sbin/thermald' };
    // 'herm' is inside 'thermald' but not a token boundary → no agent claim
    expect(classifyListener(7000, thermal, 'herm').kind).not.toBe('agent');
  });

  it('falls back to unknown (no pilot claim) for an unrecognized listener', () => {
    const c = classifyListener(9999, { comm: 'myserver', cmdline: 'myserver' });
    expect(c).toEqual({ kind: 'unknown', label: 'myserver on :9999' });
  });
});

describe('buildNetworkFix', () => {
  it('surfaces the db-shield command + rebind line for a shielded service, and flags reduces', () => {
    const { fix, reduces } = buildNetworkFix(['PostgreSQL on :5432', 'Redis on :6379']);
    expect(reduces).toBe(true);
    expect(fix).toContain('node9 shield enable postgres');
    expect(fix).toContain('node9 shield enable redis');
    expect(fix).toContain("listen_addresses='localhost'");
    expect(fix).toContain('bind 127.0.0.1');
  });

  it('does NOT flag reduces for bare dev servers node9 has no shield for', () => {
    const { fix, reduces } = buildNetworkFix(['node on :3000', 'node on :4000']);
    expect(reduces).toBe(false);
    expect(fix).not.toContain('shield enable');
    expect(fix).toContain('Bind to 127.0.0.1'); // plain rebind only
  });

  it('dedupes a shield when the same service is exposed twice', () => {
    const { fix } = buildNetworkFix(['PostgreSQL on :5432', 'PostgreSQL on :5433']);
    expect(fix.match(/shield enable postgres/g)).toHaveLength(1);
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

  it('does not flag an absolute-path or npx node9 wrap as unmanaged', () => {
    fs.writeFileSync(
      mcpFile(),
      JSON.stringify({
        mcpServers: {
          abs: { command: '/usr/local/bin/node9', args: ['mcp-wrap'] },
          viaNpx: { command: 'npx', args: ['node9', 'mcp-wrap'] },
        },
      })
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

  it('prioritizes "node9 init" when node9 is not wired, over any other fix', () => {
    const h = deriveHeadline([f('Secrets', 'critical'), f('Egress'), f('Coverage', 'critical')]);
    expect(h?.action).toMatch(/node9 init/i);
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
    erroredCategories: [],
    headline: deriveHeadline(findings),
    score: 50,
    tier: 'at-risk',
    checksRun: 8,
  });

  it('notes that advisories do not affect the score, only when present', () => {
    // The "why is it 100/100 with warnings?" fix — advisories don't deduct, so
    // say so under the score; never show the note when there are none.
    const withAdvisory = renderPosture(
      result([{ category: 'Isolation', severity: 'advisory', title: 'i', detail: [], owner: 'os' }])
    );
    expect(withAdvisory).toContain('affect the score');

    const noAdvisory = renderPosture(
      result([{ category: 'Egress', severity: 'high', title: 'e', detail: [], owner: 'node9' }])
    );
    expect(noAdvisory).not.toContain('affect the score');
  });

  it('groups open findings by owner — node9-fixable before only-you', () => {
    const out = renderPosture(
      result([
        { category: 'Egress', severity: 'high', title: 'e', detail: [], owner: 'node9' },
        { category: 'Isolation', severity: 'advisory', title: 'i', detail: [], owner: 'os' },
      ])
    );
    expect(out).toContain('node9 can fix these');
    expect(out).toContain('Only you can fix these');
    // The node9 group renders before the only-you group.
    expect(out.indexOf('node9 can fix these')).toBeLessThan(out.indexOf('Only you can fix these'));
  });

  it('puts an unset-owner finding in the "only you" bucket (conservative, no false node9 claim)', () => {
    const out = renderPosture(result([f('Mystery')])); // f() sets no owner
    expect(out).toContain('Only you can fix these');
    expect(out).not.toContain('node9 can fix these');
  });

  it('renders the 🔒 middle tier for an os-owned finding node9 can reduce, between fix-it and only-you', () => {
    const out = renderPosture(
      result([
        { category: 'Egress', severity: 'high', title: 'e', detail: [], owner: 'node9' },
        {
          category: 'Isolation',
          severity: 'advisory',
          title: 'i',
          detail: [],
          owner: 'os',
          node9Reduces: true,
        },
        { category: 'Mystery', severity: 'advisory', title: 'm', detail: [], owner: 'os' },
      ])
    );
    expect(out).toContain('node9 reduces these');
    // order: 🔧 fix-it < 🔒 reduces < 🧱 only-you
    expect(out.indexOf('node9 can fix these')).toBeLessThan(out.indexOf('node9 reduces these'));
    expect(out.indexOf('node9 reduces these')).toBeLessThan(out.indexOf('Only you can fix these'));
  });

  it('preserves explicit line breaks in a multi-line fix (bulleted options stay on their own lines)', () => {
    const out = renderPosture(
      result([
        {
          category: 'Isolation',
          severity: 'advisory',
          title: 'i',
          detail: [],
          owner: 'os',
          node9Reduces: true,
          fix: 'First line\n  • bullet one\n  • bullet two',
        },
      ])
    );
    const lines = out.split('\n');
    // The two bullets land on separate output lines (not collapsed into one wrap).
    expect(lines.filter((l) => l.includes('• bullet one'))).toHaveLength(1);
    expect(lines.filter((l) => l.includes('• bullet two'))).toHaveLength(1);
    expect(lines.some((l) => l.includes('• bullet one') && l.includes('• bullet two'))).toBe(false);
  });

  it('renders the "already protecting you" section and keeps covered out of the open list', () => {
    const out = renderPosture(
      result([
        {
          category: 'Secrets',
          severity: 'critical',
          title: 'SCARY SECRETS TITLE',
          detail: [],
          coverage: { state: 'covered', via: 'node9 DLP', level: 'block' },
        },
        f('Egress'),
      ])
    );
    expect(out).toContain('node9 is already protecting you');
    expect(out).toContain('node9 DLP is blocking this');
    // The scary title is suppressed for a covered finding.
    expect(out).not.toContain('SCARY SECRETS TITLE');
  });
});

describe('coverageFromVerdict', () => {
  const enf = { enforcing: true, egressBlocking: false, egressReviewing: false };

  it('block + enforcing → covered (block)', () => {
    expect(coverageFromVerdict('block', enf, 'project-jail shield')).toEqual({
      state: 'covered',
      level: 'block',
      via: 'project-jail shield',
    });
  });

  it('review + enforcing → covered (review = approval-gated, still covered)', () => {
    expect(coverageFromVerdict('review', enf).state).toBe('covered');
    expect(coverageFromVerdict('review', enf).level).toBe('review');
  });

  it('allow → open', () => {
    expect(coverageFromVerdict('allow', enf)).toEqual({ state: 'open' });
  });

  it('NOT enforcing → open even on a block verdict (observe mode = false green guard)', () => {
    expect(
      coverageFromVerdict('block', {
        enforcing: false,
        egressBlocking: false,
        egressReviewing: false,
      })
    ).toEqual({
      state: 'open',
    });
  });
});

describe('egressCoverage', () => {
  it('block + enforcing → covered (blocking)', () => {
    expect(
      egressCoverage({ enforcing: true, egressBlocking: true, egressReviewing: false })
    ).toEqual({ state: 'covered', level: 'block', via: 'node9 egress' });
  });

  it('review + enforcing → covered (approval-gating) — watch is NOT "open"', () => {
    // The bug this fixes: review mode approval-gates outbound to unknown hosts
    // at runtime, exactly like a review-verdict command, so it must be covered.
    expect(
      egressCoverage({ enforcing: true, egressBlocking: false, egressReviewing: true })
    ).toEqual({ state: 'covered', level: 'review', via: 'node9 egress' });
  });

  it('review but NOT enforcing → open (gate has no effect until node9 is wired)', () => {
    expect(
      egressCoverage({ enforcing: false, egressBlocking: false, egressReviewing: true })
    ).toEqual({ state: 'open' });
  });

  it('off (neither blocking nor reviewing) → open', () => {
    expect(
      egressCoverage({ enforcing: true, egressBlocking: false, egressReviewing: false })
    ).toEqual({ state: 'open' });
  });
});

describe('annotateCoverage (enforcement gate)', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'posture-cov-'));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('egress: NOT covered when block-mode is set but node9 is not wired (no false green)', async () => {
    // Project config locks egress, but no agent is wired in this temp home.
    fs.writeFileSync(
      path.join(home, 'node9.config.json'),
      JSON.stringify({ policy: { egress: { enabled: true, mode: 'block' } } })
    );
    const findings: Finding[] = [
      {
        category: 'Egress',
        severity: 'high',
        title: 't',
        detail: [],
        coverageProbe: { kind: 'egress' },
      },
    ];
    await annotateCoverage(findings, { home, cwd: home });
    expect(findings[0].coverage?.state).toBe('open'); // not enforcing → open, not covered
  });

  it('marks cantFix as cant-fix, and gates command/fileRead to OPEN when node9 is not wired', async () => {
    const findings: Finding[] = [
      {
        category: 'Isolation',
        severity: 'advisory',
        title: 't',
        detail: [],
        coverageProbe: { kind: 'cantFix' },
      },
      {
        category: 'Privilege',
        severity: 'medium',
        title: 't',
        detail: [],
        coverageProbe: { kind: 'command', command: 'sudo chmod 777 /etc/passwd' },
      },
    ];
    // Bare temp home → no agent wired → not enforcing → covered downgrades to open.
    await annotateCoverage(findings, { home, cwd: home });
    expect(findings[0].coverage).toEqual({ state: 'cant-fix' });
    expect(findings[1].coverage?.state).toBe('open');
  });
});

describe('scorePosture (coverage-aware)', () => {
  it('excludes a covered finding from the score', () => {
    const covered: Finding = {
      category: 'Secrets',
      severity: 'critical',
      title: 't',
      detail: [],
      coverage: { state: 'covered' },
    };
    expect(scorePosture([covered], 8)).toEqual({ score: 100, tier: 'good' });
  });

  it('still counts an open finding', () => {
    const open: Finding = {
      category: 'Egress',
      severity: 'high',
      title: 't',
      detail: [],
      coverage: { state: 'open' },
    };
    expect(scorePosture([open], 8).tier).toBe('at-risk');
  });
});

describe('deriveHeadline (coverage-aware)', () => {
  it('does not chain a COVERED Secrets — no "read your credentials" story', () => {
    const h = deriveHeadline([
      {
        category: 'Secrets',
        severity: 'critical',
        title: 't',
        detail: [],
        coverage: { state: 'covered' },
      },
      { category: 'Egress', severity: 'high', title: 't', detail: [], coverage: { state: 'open' } },
    ]);
    expect(h?.risk).not.toMatch(/credentials/i);
    expect(h?.risk).toMatch(/any host/i); // egress-only story
  });
});

describe('dropEnforcementRedundant', () => {
  const redundantOpen: Finding = {
    category: 'Egress',
    severity: 'high',
    title: 'locked but not enforcing',
    detail: [],
    coverage: { state: 'open' },
    redundantWhenOpen: true,
  };
  const coverage: Finding = {
    category: 'Coverage',
    severity: 'high',
    title: 'observe mode',
    detail: [],
    coverage: { state: 'open' },
  };

  it('drops the redundant-open finding when Coverage is present', () => {
    const out = dropEnforcementRedundant([redundantOpen, coverage]);
    expect(out.map((f) => f.category)).toEqual(['Coverage']);
  });

  it("keeps it when Coverage is NOT present (don't lose the only signal)", () => {
    const out = dropEnforcementRedundant([redundantOpen]);
    expect(out).toHaveLength(1);
  });

  it('keeps a redundant finding that is COVERED (not open)', () => {
    const covered: Finding = { ...redundantOpen, coverage: { state: 'covered' } };
    const out = dropEnforcementRedundant([covered, coverage]);
    expect(out).toHaveLength(2);
  });
});

describe('runChecks (error isolation)', () => {
  const ctx: CheckContext = { home: '/tmp', cwd: '/tmp' };

  it('records a throwing check without crashing; other checks still run', async () => {
    const checks: PostureCheck[] = [
      {
        category: 'Good',
        run: () => [{ category: 'Good', severity: 'high', title: 't', detail: [] }],
      },
      {
        category: 'Boom',
        run: () => {
          throw new Error('kaboom');
        },
      },
      { category: 'Clean', run: () => [] },
    ];
    const res = await runChecks(checks, ctx);
    expect(res.findings).toHaveLength(1);
    expect(res.passedCategories).toEqual(['Clean']);
    expect(res.erroredCategories).toEqual(['Boom']);
  });

  it('isolates an async (rejected promise) check too', async () => {
    const checks: PostureCheck[] = [
      { category: 'AsyncBoom', run: async () => Promise.reject(new Error('async fail')) },
      { category: 'Clean', run: () => [] },
    ];
    const res = await runChecks(checks, ctx);
    expect(res.erroredCategories).toEqual(['AsyncBoom']);
    expect(res.passedCategories).toEqual(['Clean']);
  });
});

describe('isNode9Managed', () => {
  it('treats the bare and absolute-path node9 binary as managed', () => {
    expect(isNode9Managed('node9', ['mcp-wrap'])).toBe(true);
    expect(isNode9Managed('/usr/local/bin/node9', [])).toBe(true);
  });

  it('treats an npx node9 wrapper as managed', () => {
    expect(isNode9Managed('npx', ['node9', 'mcp-wrap'])).toBe(true);
  });

  it('does not treat an unrelated binary as managed', () => {
    expect(isNode9Managed('node', ['server.js'])).toBe(false);
    expect(isNode9Managed(undefined)).toBe(false);
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
