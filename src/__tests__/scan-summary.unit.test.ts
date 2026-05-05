/**
 * Unit tests for buildScanSummary() — the shared categorization logic
 * consumed by both the terminal scan renderer and the browser.
 *
 * What we verify:
 *   1. byVerdict counts every block/review regardless of source (matches terminal)
 *   2. Sections group strictly by source (default / each shield / user / cloud)
 *   3. User-defined rules with block verdict live in "Your Rules" section,
 *      but still count in byVerdict.blocked
 *   4. Rule findings are deduplicated by (project + command preview)
 *   5. Per-agent breakdown only shows agents that had activity
 *   6. Loop cost is (count - threshold) × per-iter for each loop
 */

import { describe, it, expect } from 'vitest';
import { buildScanSummary, type AgentScanInput } from '../scan-summary';
import { isNode9SelfOutput, looksLikeFixtureToken, type ScanResult } from '../cli/commands/scan';

function finding(opts: {
  ruleName: string;
  verdict: 'block' | 'review';
  sourceType: 'default' | 'shield' | 'user';
  shieldName: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  input?: any;
  project?: string;
  agent?: 'claude' | 'gemini' | 'codex';
}) {
  return {
    source: {
      sourceType: opts.sourceType,
      shieldName: opts.shieldName,
      shieldLabel: opts.shieldName,
      rule: { name: opts.ruleName, verdict: opts.verdict, reason: opts.ruleName + ' reason' },
    },
    toolName: 'bash',
    input: opts.input ?? { command: 'echo test' },
    timestamp: '2026-04-01T00:00:00Z',
    project: opts.project ?? '~/p',
    sessionId: 'sess1',
    agent: opts.agent ?? ('claude' as const),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any;
}

function emptyScan(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    filesScanned: 0,
    sessions: 0,
    totalToolCalls: 0,
    bashCalls: 0,
    findings: [],
    dlpFindings: [],
    loopFindings: [],
    totalCostUSD: 0,
    firstDate: null,
    lastDate: null,
    sessionsWithEarlySecrets: 0,
    ...overrides,
  };
}

function claudeAgent(scan: ScanResult): AgentScanInput {
  return { id: 'claude', label: 'Claude', icon: '🤖', scan };
}

describe('buildScanSummary', () => {
  it('returns zeroed shape for empty input', () => {
    const s = buildScanSummary([claudeAgent(emptyScan())]);
    expect(s.stats.sessions).toBe(0);
    expect(s.byVerdict).toEqual({ blocked: 0, supervised: 0, leaks: 0, loops: 0 });
    expect(s.sections).toEqual([]);
    expect(s.byAgent).toEqual([]);
    expect(s.leaks).toEqual([]);
    expect(s.loops).toEqual([]);
    expect(s.loopWastedUSD).toBe(0);
  });

  it('counts byVerdict across all sources (terminal parity)', () => {
    // User's block rule (block-force-push) + shield block (block-eval-remote)
    // should both count toward byVerdict.blocked.
    const scan = emptyScan({
      sessions: 1,
      findings: [
        finding({
          ruleName: 'block-force-push',
          verdict: 'block',
          sourceType: 'user',
          shieldName: 'custom',
        }),
        finding({
          ruleName: 'shield:bash-safe:block-eval-remote',
          verdict: 'block',
          sourceType: 'shield',
          shieldName: 'bash-safe',
        }),
        finding({
          ruleName: 'review-git-push',
          verdict: 'review',
          sourceType: 'user',
          shieldName: 'custom',
        }),
      ],
    });
    const s = buildScanSummary([claudeAgent(scan)]);
    expect(s.byVerdict.blocked).toBe(2);
    expect(s.byVerdict.supervised).toBe(1);
  });

  it('groups sections by source, stripping shield: prefix from rule names', () => {
    const scan = emptyScan({
      sessions: 1,
      findings: [
        finding({
          ruleName: 'shield:bash-safe:block-eval-remote',
          verdict: 'block',
          sourceType: 'shield',
          shieldName: 'bash-safe',
        }),
        finding({
          ruleName: 'review-git-push',
          verdict: 'review',
          sourceType: 'user',
          shieldName: 'custom',
        }),
        finding({
          ruleName: 'review-git-destructive',
          verdict: 'review',
          sourceType: 'default',
          shieldName: 'default',
        }),
      ],
    });
    const s = buildScanSummary([claudeAgent(scan)]);
    const ids = s.sections.map((x) => x.id).sort();
    expect(ids).toEqual(['default', 'shield:bash-safe', 'user']);

    const shieldSection = s.sections.find((x) => x.id === 'shield:bash-safe')!;
    expect(shieldSection.rules[0].name).toBe('block-eval-remote'); // prefix stripped
    expect(shieldSection.shieldKey).toBe('bash-safe');
    expect(shieldSection.blockedCount).toBe(1);
    expect(shieldSection.reviewCount).toBe(0);

    const userSection = s.sections.find((x) => x.id === 'user')!;
    expect(userSection.rules[0].name).toBe('review-git-push');
    expect(userSection.blockedCount).toBe(0);
    expect(userSection.reviewCount).toBe(1);
  });

  it("places user's block-verdict rule in Your Rules, but still counts it in byVerdict.blocked", () => {
    // This is the exact discrepancy we set out to fix:
    // block-force-push is a USER rule with BLOCK verdict. Old browser
    // excluded it from "Blocked" because source=user; terminal included it.
    const scan = emptyScan({
      sessions: 1,
      findings: [
        finding({
          ruleName: 'block-force-push',
          verdict: 'block',
          sourceType: 'user',
          shieldName: 'custom',
        }),
      ],
    });
    const s = buildScanSummary([claudeAgent(scan)]);

    expect(s.byVerdict.blocked).toBe(1); // counted in top stats
    const userSection = s.sections.find((x) => x.id === 'user')!;
    expect(userSection.rules[0].name).toBe('block-force-push'); // also in Your Rules section
    expect(userSection.blockedCount).toBe(1);
  });

  it('deduplicates findings within a rule group by (project, command preview)', () => {
    const scan = emptyScan({
      findings: [
        finding({
          ruleName: 'review-git-push',
          verdict: 'review',
          sourceType: 'user',
          shieldName: 'custom',
          input: { command: 'git push origin dev' },
          project: '~/p',
        }),
        finding({
          ruleName: 'review-git-push',
          verdict: 'review',
          sourceType: 'user',
          shieldName: 'custom',
          input: { command: 'git push origin dev' }, // same cmd + same project
          project: '~/p',
        }),
        finding({
          ruleName: 'review-git-push',
          verdict: 'review',
          sourceType: 'user',
          shieldName: 'custom',
          input: { command: 'git push origin main' }, // different cmd
          project: '~/p',
        }),
      ],
    });
    const s = buildScanSummary([claudeAgent(scan)]);
    const userSection = s.sections.find((x) => x.id === 'user')!;
    expect(userSection.rules[0].findings.length).toBe(2); // deduped: 3 in → 2 out
  });

  it('computes per-agent breakdown only for agents with activity', () => {
    const claudeScan = emptyScan({
      sessions: 5,
      totalCostUSD: 1.23,
      findings: [
        finding({
          ruleName: 'review-git-push',
          verdict: 'review',
          sourceType: 'user',
          shieldName: 'custom',
          agent: 'claude',
        }),
      ],
    });
    const geminiScan = emptyScan(); // empty
    const codexScan = emptyScan({ sessions: 1 });
    const s = buildScanSummary([
      { id: 'claude', label: 'Claude', icon: '🤖', scan: claudeScan },
      { id: 'gemini', label: 'Gemini', icon: '♊', scan: geminiScan },
      { id: 'codex', label: 'Codex', icon: '🔮', scan: codexScan },
    ]);
    const ids = s.byAgent.map((a) => a.id);
    expect(ids).toEqual(['claude', 'codex']); // gemini filtered out (no activity)

    const claude = s.byAgent.find((a) => a.id === 'claude')!;
    expect(claude.sessions).toBe(5);
    expect(claude.findings).toBe(1);
    expect(claude.costUSD).toBeCloseTo(1.23);
  });

  it('estimates loop waste as (count - threshold) × per-iter', () => {
    const scan = emptyScan({
      loopFindings: [
        {
          toolName: 'edit',
          commandPreview: 'edit /a',
          count: 10, // 10 - 3 = 7 wasted
          timestamp: '',
          project: '~/p',
          sessionId: 's',
          agent: 'claude',
        },
        {
          toolName: 'edit',
          commandPreview: 'edit /b',
          count: 5, // 5 - 3 = 2 wasted
          timestamp: '',
          project: '~/p',
          sessionId: 's',
          agent: 'claude',
        },
      ],
    });
    const s = buildScanSummary([claudeAgent(scan)]);
    // Total wasted = 9 iters × $0.006 = $0.054
    expect(s.loopWastedUSD).toBeCloseTo(9 * 0.006);
  });

  it('sorts sections: most blocked first, then by total findings', () => {
    const scan = emptyScan({
      findings: [
        // user section: 0 blocked, 3 review
        finding({
          ruleName: 'a',
          verdict: 'review',
          sourceType: 'user',
          shieldName: 'custom',
        }),
        finding({
          ruleName: 'b',
          verdict: 'review',
          sourceType: 'user',
          shieldName: 'custom',
          input: { command: 'diff b' },
        }),
        finding({
          ruleName: 'c',
          verdict: 'review',
          sourceType: 'user',
          shieldName: 'custom',
          input: { command: 'diff c' },
        }),
        // shield section: 1 blocked
        finding({
          ruleName: 'shield:bash-safe:x',
          verdict: 'block',
          sourceType: 'shield',
          shieldName: 'bash-safe',
        }),
      ],
    });
    const s = buildScanSummary([claudeAgent(scan)]);
    // Shield has blocked=1; user has blocked=0 → shield first
    expect(s.sections[0].id).toBe('shield:bash-safe');
    expect(s.sections[1].id).toBe('user');
  });
});

// ── DLP self-output filter & fixture-token demotion ─────────────────────────

describe('isNode9SelfOutput', () => {
  it('detects scanArgs output struct (patternName + redactedSample)', () => {
    const text = `token: ghp_abc
scan: { patternName: 'GitHub Token', redactedSample: 'ghp_***abc' }`;
    expect(isNode9SelfOutput(text)).toBe(true);
  });
  it('detects live security alert text', () => {
    // Two markers needed; combine alert + redactedSample.
    const text = `NODE9 SECURITY ALERT: secret detected
redactedSample: 'ghp_***xyz'`;
    expect(isNode9SelfOutput(text)).toBe(true);
  });
  it('detects severity + patternName combo', () => {
    const text = `{ patternName: 'AWS Access Key ID', severity: 'block' }`;
    expect(isNode9SelfOutput(text)).toBe(true);
  });
  it('does not flag a single coincidental marker', () => {
    // patternName alone is not enough — could appear in user docs.
    const text = `the patternName: 'thing' was discussed in the meeting`;
    expect(isNode9SelfOutput(text)).toBe(false);
  });
  it('does not flag normal tool output', () => {
    expect(isNode9SelfOutput('Here is your token: ghp_realsecret123')).toBe(false);
  });
});

// ── detectLoops classifies kind by time span ────────────────────────────────

import { detectLoops } from '../cli/commands/scan';

describe('detectLoops kind classification', () => {
  function call(toolName: string, command: string, isoTs: string) {
    return { toolName, input: { command }, timestamp: isoTs };
  }

  it('flags bursty repeats as kind="loop"', () => {
    // 5 calls within 60 seconds — clearly stuck behavior.
    const calls = [
      call('Bash', 'ls -la', '2026-04-01T00:00:00Z'),
      call('Bash', 'ls -la', '2026-04-01T00:00:15Z'),
      call('Bash', 'ls -la', '2026-04-01T00:00:30Z'),
      call('Bash', 'ls -la', '2026-04-01T00:00:45Z'),
      call('Bash', 'ls -la', '2026-04-01T00:01:00Z'),
    ];
    const found = detectLoops(calls, '~/p', 'sess1', 'claude');
    expect(found).toHaveLength(1);
    expect(found[0].kind).toBe('loop');
    expect(found[0].count).toBe(5);
  });

  it('flags long-spanning repeats as kind="long-iteration"', () => {
    // 5 edits over 2 hours — sustained deep work, not stuck.
    const calls = [
      call('Edit', 'src/feature.ts', '2026-04-01T10:00:00Z'),
      call('Edit', 'src/feature.ts', '2026-04-01T10:30:00Z'),
      call('Edit', 'src/feature.ts', '2026-04-01T11:00:00Z'),
      call('Edit', 'src/feature.ts', '2026-04-01T11:30:00Z'),
      call('Edit', 'src/feature.ts', '2026-04-01T12:00:00Z'),
    ];
    const found = detectLoops(calls, '~/p', 'sess1', 'claude');
    expect(found).toHaveLength(1);
    expect(found[0].kind).toBe('long-iteration');
  });

  it('boundary: 10 minutes exactly is long-iteration (≥)', () => {
    const calls = [
      call('Bash', 'cmd', '2026-04-01T00:00:00Z'),
      call('Bash', 'cmd', '2026-04-01T00:05:00Z'),
      call('Bash', 'cmd', '2026-04-01T00:10:00Z'),
    ];
    const found = detectLoops(calls, '~/p', 'sess1', 'claude');
    expect(found[0].kind).toBe('long-iteration');
  });
});

// ── Loop vs long-iteration classification ───────────────────────────────────

describe('loopWastedUSD excludes long-iteration findings', () => {
  it('counts only kind="loop" toward waste; ignores long-iteration', () => {
    const scan = emptyScan({
      sessions: 1,
      loopFindings: [
        // Real loop: 10 iterations, kind 'loop' — counts as waste
        {
          toolName: 'Bash',
          commandPreview: 'ls -la',
          count: 10,
          timestamp: '2026-04-01T00:00:00Z',
          project: '~/p',
          sessionId: 'sess1',
          agent: 'claude',
          kind: 'loop',
        },
        // Long iteration: 100 iterations, kind 'long-iteration' — NO waste
        {
          toolName: 'Edit',
          commandPreview: 'src/feature.ts',
          count: 100,
          timestamp: '2026-04-01T00:00:00Z',
          project: '~/p',
          sessionId: 'sess1',
          agent: 'claude',
          kind: 'long-iteration',
        },
      ],
    });
    const s = buildScanSummary([claudeAgent(scan)]);
    // Only 7 wasted iters (10 loop - 3 threshold), at $0.006/iter = $0.042.
    // The 97 long-iteration iters above threshold contribute ZERO.
    expect(s.loopWastedUSD).toBeCloseTo(7 * 0.006, 4);
  });

  it('treats missing kind as a real loop (backwards compat)', () => {
    const scan = emptyScan({
      sessions: 1,
      loopFindings: [
        {
          toolName: 'Bash',
          commandPreview: 'ls -la',
          count: 10,
          timestamp: '2026-04-01T00:00:00Z',
          project: '~/p',
          sessionId: 'sess1',
          agent: 'claude',
          // no `kind` field — legacy data
        },
      ],
    });
    const s = buildScanSummary([claudeAgent(scan)]);
    expect(s.loopWastedUSD).toBeCloseTo(7 * 0.006, 4);
  });
});

describe('looksLikeFixtureToken', () => {
  it.each([
    ['ghp_aaaaaaaa', true],
    ['ghp_aaaaaaaaaaaaaaaaaaaa', true],
    ['ghp_abcdefghijklmnop', true],
    ['ghp_1234567890abcdef', true],
    ['ghp_***EXAMPLE', true],
    ['AIzaSyAbcdefghijklmn0123456', true],
    ['ghp_***GJSn', false], // realistic redaction
    ['AKIA****5XYZ', false],
    ['sk-proj-realLooking123', false],
  ])('looksLikeFixtureToken(%s) → %s', (sample, expected) => {
    expect(looksLikeFixtureToken(sample)).toBe(expected);
  });
});
