/**
 * Render tests for ScoreBanner — phase 3f's most logic-heavy
 * component, with a 5-tier headline cascade and a 4-tier score
 * coloring. The cascade is where regressions would silently bite, so
 * exercising the render output across the branches is the highest-ROI
 * place to spend test effort on the Report [2] surface.
 *
 * Uses ink-testing-library to capture lastFrame() and assert on text.
 */
import React from 'react';
import { describe, it, expect } from 'vitest';
import { render } from 'ink-testing-library';

import { ScoreBanner } from '../tui/dashboard/views/report/index';
import { EMPTY_FILTERED_SCAN, type FilteredScan } from '../tui/dashboard/views/report/derive';
import type { BlastSnapshot, ScanCache } from '../tui/dashboard/types';
import type { AggregateResult } from '../cli/aggregate/report-audit';
import type { BuildReportJsonInput } from '../cli/render/report-json';

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

function makeAudit(spend: number = 0): AggregateResult {
  const data: BuildReportJsonInput = {
    period: '7d',
    start: new Date('2026-05-04T00:00:00Z'),
    end: new Date('2026-05-10T23:59:59Z'),
    excludedTests: 0,
    total: 100,
    userApproved: 0,
    userDenied: 0,
    timedOut: 0,
    hardBlocked: 0,
    dlpBlocked: 0,
    observeDlp: 0,
    loopHits: 0,
    testPasses: 0,
    testFails: 0,
    unackedDlp: 0,
    priorBlockRate: null,
    cost: {
      claudeUSD: spend,
      codexUSD: 0,
      geminiUSD: 0,
      inputTokens: 0,
      outputTokens: 0,
      cacheWriteTokens: 0,
      cacheReadTokens: 0,
      byDay: new Map(),
      byModel: new Map(),
      byProject: new Map(),
    },
    toolMap: new Map(),
    blockMap: new Map(),
    ruleMap: new Map(),
    agentMap: new Map(),
    mcpMap: new Map(),
    dailyMap: new Map(),
    hourMap: new Map(),
    dimensions: {
      network: { blocked: 0 },
      data: { blocked: 0, observed: 0 },
      detection: { loops: 0, pinMismatches: 0, injections: 0 },
      approvals: { approved: 0, denied: 0, timedOut: 0 },
      files: { blocked: 0 },
      toolRules: { blocked: 0 },
      apps: { blocked: 0 },
      cost: { totalUSD: 0 },
    },
    generatedAt: '2026-05-10T15:00:00Z',
  };
  return { data, hasAuditFile: true, responseDlpEntries: [] };
}

function makeBlast(paths: number = 0): BlastSnapshot {
  return {
    paths: Array.from({ length: paths }, (_, i) => ({
      label: `~/.path${i}`,
      description: `desc${i}`,
    })),
    envFindings: 0,
  };
}

const EMPTY_RESULT = {
  filesScanned: 0,
  sessions: 0,
  totalToolCalls: 0,
  bashCalls: 0,
  findings: [],
  dlpFindings: [],
  canaryFindings: [],
  loopFindings: [],
  totalCostUSD: 0,
  firstDate: null,
  lastDate: null,
  sessionsWithEarlySecrets: 0,
  perSession: [],
};

const READY: ScanCache = {
  status: 'ready',
  readyAt: 0,
  results: {
    claude: { ...EMPTY_RESULT },
    gemini: { ...EMPTY_RESULT },
    codex: { ...EMPTY_RESULT },
    copilot: { ...EMPTY_RESULT },
    antigravity: { ...EMPTY_RESULT },
  },
};

// ---------------------------------------------------------------------------
// Score tier rendering
// ---------------------------------------------------------------------------

describe('ScoreBanner score (the posture score, fw#421)', () => {
  const posture = (score: number, tier: 'good' | 'at-risk' | 'critical', action?: string) => ({
    score,
    tier,
    action: action ?? null,
    headroom: 0,
    at: 0,
  });

  it('renders dim "—/100" while the posture has not loaded', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit(1.23)}
        blast={makeBlast()}
        posture={null}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('Score —/100');
    expect(lastFrame()).toContain('$1.23');
  });

  it('renders Critical for the critical tier', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast()}
        posture={posture(0, 'critical')}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('Score 0/100');
    expect(lastFrame()).toContain('Critical');
  });

  it('renders At risk and Good for the other tiers', () => {
    const atRisk = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast()}
        posture={posture(60, 'at-risk')}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(atRisk.lastFrame()).toContain('Score 60/100');
    expect(atRisk.lastFrame()).toContain('At risk');
    const good = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast()}
        posture={posture(92, 'good')}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(good.lastFrame()).toContain('Score 92/100');
    expect(good.lastFrame()).toContain('Good');
  });

  it('row 2 is the posture action and the hardening headroom, never a blast breakdown', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast()}
        posture={{ ...posture(40, 'critical', 'Lock egress: node9 egress lock'), headroom: 16 }}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    const out = lastFrame() ?? '';
    expect(out).toContain('Lock egress');
    expect(out).toContain('16 pts');
    expect(out).not.toContain('exposed');
    expect(out).not.toContain('effective');
  });

  it('omits row 2 when there is no action and no headroom', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast()}
        posture={posture(100, 'good')}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).not.toContain('pts');
  });
});

describe('ScoreBanner headline cascade', () => {
  it('shows "scanning history…" while scanCache is loading', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(3)} // exposed paths exist but scan still loading
        scanCache={{ status: 'loading' }}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('scanning history');
    // Loading state preempts even the blast-paths cascade tier
    expect(lastFrame()).not.toContain('exposed path');
  });

  it('shows "[r] to start" affordance while scanCache is idle (transient)', () => {
    // Idle is transient now — entering [2] auto-starts the walk. The
    // banner still surfaces an affordance in case the user lands here
    // (e.g. mid-cancel) so they know how to kick a rescan.
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(3)}
        scanCache={{ status: 'idle' }}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('[r] to start');
  });

  it('shows scan-failed message on cache error', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast()}
        scanCache={{ status: 'error', error: new Error('boom') }}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('scan failed');
  });

  it('sessions-with-early-secrets does NOT trigger the headline (cascade rule retired)', () => {
    // The lifetime-of-history `sessionsWithEarlySecrets` cascade rule
    // was removed 2026-05-12 — it produced a stuck red badge from
    // sessions long outside the selected period. With sessionsWithEarlySecrets=2
    // and NO leaks/loops/blast paths, the headline now falls through
    // to the dim "clean" state instead of pinning a misleading
    // pre-edit-secrets message.
    const filtered: FilteredScan = {
      ...EMPTY_FILTERED_SCAN,
      sessionsWithEarlySecrets: 2,
    };
    const { lastFrame } = render(
      <ScoreBanner audit={makeAudit()} blast={makeBlast()} scanCache={READY} filtered={filtered} />
    );
    expect(lastFrame()).not.toContain('loaded secrets pre-edit');
  });

  it('headline tier 2 — leaks > 0 (when no early-secrets)', () => {
    const filtered: FilteredScan = {
      ...EMPTY_FILTERED_SCAN,
      leaks: [
        {
          patternName: 'X',
          redactedSample: '',
          toolName: '',
          timestamp: '',
          project: '',
          sessionId: '',
          agent: 'claude',
        },
        {
          patternName: 'X',
          redactedSample: '',
          toolName: '',
          timestamp: '',
          project: '',
          sessionId: '',
          agent: 'claude',
        },
        {
          patternName: 'X',
          redactedSample: '',
          toolName: '',
          timestamp: '',
          project: '',
          sessionId: '',
          agent: 'claude',
        },
      ] as FilteredScan['leaks'],
    };
    const { lastFrame } = render(
      <ScoreBanner audit={makeAudit()} blast={makeBlast()} scanCache={READY} filtered={filtered} />
    );
    expect(lastFrame()).toContain('3 leaks this period');
  });

  it('headline tier 3 — loops > 100, counts and no cost estimate', () => {
    const loops = Array.from({ length: 150 }, () => ({
      toolName: 'Edit',
      commandPreview: '/x',
      count: 10,
      timestamp: '',
      project: '',
      sessionId: '',
      agent: 'claude' as const,
    }));
    const filtered: FilteredScan = {
      ...EMPTY_FILTERED_SCAN,
      loops,
    };
    const { lastFrame } = render(
      <ScoreBanner audit={makeAudit()} blast={makeBlast()} scanCache={READY} filtered={filtered} />
    );
    // Was: `150 loops · ~$9.00 wasted`, from Σ(count) × COST_PER_LOOP_ITER_USD.
    // Wrong three ways — it billed the first legitimate call, counted
    // long-iteration findings as loops, and used a constant measured ~170x
    // low. Two inflations and one deflation landed on a believable number
    // while `node9 scan` reported five times more from the same data.
    //
    // The headline now states what it counted. Dollars live on the one screen
    // that prices them per session.
    expect(lastFrame()).toContain('150 repeated patterns');
    expect(lastFrame()).not.toContain('wasted');
    // Scoped to the headline: the banner has its own spend indicator, so a
    // bare "no $ anywhere" assertion would fail on unrelated output.
    const headline = (lastFrame() ?? '').split('📌')[1]?.split('💰')[0] ?? '';
    expect(headline).not.toContain('$');
  });

  it('headline tier 4 — exposed blast paths (when no leaks/loops/early-secrets)', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(4)}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('4 exposed paths');
  });

  it('headline tier 5 — clean state shows dim placeholder', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast()}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('no critical issues this period');
  });

  it('singular grammar: "1 leak this period" not "1 leaks"', () => {
    const filtered: FilteredScan = {
      ...EMPTY_FILTERED_SCAN,
      leaks: [
        {
          patternName: 'X',
          redactedSample: '',
          toolName: '',
          timestamp: '',
          project: '',
          sessionId: '',
          agent: 'claude',
        },
      ] as FilteredScan['leaks'],
    };
    const { lastFrame } = render(
      <ScoreBanner audit={makeAudit()} blast={makeBlast()} scanCache={READY} filtered={filtered} />
    );
    expect(lastFrame()).toContain('1 leak this period');
    expect(lastFrame()).not.toContain('1 leaks');
  });
});

// ---------------------------------------------------------------------------
// Spend rendering
// ---------------------------------------------------------------------------

describe('ScoreBanner spend', () => {
  it('renders spend from audit cost (claude + codex)', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit(4.23)}
        blast={makeBlast(4)}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('$4.23');
  });

  it('renders $0 when no spend', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit(0)}
        blast={makeBlast()}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('$0');
  });

  it('renders rounded thousands above $100', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit(11678.76)}
        blast={makeBlast()}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('$11,679');
  });
});
