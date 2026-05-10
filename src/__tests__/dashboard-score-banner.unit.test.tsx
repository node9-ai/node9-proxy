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
      inputTokens: 0,
      outputTokens: 0,
      cacheWriteTokens: 0,
      cacheReadTokens: 0,
      byDay: new Map(),
      byModel: new Map(),
    },
    toolMap: new Map(),
    blockMap: new Map(),
    agentMap: new Map(),
    mcpMap: new Map(),
    dailyMap: new Map(),
    hourMap: new Map(),
    generatedAt: '2026-05-10T15:00:00Z',
  };
  return { data, hasAuditFile: true, responseDlpEntries: [] };
}

function makeBlast(score: number, paths: number = 0): BlastSnapshot {
  return {
    score,
    paths: Array.from({ length: paths }, (_, i) => ({
      label: `~/.path${i}`,
      description: `desc${i}`,
      score: 5,
    })),
    envFindings: 0,
  };
}

const READY: ScanCache = {
  status: 'ready',
  readyAt: 0,
  results: {
    claude: {
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
    },
    gemini: {
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
    },
    codex: {
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
    },
  },
};

// ---------------------------------------------------------------------------
// Score tier rendering
// ---------------------------------------------------------------------------

describe('ScoreBanner score tier', () => {
  it('renders dim "—/100" when blast is null', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit(1.23)}
        blast={null}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('Score —/100');
  });

  it('renders Critical when score < 25', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(20)}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('Score 20/100');
    expect(lastFrame()).toContain('Critical');
  });

  it('renders High risk for 25 ≤ score < 50', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(30)}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('High risk');
  });

  it('renders Moderate for 50 ≤ score < 80', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(70)}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('Moderate');
  });

  it('renders Good for score ≥ 80', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(95)}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('Good');
  });
});

// ---------------------------------------------------------------------------
// Headline cascade — first match wins
// ---------------------------------------------------------------------------

describe('ScoreBanner headline cascade', () => {
  it('shows "scanning history…" while scanCache is loading', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(95, 3)} // exposed paths exist but scan still loading
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
        blast={makeBlast(95, 3)}
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
        blast={makeBlast(95)}
        scanCache={{ status: 'error', error: new Error('boom') }}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('scan failed');
  });

  it('headline tier 1 — sessions-with-early-secrets wins over leaks', () => {
    const filtered: FilteredScan = {
      ...EMPTY_FILTERED_SCAN,
      sessionsWithEarlySecrets: 2,
      // Even with leaks present, the pre-edit-secrets headline comes first
      leaks: [
        // a couple leak placeholders — only length is read by the cascade
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
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(95)}
        scanCache={READY}
        filtered={filtered}
      />
    );
    expect(lastFrame()).toContain('2 sessions loaded secrets pre-edit');
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
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(95)}
        scanCache={READY}
        filtered={filtered}
      />
    );
    expect(lastFrame()).toContain('3 leaks this period');
  });

  it('headline tier 3 — loops > 100 with cost estimate', () => {
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
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(95)}
        scanCache={READY}
        filtered={filtered}
      />
    );
    expect(lastFrame()).toContain('150 loops');
    expect(lastFrame()).toContain('wasted');
    // 150 loops * count 10 * COST_PER_LOOP_ITER_USD (0.006) = $9 → "$9.00"
    expect(lastFrame()).toContain('$9.00');
  });

  it('headline tier 4 — exposed blast paths (when no leaks/loops/early-secrets)', () => {
    const { lastFrame } = render(
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(40, 4)}
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
        blast={makeBlast(95, 0)}
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
      <ScoreBanner
        audit={makeAudit()}
        blast={makeBlast(95)}
        scanCache={READY}
        filtered={filtered}
      />
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
        blast={makeBlast(95)}
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
        blast={makeBlast(95)}
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
        blast={makeBlast(95)}
        scanCache={READY}
        filtered={EMPTY_FILTERED_SCAN}
      />
    );
    expect(lastFrame()).toContain('$11,679');
  });
});
