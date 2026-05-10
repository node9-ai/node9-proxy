/**
 * Render tests for the loading + empty states across the Report [2]
 * panels. Each panel exposes a "loading…" placeholder when its data
 * source is null (initial mount before useEffect fires) and a panel-
 * specific empty state when the data is loaded but the period is
 * empty. This file exercises both branches per panel.
 *
 * The populated branches are visible to the user via manual smoke
 * test + are type-checked, but loading/empty paths are easy to break
 * (e.g. forgetting null-coalescing on a Map.get) so worth automating.
 */
import React from 'react';
import { describe, it, expect } from 'vitest';
import { render } from 'ink-testing-library';

import { Protection } from '../tui/dashboard/views/report/panels/Protection';
import { TopBlocks } from '../tui/dashboard/views/report/panels/TopBlocks';
import { ThisWeek } from '../tui/dashboard/views/report/panels/ThisWeek';
import { BlastRadius } from '../tui/dashboard/views/report/panels/BlastRadius';
import { FooterStrip } from '../tui/dashboard/views/report/panels/FooterStrip';
import type { AggregateResult } from '../cli/aggregate/report-audit';
import type { BuildReportJsonInput } from '../cli/render/report-json';
import type { BlastSnapshot, ShieldStatus } from '../tui/dashboard/types';

// ---------------------------------------------------------------------------
// Audit fixture builder — minimal counts, all maps default to empty
// ---------------------------------------------------------------------------

function emptyAudit(overrides: Partial<BuildReportJsonInput> = {}): AggregateResult {
  const data: BuildReportJsonInput = {
    period: '7d',
    start: new Date('2026-05-04T00:00:00Z'),
    end: new Date('2026-05-10T23:59:59Z'),
    excludedTests: 0,
    total: 0,
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
      claudeUSD: 0,
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
    ...overrides,
  };
  return { data, hasAuditFile: true, responseDlpEntries: [] };
}

// ---------------------------------------------------------------------------
// Protection
// ---------------------------------------------------------------------------

describe('Protection', () => {
  it('renders "loading…" when audit is null', () => {
    const { lastFrame } = render(<Protection audit={null} />);
    expect(lastFrame()).toContain('PROTECTION');
    expect(lastFrame()).toContain('loading…');
  });

  it('renders "no activity this period" when audit has zero events', () => {
    const { lastFrame } = render(<Protection audit={emptyAudit()} />);
    expect(lastFrame()).toContain('no activity this period');
  });

  it('renders counter rows when activity exists', () => {
    const { lastFrame } = render(
      <Protection audit={emptyAudit({ total: 10, userApproved: 7, userDenied: 3 })} />
    );
    expect(lastFrame()).toContain('Approved');
    expect(lastFrame()).toContain('7');
    expect(lastFrame()).toContain('3');
  });
});

// ---------------------------------------------------------------------------
// TopBlocks
// ---------------------------------------------------------------------------

describe('TopBlocks', () => {
  it('renders "loading…" when audit is null', () => {
    const { lastFrame } = render(<TopBlocks audit={null} />);
    expect(lastFrame()).toContain('TOP BLOCKS');
    expect(lastFrame()).toContain('loading…');
  });

  it('renders "nothing blocked ✓" when blockMap is empty', () => {
    const { lastFrame } = render(<TopBlocks audit={emptyAudit()} />);
    expect(lastFrame()).toContain('nothing blocked');
  });

  it('renders block rows with humanized labels', () => {
    const audit = emptyAudit({
      blockMap: new Map([
        ['smart-rule-block', 5],
        ['timeout', 2],
      ]),
    });
    const { lastFrame } = render(<TopBlocks audit={audit} />);
    expect(lastFrame()).toContain('Smart rule');
    // Long reason "Approval timeout" gets truncated by fitLabel(LABEL_W=12)
    // — assert the truncated prefix is present rather than the full string.
    expect(lastFrame()).toContain('Approval');
  });
});

// ---------------------------------------------------------------------------
// ThisWeek
// ---------------------------------------------------------------------------

describe('ThisWeek', () => {
  it('renders "loading…" when audit is null', () => {
    const { lastFrame } = render(<ThisWeek audit={null} />);
    expect(lastFrame()).toContain('THIS WEEK');
    expect(lastFrame()).toContain('loading…');
  });

  it('renders "no activity this period" when dailyMap is empty', () => {
    const { lastFrame } = render(<ThisWeek audit={emptyAudit()} />);
    expect(lastFrame()).toContain('no activity this period');
  });

  it('renders daily rows with date + count + cost', () => {
    const audit = emptyAudit({
      dailyMap: new Map([['2026-05-09', { calls: 1419, blocked: 304 }]]),
      cost: {
        claudeUSD: 1101.31,
        codexUSD: 0,
        inputTokens: 0,
        outputTokens: 0,
        cacheWriteTokens: 0,
        cacheReadTokens: 0,
        byDay: new Map([['2026-05-09', 1101.31]]),
        byModel: new Map(),
      },
    });
    const { lastFrame } = render(<ThisWeek audit={audit} />);
    expect(lastFrame()).toContain('May 9');
    expect(lastFrame()).toContain('1,419');
    expect(lastFrame()).toContain('$1,101');
  });
});

// ---------------------------------------------------------------------------
// BlastRadius
// ---------------------------------------------------------------------------

describe('BlastRadius', () => {
  it('renders "loading…" header when blast is null', () => {
    const { lastFrame } = render(<BlastRadius blast={null} protectedByProjectJail={false} />);
    expect(lastFrame()).toContain('BLAST RADIUS');
    expect(lastFrame()).toContain('loading…');
  });

  it('renders "no exposed sensitive files" when paths is empty', () => {
    const blast: BlastSnapshot = { score: 100, paths: [], envFindings: 0 };
    const { lastFrame } = render(<BlastRadius blast={blast} protectedByProjectJail={false} />);
    expect(lastFrame()).toContain('no exposed sensitive files');
  });

  it('renders one row per exposed path with description', () => {
    const blast: BlastSnapshot = {
      score: 30,
      envFindings: 0,
      paths: [
        { label: '~/.ssh/id_rsa', description: 'RSA private key', score: 20 },
        { label: '~/.npmrc', description: 'npm auth token', score: 10 },
      ],
    };
    const { lastFrame } = render(<BlastRadius blast={blast} protectedByProjectJail={false} />);
    expect(lastFrame()).toContain('~/.ssh/id_rsa');
    expect(lastFrame()).toContain('RSA private key');
    expect(lastFrame()).toContain('~/.npmrc');
    expect(lastFrame()).toContain('→ enable project-jail');
  });

  it('shows "blocked by project-jail" when shield is active', () => {
    const blast: BlastSnapshot = {
      score: 30,
      envFindings: 0,
      paths: [{ label: '~/.npmrc', description: 'npm auth token', score: 10 }],
    };
    const { lastFrame } = render(<BlastRadius blast={blast} protectedByProjectJail={true} />);
    expect(lastFrame()).toContain('blocked by project-jail');
    expect(lastFrame()).not.toContain('→ enable project-jail');
  });

  it('uses singular grammar for exactly 1 path on disk', () => {
    const blast: BlastSnapshot = {
      score: 80,
      envFindings: 0,
      paths: [{ label: '~/.npmrc', description: 'npm auth token', score: 10 }],
    };
    const { lastFrame } = render(<BlastRadius blast={blast} protectedByProjectJail={false} />);
    expect(lastFrame()).toContain('1 path on disk');
    expect(lastFrame()).not.toContain('1 paths on disk');
  });
});

// ---------------------------------------------------------------------------
// FooterStrip
// ---------------------------------------------------------------------------

describe('FooterStrip', () => {
  it('renders "loading…" when shieldStatus is null', () => {
    const { lastFrame } = render(<FooterStrip shieldStatus={null} audit={null} />);
    expect(lastFrame()).toContain('SHIELDS');
    expect(lastFrame()).toContain('loading…');
  });

  it('renders active shield names + inactive count', () => {
    const shieldStatus: ShieldStatus = {
      active: ['project-jail', 'bash-safe', 'filesystem'],
      inactive: ['aws', 'docker', 'k8s'],
    };
    const { lastFrame } = render(<FooterStrip shieldStatus={shieldStatus} audit={null} />);
    expect(lastFrame()).toContain('project-jail');
    expect(lastFrame()).toContain('bash-safe');
    expect(lastFrame()).toContain('3 inactive');
  });

  it('renders "(none)" when no active shields', () => {
    const shieldStatus: ShieldStatus = { active: [], inactive: ['aws'] };
    const { lastFrame } = render(<FooterStrip shieldStatus={shieldStatus} audit={null} />);
    expect(lastFrame()).toContain('(none)');
  });

  it('shows +N overflow when more than 4 active shields', () => {
    const shieldStatus: ShieldStatus = {
      active: ['a', 'b', 'c', 'd', 'e', 'f'],
      inactive: [],
    };
    const { lastFrame } = render(<FooterStrip shieldStatus={shieldStatus} audit={null} />);
    expect(lastFrame()).toContain('+2');
  });

  it('renders the HOUR OF DAY sparkline label', () => {
    const { lastFrame } = render(<FooterStrip shieldStatus={null} audit={null} />);
    expect(lastFrame()).toContain('HOUR OF DAY');
    expect(lastFrame()).toContain('0h');
    expect(lastFrame()).toContain('23h');
  });
});
