/**
 * Render coverage for the HIGH LEVEL panel.
 *
 * The cost / token figures shown here are deliberately scoped to "spend
 * since the monitor opened" (App.tsx subtracts a baseline at mount).
 * The window-label caption (`labelFor`) communicates that scope to the
 * user — we pin its presence here so a future copy refactor can't
 * silently drop the only contextual signal on this panel.
 */
import React from 'react';
import { describe, expect, it } from 'vitest';
import { render } from 'ink-testing-library';

import { HighLevel } from '../tui/dashboard/panels';
import type { AuditAggregates, CostSnapshot, TimeWindow } from '../tui/dashboard/types';

function makeAgg(overrides: Partial<AuditAggregates> = {}): AuditAggregates {
  return {
    total: 0,
    allow: 0,
    block: 0,
    review: 0,
    loops: 0,
    dlpHits: 0,
    sessions: 0,
    mcpServers: 0,
    mcpCalls: 0,
    byTool: [],
    byBlock: [],
    byShell: [],
    ...overrides,
  };
}

function makeCost(overrides: Partial<CostSnapshot> = {}): CostSnapshot {
  return {
    totalUSD: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    byModel: [],
    loaded: true,
    ...overrides,
  };
}

const WINDOW: TimeWindow = '1d';

describe('HighLevel', () => {
  it('renders the window-label caption ("last 24 hours" / "since dashboard opened" / etc.)', () => {
    const { lastFrame } = render(
      <HighLevel window="1d" agg={makeAgg()} cost={makeCost()} skillsPinned={0} mcpPinned={0} />
    );
    expect(lastFrame()).toContain('last 24 hours');
  });

  it('renders "since dashboard opened" when the window is `now`', () => {
    const { lastFrame } = render(
      <HighLevel window="now" agg={makeAgg()} cost={makeCost()} skillsPinned={0} mcpPinned={0} />
    );
    expect(lastFrame()).toContain('since dashboard opened');
  });

  it('renders the cost panel content even when totals are zero', () => {
    const { lastFrame } = render(
      <HighLevel window={WINDOW} agg={makeAgg()} cost={makeCost()} skillsPinned={0} mcpPinned={0} />
    );
    const frame = lastFrame() ?? '';
    expect(frame).toContain('cost');
    expect(frame).toContain('tokens');
  });

  it('shows "cost loading…" placeholder while the initial walk is in flight', () => {
    const { lastFrame } = render(
      <HighLevel window={WINDOW} agg={makeAgg()} cost={null} skillsPinned={0} mcpPinned={0} />
    );
    expect(lastFrame()).toContain('cost loading');
  });
});
