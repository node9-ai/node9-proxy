// src/tui/dashboard/views/report/panels/Cost.tsx
//
// Upper-row panel: cost rollup for the selected period. Shows total
// spend + tokens, per-agent breakdown (Claude / Codex), and a daily
// cost sparkline.
//
// Replaces TOP BLOCKS in the upper row (which had a red bar chart of
// rule fire counts — informative but the bars wasted column width).
// TOP BLOCKS info moves to the bottom row alongside LEAKS / LOOPS in
// a later commit (see roadmap Phase 2 sub-commit #5).
//
// Data sources (all from the audit-log aggregator, period-bounded):
//   - audit.data.cost.claudeUSD / codexUSD — per-agent spend
//   - audit.data.cost.inputTokens / outputTokens — total tokens
//   - audit.data.cost.byDay — Map<day, USD> for the sparkline
//
// Per-agent tokens aren't tracked (the JSONL files give us tokens at
// the message level, not per-agent rollup), so the panel shows total
// tokens once on the Total line — no per-agent tokens column.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import { formatCost, formatTokens } from '../../../format.js';
import { sparkline } from '../util.js';

const LABEL_W = 10;

export function Cost({ audit }: { audit: AggregateResult | null }): React.ReactElement {
  const data = audit?.data;
  const total = data ? data.cost.claudeUSD + data.cost.codexUSD : 0;
  const totalTokens = data ? data.cost.inputTokens + data.cost.outputTokens : 0;
  const claude = data?.cost.claudeUSD ?? 0;
  const codex = data?.cost.codexUSD ?? 0;

  // Daily sparkline — Map<ISO day, USD>. Sort by day so the trend
  // reads left-to-right oldest → newest. Cap to the LAST N days so
  // longer periods (30d / 90d) don't overflow the narrow column and
  // wrap onto a second line. 14 cells comfortably fits next to the
  // "Trend" label inside the COST panel at typical widths.
  const SPARK_CELLS = 14;
  const daySeries = data
    ? [...data.cost.byDay.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([, usd]) => usd)
        .slice(-SPARK_CELLS)
    : [];
  const trend = daySeries.length > 0 ? sparkline(daySeries) : '';

  return (
    <Box
      borderStyle="round"
      borderColor={COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={1}
      flexBasis={0}
    >
      <Text bold>COST</Text>
      {audit === null ? (
        <Text dimColor>loading…</Text>
      ) : (
        <>
          <Box height={1}>
            <Box width={LABEL_W}>
              <Text>Total</Text>
            </Box>
            <Text bold>{formatCost(total)}</Text>
            <Text>{'   '}</Text>
            <Text dimColor>{`${formatTokens(totalTokens)} tokens`}</Text>
          </Box>
          <Box height={1}>
            <Box width={LABEL_W}>
              <Text>Claude</Text>
            </Box>
            <Text>{formatCost(claude)}</Text>
          </Box>
          <Box height={1}>
            <Box width={LABEL_W}>
              <Text>Codex</Text>
            </Box>
            <Text>{formatCost(codex)}</Text>
          </Box>
          {/* Gemini cost isn't tracked by the aggregator yet —
              Gemini sessions appear in agentMap (so the header
              shows "Gemini N") but the JSONL cost walker only
              handles Claude / Codex. Render an explicit "—" so the
              user knows it's not missing data, it's a known gap. */}
          <Box height={1}>
            <Box width={LABEL_W}>
              <Text dimColor>Gemini</Text>
            </Box>
            <Text dimColor>— (not tracked)</Text>
          </Box>
          <Box height={1}>
            <Box width={LABEL_W}>
              <Text dimColor>Trend</Text>
            </Box>
            <Text>{trend || <Text dimColor>(no data)</Text>}</Text>
          </Box>
        </>
      )}
    </Box>
  );
}
