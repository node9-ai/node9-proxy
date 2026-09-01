// src/cli/render/ink/panels/CostPanel.tsx
//
// Spend rollup panel for the new Ink-rendered scan scorecard. Sits
// in the top "Spend & activity" band, paired side-by-side with the
// ACTIVITY panel (added in commit #2).
//
// Data sources (all from ScanSummary):
//   - summary.stats.totalCostUSD — total spend across all agents
//   - summary.byAgent[].costUSD — per-agent breakdown (Claude/Codex/Gemini/...)
//   - summary.loopWastedUSD — estimated wasted dollars on agent loops
//
// Width is fixed at 30 columns for the spike (commit #1). Commit #2
// will let the parent flexbox row decide width when ACTIVITY joins it.

import React from 'react';
import { Box, Text } from 'ink';

import type { ScanSummary } from '../../../../scan-summary.js';
import { formatCost } from '../../../../tui/dashboard/format.js';

interface Props {
  summary: ScanSummary;
  width: number;
}

const LABEL_W = 16;

export function CostPanel({ summary, width }: Props): React.ReactElement {
  const total = summary.stats.totalCostUSD;
  return (
    <Box borderStyle="round" borderColor="gray" paddingX={1} flexDirection="column" width={width}>
      {/* "API value", not "spend": this is tokens x list price. A user on a
          flat monthly plan pays their plan, not this — and today the product
          has no concept of a plan at all, so an unqualified "Total" asserts
          something false for every subscriber. The number is right; the word
          was wrong. It is also the better story once labelled: this much
          value consumed, against whatever the plan actually costs. */}
      <Text bold>COST · API value</Text>

      <Box>
        <Box width={LABEL_W}>
          <Text>Total</Text>
        </Box>
        <Text bold>{formatCost(total)}</Text>
      </Box>

      {summary.byAgent.map((agent) => (
        <Box key={agent.id}>
          <Box width={LABEL_W}>
            <Text>{agent.label}</Text>
          </Box>
          <Text>{formatCost(agent.costUSD)}</Text>
        </Box>
      ))}

      {summary.loopWastedUSD > 0 ? (
        <Box>
          <Box width={LABEL_W}>
            <Text dimColor>Wasted on loops</Text>
          </Box>
          <Text color="yellow">{'~' + formatCost(summary.loopWastedUSD)}</Text>
        </Box>
      ) : null}
    </Box>
  );
}
