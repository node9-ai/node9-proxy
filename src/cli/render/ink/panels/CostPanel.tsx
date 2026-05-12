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
}

const LABEL_W = 16;

export function CostPanel({ summary }: Props): React.ReactElement {
  const total = summary.stats.totalCostUSD;
  return (
    <Box borderStyle="round" borderColor="gray" paddingX={1} flexDirection="column" width={32}>
      <Text bold>COST</Text>

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
