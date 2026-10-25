// src/cli/render/ink/panels/ActivityPanel.tsx
//
// Right-side panel in the "Spend & activity" band, sits next to
// CostPanel. Surfaces volume metrics that complement the dollar
// figures: sessions, tools, shell, MCP counts.
//
// Date range is intentionally NOT here — it's already in the
// scorecard's header line ("scanned last 90 days") so duplicating
// it in this panel is noise.
//
// MCP: the number of `mcp__<server>__*` tool calls in the window, from the
// same tally as Shell (fw#403), with the busiest server beside it.

import React from 'react';
import { Box, Text } from 'ink';

import type { ScanSummary } from '../../../../scan-summary.js';
import type { ScanResult } from '../../../commands/scan.js';

interface Props {
  summary: ScanSummary;
  scan: ScanResult;
  width: number;
}

const LABEL_W = 16;

function fmtNum(n: number): string {
  return n.toLocaleString();
}

export function ActivityPanel({ summary, scan, width }: Props): React.ReactElement {
  const { sessions, totalToolCalls, bashCalls, totalCostUSD, mcpCalls, mcpByServer } =
    summary.stats;
  const perSession = sessions > 0 ? totalCostUSD / sessions : 0;
  const toolsPerSession = sessions > 0 ? Math.round(totalToolCalls / sessions) : 0;
  const mcpCount = mcpCalls ?? 0;
  const topServer = Object.entries(mcpByServer ?? {}).sort((a, b) => b[1] - a[1])[0];
  void scan;
  // Find the most-active agent (by sessions). Surfaces "Claude
  // dominates" / "Codex took over" without needing a dedicated panel.
  const topAgent = summary.byAgent.slice().sort((a, b) => b.sessions - a.sessions)[0];
  return (
    <Box borderStyle="round" borderColor="gray" paddingX={1} flexDirection="column" width={width}>
      <Text bold>ACTIVITY</Text>

      <Box>
        <Box width={LABEL_W}>
          <Text>Sessions</Text>
        </Box>
        <Text bold>{fmtNum(sessions)}</Text>
      </Box>

      <Box>
        <Box width={LABEL_W}>
          <Text>Tools</Text>
        </Box>
        <Text>{fmtNum(totalToolCalls)}</Text>
      </Box>

      <Box>
        <Box width={LABEL_W}>
          <Text dimColor>{'  Shell'}</Text>
        </Box>
        <Text dimColor>{fmtNum(bashCalls)}</Text>
      </Box>

      {mcpCount > 0 ? (
        <Box>
          <Box width={LABEL_W}>
            <Text dimColor>{'  MCP'}</Text>
          </Box>
          <Text dimColor>
            {fmtNum(mcpCount)}
            {topServer ? `  (${topServer[0]} ${fmtNum(topServer[1])})` : ''}
          </Text>
        </Box>
      ) : null}

      <Box>
        <Box width={LABEL_W}>
          <Text>Tools / session</Text>
        </Box>
        <Text>{'~' + fmtNum(toolsPerSession)}</Text>
      </Box>

      <Box>
        <Box width={LABEL_W}>
          <Text>Cost / session</Text>
        </Box>
        <Text>{'~$' + Math.round(perSession).toLocaleString()}</Text>
      </Box>

      {topAgent ? (
        <Box>
          <Box width={LABEL_W}>
            <Text dimColor>Top agent</Text>
          </Box>
          <Text dimColor>{`${topAgent.label} (${fmtNum(topAgent.sessions)})`}</Text>
        </Box>
      ) : null}
    </Box>
  );
}
