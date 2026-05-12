// src/cli/render/ink/panels/ActivityPanel.tsx
//
// Right-side panel in the "Spend & activity" band, sits next to
// CostPanel. Surfaces volume metrics that complement the dollar
// figures: how much agent time, how many tool calls, the date
// window in scope.
//
// Data — all from ScanSummary.stats which the scan pipeline
// already populates. No new walker work needed.
//
// Tokens are intentionally NOT here (yet) — scan today aggregates
// cost but not per-agent token counts. The data plumbing would be
// a separate change. Will revisit if useful for spend attribution.

import React from 'react';
import { Box, Text } from 'ink';

import type { ScanSummary } from '../../../../scan-summary.js';

interface Props {
  summary: ScanSummary;
}

const LABEL_W = 16;

/** Display a short date like "Apr 6". Returns "?" on bad input. */
function fmtDate(iso: string | null): string {
  if (!iso) return '?';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '?';
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function fmtNum(n: number): string {
  return n.toLocaleString();
}

export function ActivityPanel({ summary }: Props): React.ReactElement {
  const { sessions, totalToolCalls, bashCalls, totalCostUSD, firstDate, lastDate } = summary.stats;
  const perSession = sessions > 0 ? totalCostUSD / sessions : 0;
  return (
    <Box borderStyle="round" borderColor="gray" paddingX={1} flexDirection="column" width={32}>
      <Text bold>ACTIVITY</Text>

      <Box>
        <Box width={LABEL_W}>
          <Text>Sessions</Text>
        </Box>
        <Text bold>{fmtNum(sessions)}</Text>
      </Box>

      <Box>
        <Box width={LABEL_W}>
          <Text>Tool calls</Text>
        </Box>
        <Text>{fmtNum(totalToolCalls)}</Text>
      </Box>

      <Box>
        <Box width={LABEL_W}>
          <Text dimColor>{'  Bash'}</Text>
        </Box>
        <Text dimColor>{fmtNum(bashCalls)}</Text>
      </Box>

      <Box>
        <Box width={LABEL_W}>
          <Text>Cost / session</Text>
        </Box>
        <Text>{'~$' + Math.round(perSession).toLocaleString()}</Text>
      </Box>

      <Box>
        <Text dimColor>{`${fmtDate(firstDate)} → ${fmtDate(lastDate)}`}</Text>
      </Box>
    </Box>
  );
}
