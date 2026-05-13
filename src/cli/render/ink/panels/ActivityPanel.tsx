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
// MCP counts: scan.findings carry a toolName per finding. Any tool
// matching the `mcp__*` naming convention counts as MCP. This is
// approximate (only counts findings that matched a rule), but it's
// the best we can do without instrumenting the JSONL walker to
// track MCP separately. TODO: thread total MCP call count through
// ScanResult so this panel can show a true count.

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

/** Approximate MCP call count from findings (tools matching mcp__*).
 *  Under-counts since findings only include rule-matches, not all
 *  MCP calls. Returns 0 if none. */
function countMcpFindings(scan: ScanResult): number {
  let n = 0;
  for (const f of scan.findings) {
    if (f.toolName.startsWith('mcp__')) n++;
  }
  return n;
}

export function ActivityPanel({ summary, scan, width }: Props): React.ReactElement {
  const { sessions, totalToolCalls, bashCalls, totalCostUSD } = summary.stats;
  const perSession = sessions > 0 ? totalCostUSD / sessions : 0;
  const mcpCount = countMcpFindings(scan);
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
          <Text dimColor>{fmtNum(mcpCount)}</Text>
        </Box>
      ) : null}

      <Box>
        <Box width={LABEL_W}>
          <Text>Cost / session</Text>
        </Box>
        <Text>{'~$' + Math.round(perSession).toLocaleString()}</Text>
      </Box>
    </Box>
  );
}
