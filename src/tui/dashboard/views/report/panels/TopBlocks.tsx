// src/tui/dashboard/views/report/panels/TopBlocks.tsx
//
// Top-row panel: most-fired block reasons with horizontal bars. Pulled
// from BuildReportJsonInput.blockMap, sorted descending, top 5. Each row
// is human-readable label + bar (red for blocks) + count.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import { humanBlockReason, num, renderBar } from '../util.js';

const ROW_LIMIT = 5;
const BAR_WIDTH = 6;

export function TopBlocks({ audit }: { audit: AggregateResult | null }): React.ReactElement {
  const data = audit?.data;
  const sorted = data
    ? [...data.blockMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, ROW_LIMIT)
    : [];
  const max = sorted.length > 0 ? sorted[0][1] : 0;

  return (
    <Box
      borderStyle="round"
      borderColor={COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={1}
      flexBasis={0}
    >
      <Text bold>TOP BLOCKS</Text>
      {audit === null ? (
        <Text dimColor>loading…</Text>
      ) : sorted.length === 0 ? (
        <Text dimColor>nothing blocked ✓</Text>
      ) : (
        sorted.map(([reason, count]) => (
          // Single-Text-with-truncate so the row stays exactly 1 line tall.
          <Text key={reason} wrap="truncate-end">
            {humanBlockReason(reason).padEnd(12)}{' '}
            <Text color="red">{renderBar(count, max, BAR_WIDTH)}</Text>{' '}
            <Text bold>{num(count).padStart(4)}</Text>
          </Text>
        ))
      )}
    </Box>
  );
}
