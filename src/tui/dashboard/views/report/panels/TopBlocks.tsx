// src/tui/dashboard/views/report/panels/TopBlocks.tsx
//
// Top-row panel: most-fired block reasons with horizontal bars. Pulled
// from BuildReportJsonInput.blockMap, sorted descending, top 5. Each row
// is human-readable label + bar (red for blocks) + count.
//
// Uses fixed-width Box columns + `fitLabel` on the label so a long
// reason string ("Persistent deny", "Smart rule", …) doesn't push the
// count off the column. height={1} keeps each row exactly one line.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import { fitLabel, humanBlockReason, num, renderBar } from '../util.js';

const ROW_LIMIT = 5;
const LABEL_W = 12;
const BAR_W = 6;
const COUNT_W = 4;

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
          <Box key={reason} height={1}>
            <Box width={LABEL_W}>
              <Text>{fitLabel(humanBlockReason(reason), LABEL_W)}</Text>
            </Box>
            <Text> </Text>
            <Text color="red">{renderBar(count, max, BAR_W)}</Text>
            <Text> </Text>
            <Box width={COUNT_W} justifyContent="flex-end">
              <Text bold>{num(count)}</Text>
            </Box>
          </Box>
        ))
      )}
    </Box>
  );
}
