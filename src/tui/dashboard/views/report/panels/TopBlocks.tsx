// src/tui/dashboard/views/report/panels/TopBlocks.tsx
//
// Bottom-row panel: most-fired block reasons. Pulled from
// BuildReportJsonInput.blockMap (period-bounded by the aggregator),
// sorted descending, top 5. Each row is humanized label + count.
//
// The red horizontal bar that used to flank the count was retired
// 2026-05-12 — it took column width without adding signal beyond
// the number itself. The wider label column means long reason names
// ("Persistent denial") fit without aggressive truncation.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import { fitLabel, humanBlockReason, num } from '../util.js';

const ROW_LIMIT = 5;
const LABEL_W = 18;
const COUNT_W = 5;

export function TopBlocks({ audit }: { audit: AggregateResult | null }): React.ReactElement {
  const data = audit?.data;
  const sorted = data
    ? [...data.blockMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, ROW_LIMIT)
    : [];

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
            <Box width={COUNT_W} justifyContent="flex-end">
              <Text bold>{num(count)}</Text>
            </Box>
          </Box>
        ))
      )}
    </Box>
  );
}
