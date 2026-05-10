// src/tui/dashboard/views/report/panels/TopRules.tsx
//
// Bottom-row panel: most-fired rules within the period. Pulled from
// scan-derived findings (Finding.source.rule.name), sorted desc by
// count. Top 4 rows. Empty state when ready-but-zero.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { ScanCache } from '../../../types.js';
import type { FilteredScan } from '../derive.js';
import { num } from '../util.js';

const ROW_LIMIT = 4;

export function TopRules({
  scanCache,
  filtered,
}: {
  scanCache: ScanCache;
  filtered: FilteredScan;
}): React.ReactElement {
  const ready = scanCache.status === 'ready';
  const rules = filtered.topRules.slice(0, ROW_LIMIT);

  return (
    <Box
      borderStyle="round"
      borderColor={COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={1}
      flexBasis={0}
    >
      <Text bold>TOP RULES FIRED</Text>
      {scanCache.status === 'loading' ? (
        <Text dimColor>Walking history…</Text>
      ) : scanCache.status === 'error' ? (
        <Text color="red">⚠ scan failed · [r] retry</Text>
      ) : scanCache.status === 'idle' ? (
        <Text dimColor>—</Text>
      ) : !ready || rules.length === 0 ? (
        <Text dimColor>no rules fired this period</Text>
      ) : (
        rules.map((row) => (
          // Rule name in a flex-shrinking Box with truncate-end so long
          // names (e.g. "shield:project-jail:block-read-credentials")
          // don't push the count off the column or wrap to a new line.
          // Count is fixed-width on the right.
          <Box key={row.rule}>
            <Box flexGrow={1} flexShrink={1}>
              <Text wrap="truncate-end">{row.rule}</Text>
            </Box>
            <Text bold>{num(row.count).padStart(4)}</Text>
          </Box>
        ))
      )}
    </Box>
  );
}
