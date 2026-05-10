// src/tui/dashboard/views/report/panels/TopRules.tsx
//
// Bottom-row panel: most-fired rules within the period. Pulled from
// scan-derived findings (Finding.source.rule.name), sorted desc by
// count. Top 4 rows. Empty state when ready-but-zero.
//
// Fixed-width Box columns + fitLabel — rule names like
// "shield:project-jail:block-read-credentials" are long; truncating at
// LABEL_W keeps the count column aligned across rows.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { ScanCache } from '../../../types.js';
import type { FilteredScan } from '../derive.js';
import { fitLabel, num } from '../util.js';

const ROW_LIMIT = 4;
const LABEL_W = 18;
const COUNT_W = 4;

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
        <Text color="red">⚠ scan failed · [s] retry</Text>
      ) : scanCache.status === 'idle' ? (
        <Text dimColor>Press [s] to scan history</Text>
      ) : !ready || rules.length === 0 ? (
        <Text dimColor>no rules fired this period</Text>
      ) : (
        rules.map((row) => (
          <Box key={row.rule} height={1}>
            <Box width={LABEL_W}>
              <Text>{fitLabel(row.rule, LABEL_W)}</Text>
            </Box>
            <Box width={COUNT_W} justifyContent="flex-end">
              <Text bold>{num(row.count)}</Text>
            </Box>
          </Box>
        ))
      )}
    </Box>
  );
}
