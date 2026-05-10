// src/tui/dashboard/views/report/panels/Leaks.tsx
//
// Bottom-row panel: credential leaks within the period, grouped by
// pattern type. Header shows total count; body shows top types.
//
// Data is scan-walker-derived (slow), so this panel respects the
// scanCache lifecycle: dim placeholder while loading, red message on
// error, empty-state when ready-but-zero, real rollup when populated.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { ScanCache } from '../../../types.js';
import type { FilteredScan } from '../derive.js';
import { num } from '../util.js';

const ROW_LIMIT = 4;

export function Leaks({
  scanCache,
  filtered,
}: {
  scanCache: ScanCache;
  filtered: FilteredScan;
}): React.ReactElement {
  const total = filtered.leaks.length;
  const ready = scanCache.status === 'ready';

  return (
    <Box
      borderStyle="round"
      borderColor={ready && total > 0 ? 'red' : COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={1}
      flexBasis={0}
    >
      <Box>
        <Text bold>LEAKS</Text>
        {ready ? <Text dimColor>{`  (${num(total)})`}</Text> : null}
      </Box>
      {scanCache.status === 'loading' ? (
        <Text dimColor>Walking history…</Text>
      ) : scanCache.status === 'error' ? (
        <Text color="red">⚠ scan failed · [r] retry</Text>
      ) : scanCache.status === 'idle' ? (
        <Text dimColor>—</Text>
      ) : total === 0 ? (
        <Text color="green">✓ no leaks this period</Text>
      ) : (
        filtered.leaksByType.slice(0, ROW_LIMIT).map((row) => (
          <Box key={row.type}>
            <Text color="red">🚨 </Text>
            <Box flexGrow={1} flexShrink={1}>
              <Text wrap="truncate-end">{row.type}</Text>
            </Box>
            <Text bold>{num(row.count).padStart(3)}</Text>
          </Box>
        ))
      )}
    </Box>
  );
}
