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

import type { ScanCache } from '../../../types.js';
import type { FilteredScan } from '../derive.js';
import { Spinner } from './Spinner.js';
import { fitLabel, num } from '../util.js';

const ROW_LIMIT = 4;
const ICON_W = 2;
const LABEL_W = 14;
const COUNT_W = 4;

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
    <Box paddingX={1} flexDirection="column" flexGrow={1} flexBasis={0}>
      <Box>
        <Text bold>LEAKS</Text>
        {ready ? <Text dimColor>{`  (${num(total)})`}</Text> : null}
      </Box>
      {scanCache.status === 'loading' ? (
        <Text dimColor>
          <Spinner /> Walking history…
        </Text>
      ) : scanCache.status === 'error' ? (
        <Text color="red">⚠ scan failed · [r] retry</Text>
      ) : scanCache.status === 'idle' ? (
        <Text dimColor>—</Text>
      ) : total === 0 ? (
        <Text color="green">✓ no leaks this period</Text>
      ) : (
        filtered.leaksByType.slice(0, ROW_LIMIT).map((row) => (
          <Box key={row.type} height={1}>
            <Box width={ICON_W}>
              <Text color="red">🚨</Text>
            </Box>
            <Box width={LABEL_W}>
              <Text>{fitLabel(row.type, LABEL_W)}</Text>
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
