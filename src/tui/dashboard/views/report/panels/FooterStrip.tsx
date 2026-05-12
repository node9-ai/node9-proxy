// src/tui/dashboard/views/report/panels/FooterStrip.tsx
//
// One-line footer at the bottom of the Report [2] view:
//
//   HOUR OF DAY (local)   ▁    ▇▃█▇▂▄▂▅▄▁▂▂▃ ▄              0h ─ 12h ─ 23h
//
// Was a two-line strip with a SHIELDS one-liner on top; that shields
// line moved into a proper PeriodShields panel in the middle row
// during the Phase 2 [2] revamp. Only HOUR OF DAY remains here.

import React from 'react';
import { Box, Text } from 'ink';

import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import { sparkline } from '../util.js';

const SPARK_WIDTH = 24; // one cell per hour

export function FooterStrip({ audit }: { audit: AggregateResult | null }): React.ReactElement {
  // 24-cell sparkline: one block per hour, 0–23 local time. Falls back to
  // an empty 24-space placeholder until audit data lands.
  const hourValues = audit
    ? Array.from({ length: SPARK_WIDTH }, (_, h) => audit.data.hourMap.get(h) ?? 0)
    : new Array(SPARK_WIDTH).fill(0);
  const spark = sparkline(hourValues);

  return (
    <Box paddingX={1} paddingTop={1}>
      <Text bold>HOUR OF DAY</Text>
      <Text dimColor>{' (local)   '}</Text>
      <Text color="cyan">{spark}</Text>
      <Text>{'   '}</Text>
      <Text dimColor>{'0h ─── 12h ─── 23h'}</Text>
    </Box>
  );
}
