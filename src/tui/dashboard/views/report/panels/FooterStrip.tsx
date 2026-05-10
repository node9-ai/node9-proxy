// src/tui/dashboard/views/report/panels/FooterStrip.tsx
//
// Two-line footer strip at the bottom of the Report [2] view:
//
//   SHIELDS   ✓ project-jail · bash-safe · filesystem      ✗ 6 inactive
//   HOUR OF DAY (local)   ▁    ▇▃█▇▂▄▂▅▄▁▂▂▃ ▄              0h ─ 12h ─ 23h
//
// Compact summaries — the realtime view already has a richer Risk
// panel for shields, and `node9 scan` shows the per-hour distribution
// in detail. This footer is for at-a-glance pattern recognition.

import React from 'react';
import { Box, Text } from 'ink';

import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import type { ShieldStatus } from '../../../types.js';
import { sparkline } from '../util.js';

const ACTIVE_LIMIT = 4; // cap names shown to keep line under terminal width
const SPARK_WIDTH = 24; // one cell per hour

export function FooterStrip({
  shieldStatus,
  audit,
}: {
  shieldStatus: ShieldStatus | null;
  audit: AggregateResult | null;
}): React.ReactElement {
  const active = shieldStatus?.active ?? [];
  const inactive = shieldStatus?.inactive ?? [];
  const visible = active.slice(0, ACTIVE_LIMIT);
  const overflow = active.length - visible.length;
  const activeLine =
    visible.length > 0 ? visible.join(' · ') + (overflow > 0 ? ` +${overflow}` : '') : '(none)';

  // 24-cell sparkline: one block per hour, 0–23 local time. Falls back to
  // an empty 24-space placeholder until audit data lands.
  const hourValues = audit
    ? Array.from({ length: SPARK_WIDTH }, (_, h) => audit.data.hourMap.get(h) ?? 0)
    : new Array(SPARK_WIDTH).fill(0);
  const spark = sparkline(hourValues);

  return (
    <Box flexDirection="column" paddingX={1} paddingTop={1}>
      <Box>
        <Text bold>SHIELDS</Text>
        <Text>{'   '}</Text>
        <Text color="green">✓ </Text>
        <Box flexGrow={1} flexShrink={1}>
          <Text wrap="truncate-end">{activeLine}</Text>
        </Box>
        <Text>{'    '}</Text>
        <Text color={inactive.length > 0 ? 'red' : 'green'}>✗ </Text>
        <Text dimColor>{`${inactive.length} inactive`}</Text>
      </Box>
      <Box>
        <Text bold>HOUR OF DAY</Text>
        <Text dimColor>{' (local)   '}</Text>
        <Text color="cyan">{spark}</Text>
        <Text>{'   '}</Text>
        <Text dimColor>{'0h ─── 12h ─── 23h'}</Text>
      </Box>
    </Box>
  );
}
