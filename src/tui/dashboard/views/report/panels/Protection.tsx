// src/tui/dashboard/views/report/panels/Protection.tsx
//
// Top-row panel: 6 outcome counters from the Protection Summary in `node9
// report`. Each row is icon + label + count, with the icon dimmed when
// the count is zero (visually separates "this didn't happen this period"
// from "this happened" without needing to read the number).

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import { num } from '../util.js';

export function Protection({ audit }: { audit: AggregateResult | null }): React.ReactElement {
  const data = audit?.data;
  const rows: Array<{ icon: string; label: string; count: number; color?: string }> = data
    ? [
        { icon: '✅', label: 'Approved', count: data.userApproved, color: 'green' },
        { icon: '🚫', label: 'Denied', count: data.userDenied, color: 'red' },
        { icon: '⏱', label: 'Timed out', count: data.timedOut, color: 'yellow' },
        { icon: '🛑', label: 'Auto-blocked', count: data.hardBlocked, color: 'red' },
        { icon: '🚨', label: 'DLP blocked', count: data.dlpBlocked, color: 'yellow' },
        { icon: '👁', label: 'DLP observe', count: data.observeDlp, color: 'blue' },
      ]
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
      <Text bold>PROTECTION</Text>
      {rows.map((r) => (
        <Box key={r.label}>
          <Text dimColor={r.count === 0} color={r.count > 0 ? r.color : undefined}>
            {r.icon}
          </Text>
          <Text> </Text>
          <Text dimColor={r.count === 0}>{r.label.padEnd(13)}</Text>
          <Text dimColor={r.count === 0} bold={r.count > 0}>
            {num(r.count).padStart(5)}
          </Text>
        </Box>
      ))}
    </Box>
  );
}
