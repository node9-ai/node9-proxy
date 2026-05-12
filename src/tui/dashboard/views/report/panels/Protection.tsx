// src/tui/dashboard/views/report/panels/Protection.tsx
//
// Top-row panel: 6 outcome counters from the Protection Summary in `node9
// report`. Each row is icon + label + count, with the icon dimmed when
// the count is zero (visually separates "this didn't happen this period"
// from "this happened" without needing to read the number).
//
// Layout uses fixed-width Box columns rather than padEnd-then-string-
// concat — emoji icons render at 1 OR 2 visual cells depending on the
// terminal/font (✅ is usually 2, ⏱ is often 1, etc). JS string padding
// counts UTF-16 code units, not visual cells, so the count column drifts
// when the icon glyph width varies row-to-row. Wrapping each column in
// `<Box width={N}>` makes Ink do the cell-width math correctly.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import { num } from '../util.js';

const ICON_W = 2; // most icons are 2 cells; the few 1-cell ones get padded
const LABEL_W = 14;
const COUNT_W = 5;

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

  const isEmpty = data && data.total === 0;

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
      {audit === null ? (
        <Text dimColor>loading…</Text>
      ) : isEmpty ? (
        <Text dimColor>no activity this period</Text>
      ) : (
        rows.map((r) => (
          <Box key={r.label} height={1}>
            <Box width={ICON_W}>
              <Text dimColor={r.count === 0} color={r.count > 0 ? r.color : undefined}>
                {r.icon}
              </Text>
            </Box>
            <Box width={LABEL_W}>
              <Text dimColor={r.count === 0}>{r.label}</Text>
            </Box>
            <Box width={COUNT_W} justifyContent="flex-end">
              <Text dimColor={r.count === 0} bold={r.count > 0}>
                {num(r.count)}
              </Text>
            </Box>
          </Box>
        ))
      )}
    </Box>
  );
}
