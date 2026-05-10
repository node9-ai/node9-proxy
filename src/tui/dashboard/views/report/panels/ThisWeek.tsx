// src/tui/dashboard/views/report/panels/ThisWeek.tsx
//
// Top-row panel: daily activity bars for the last 5 days in the period
// (or up to the period length, whichever is shorter). Each row is
// short-date + bar of calls vs day-max + cost-for-that-day.
//
// dailyMap is keyed YYYY-MM-DD; cost.byDay is the same key shape
// (already merged Codex into Claude in the aggregator). We sort by date
// ascending and take the trailing N rows so newest is at the bottom.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import { fmtCost, fmtShortDate, num, renderBar } from '../util.js';

const ROW_LIMIT = 5;
const BAR_WIDTH = 6;

export function ThisWeek({ audit }: { audit: AggregateResult | null }): React.ReactElement {
  const data = audit?.data;
  const days = data
    ? [...data.dailyMap.entries()].sort((a, b) => a[0].localeCompare(b[0])).slice(-ROW_LIMIT)
    : [];
  const maxCalls = days.length > 0 ? Math.max(...days.map(([, v]) => v.calls), 1) : 1;
  const costByDay = data?.cost.byDay ?? new Map<string, number>();

  return (
    <Box
      borderStyle="round"
      borderColor={COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={1}
      flexBasis={0}
    >
      <Text bold>THIS WEEK</Text>
      {audit === null ? (
        <Text dimColor>loading…</Text>
      ) : days.length === 0 ? (
        <Text dimColor>no activity this period</Text>
      ) : (
        days.map(([dateKey, { calls, blocked }]) => {
          const cost = costByDay.get(dateKey) ?? 0;
          // Date is fixed-width left; bar fixed-width middle; calls
          // count flex-grows so the cost label is the first thing to
          // truncate on a narrow column. This prevents the count from
          // being clipped (which loses the more important number).
          return (
            <Box key={dateKey}>
              <Text dimColor>{fmtShortDate(dateKey).padEnd(7)}</Text>
              <Text color={blocked > 0 ? 'red' : 'cyan'}>
                {renderBar(calls, maxCalls, BAR_WIDTH)}
              </Text>
              <Text> </Text>
              <Text bold>{num(calls)}</Text>
              {cost > 0 ? (
                <Box flexGrow={1} flexShrink={1} justifyContent="flex-end">
                  <Text color="yellow" wrap="truncate-end">
                    {' ' + fmtCost(cost)}
                  </Text>
                </Box>
              ) : null}
            </Box>
          );
        })
      )}
    </Box>
  );
}
