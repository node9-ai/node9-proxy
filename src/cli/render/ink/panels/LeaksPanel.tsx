// src/cli/render/ink/panels/LeaksPanel.tsx
//
// First panel under the "Critical" band. Lists the top-N credential
// leaks found in agent history with relative-date framing.
//
// Returns null entirely when there are no leaks — the design decision
// is to hide empty bands rather than show "0 leaks" placeholders.
//
// Data: ScanSummary.leaks (LeakRef[]) — already sorted desc by
// timestamp by the summary builder; we slice to top-N for display.

import React from 'react';
import { Box, Text } from 'ink';

import type { ScanSummary } from '../../../../scan-summary.js';
import { relativeDate } from '../../scan-derive.js';
import { topOf } from './title-count.js';

interface Props {
  summary: ScanSummary;
  width: number;
  /** Reference time for relativeDate(). Defaults to wall clock — tests
   *  inject a fixed value so snapshots don't drift as days pass since
   *  the fixture was authored. */
  now?: Date;
}

/** Max leak rows shown individually. 4 keeps the panel tight against
 *  BLOCKED in the side-by-side Critical band. Overflow is signalled in
 *  the panel TITLE (`· top 4 of N`, see title-count.ts) — a `+N more`
 *  row was tried and removed to save vertical space. */
const ROW_LIMIT = 4;

export function LeaksPanel({ summary, width, now = new Date() }: Props): React.ReactElement | null {
  const leaks = summary.leaks;
  if (leaks.length === 0) return null;

  return (
    <Box borderStyle="round" borderColor="red" paddingX={1} flexDirection="column" width={width}>
      <Text bold color="red">
        CREDENTIAL LEAKS
        <Text dimColor>{topOf(Math.min(leaks.length, ROW_LIMIT), leaks.length)}</Text>
      </Text>

      {leaks.slice(0, ROW_LIMIT).map((leak, i) => (
        <Box key={i}>
          <Box width={5}>
            <Text dimColor>{relativeDate(leak.timestamp, now).padStart(4)}</Text>
          </Box>
          <Box width={16}>
            <Text color="red" bold wrap="truncate-end">
              {leak.patternName}
            </Text>
          </Box>
          <Box width={15}>
            <Text dimColor wrap="truncate-end">{`[${leak.toolName}]`}</Text>
          </Box>
          <Text dimColor wrap="truncate-end">
            {leak.agent}
          </Text>
        </Box>
      ))}

      {/* No `… +N more` row — the subset signal lives in the panel
       *  title (`· top 4 of N`) so the panel stays one row tighter.
       *  The severity band above carries the total as well. */}
      <Box>
        <Text dimColor>{'→ '}</Text>
        <Text bold color="cyan">
          DLP
        </Text>
        <Text dimColor>{' · '}</Text>
        <Text bold color="cyan">
          node9 mask
        </Text>
        <Text dimColor wrap="truncate-end">
          {' (runtime + cleanup)'}
        </Text>
      </Box>
    </Box>
  );
}
