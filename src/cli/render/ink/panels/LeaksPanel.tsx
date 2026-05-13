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

interface Props {
  summary: ScanSummary;
  width: number;
}

/** Max leak rows shown individually. Anything past this collapses to
 *  a `… +N more` line so the panel stays bounded on heavy-leak
 *  machines. 4 keeps the panel tight against BLOCKED in the side-by-
 *  side Critical band — the +N more line handles overflow. */
const ROW_LIMIT = 4;

export function LeaksPanel({ summary, width }: Props): React.ReactElement | null {
  const leaks = summary.leaks;
  if (leaks.length === 0) return null;

  const now = new Date();
  return (
    <Box borderStyle="round" borderColor="red" paddingX={1} flexDirection="column" width={width}>
      <Text bold color="red">
        CREDENTIAL LEAKS
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

      {/* No `… +N more` line — the severity-band header already
       *  reports the total count, e.g. "Critical (5 secrets leaked)".
       *  Keeping the panel one row tighter saves vertical space. */}
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
