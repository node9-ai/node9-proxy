// src/cli/render/ink/SeverityBand.tsx
//
// Section divider used to anchor the redesigned `node9 scan` panel
// scorecard. Renders as:
//
//   ━━ Critical (5 secrets leaked + 2 ops blocked) ━━━━━━━━━━━━━━
//
// One band per logical group: spend & activity, critical, high,
// medium, recommended action. Empty bands aren't rendered at all
// (decided in the scan-redesign plan).
//
// Visual weight (━ box-drawing heavy line) is the hierarchy signal —
// works without color so it lands in narrow / mono terminals too.

import React from 'react';
import { Box, Text } from 'ink';

interface Props {
  /** Heading text, e.g. "Critical (5 secrets leaked + 2 ops blocked)". */
  label: string;
}

/** Width of the band when rendered. Matches the panel-row width below
 *  so the band visually frames the section it introduces. Hardcoded
 *  for now; commit #2 will switch to flexBasis so it adapts to
 *  process.stdout.columns. */
const BAND_WIDTH = 76;

export function SeverityBand({ label }: Props): React.ReactElement {
  const labelLen = label.length + 4; // "━━ " (2 wide via Unicode) + " " padding + label + " "
  const trailing = Math.max(3, BAND_WIDTH - labelLen);
  return (
    <Box marginTop={1}>
      <Text dimColor>{'━━ '}</Text>
      <Text bold>{label}</Text>
      <Text dimColor>{' ' + '━'.repeat(trailing)}</Text>
    </Box>
  );
}
