// src/cli/render/ink/panels/Header.tsx
//
// Single-line header for the new Ink-rendered `node9 scan` scorecard.
// Mirrors the monitor [2] Report's branding so the two views feel
// like one product.
//
//   🛡  node9 dashboard  ·  scanned last 90 days
//
// Everything else that was in the old chalk hero block (score line,
// stat card, AI spend line) has moved into the panels below:
//   - Score → header score line in monitor would go here, but the
//     scan-redesign decision was to keep this header minimal and let
//     the panels carry the score weight (BLAST RADIUS already shows
//     the underlying paths; SHIELDS shows the recommendation math).
//   - Stat card 🔑5 leaks 🛑2 blocked → severity bands tell that
//     story (Critical / High / Medium).
//   - AI spend → COST panel.

import React from 'react';
import { Box, Text } from 'ink';

interface Props {
  /** Display string for the time window the scan covered:
   *  "last 90 days" / "today" / "all time" / "last 7 days". */
  rangeLabel: string;
}

export function Header({ rangeLabel }: Props): React.ReactElement {
  return (
    <Box>
      <Text bold>{'🛡  node9 dashboard'}</Text>
      <Text dimColor>{'  ·  '}</Text>
      <Text>{`scanned ${rangeLabel}`}</Text>
    </Box>
  );
}
