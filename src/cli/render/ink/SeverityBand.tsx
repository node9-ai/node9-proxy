// src/cli/render/ink/SeverityBand.tsx
//
// Section divider with centered title used to anchor the redesigned
// `node9 scan` panel scorecard. Renders as:
//
//   ━━━━━━━━━━━━ Critical (5 secrets leaked) ━━━━━━━━━━━━━
//
// The title sits centered with balanced ━ dashes on each side. One
// band per logical group (spend & activity, critical, high, medium,
// recommended action). Empty bands aren't rendered at all (decided
// in the scan-redesign plan).
//
// Width is passed in by the parent so the band matches the
// scorecard's renderWidth (terminal cap or 90 cols).

import React from 'react';
import { Box, Text } from 'ink';

interface Props {
  /** Heading text, e.g. "Critical (5 secrets leaked + 2 ops blocked)". */
  label: string;
  /** Total band width in columns — caller passes scorecard's renderWidth. */
  width: number;
}

export function SeverityBand({ label, width }: Props): React.ReactElement {
  // " label " — single-space padding on each side keeps the title
  // visually distinct from the surrounding dashes.
  const titleText = ` ${label} `;
  const remaining = Math.max(2, width - titleText.length);
  const leftDashes = '━'.repeat(Math.floor(remaining / 2));
  const rightDashes = '━'.repeat(remaining - leftDashes.length);
  return (
    <Box>
      <Text dimColor>{leftDashes}</Text>
      <Text bold>{titleText}</Text>
      <Text dimColor>{rightDashes}</Text>
    </Box>
  );
}
