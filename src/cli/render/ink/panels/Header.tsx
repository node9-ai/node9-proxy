// src/cli/render/ink/panels/Header.tsx
//
// Two-line header for the new Ink-rendered `node9 scan` panel mode.
// Line 1: "🛡  Node9 Scan  ·  39 sessions · 90d"
// Line 2: "⚠   Score 25/100 Critical"
//
// Kept minimal by design — the spike/redesign plan chose a "small
// header + prominent panels" hierarchy rather than a hero block.
// Spend / token detail lives in the COST and ACTIVITY panels below.

import React from 'react';
import { Box, Text } from 'ink';

import type { ScanResult } from '../../../commands/scan.js';
import { classifyScore } from '../../scan-derive.js';

interface Props {
  scan: ScanResult;
  blastScore: number;
  /** Display label for the time window: "90d", "today", "all time", etc.
   *  Caller-provided so the header doesn't have to re-derive it. */
  rangeLabel: string;
}

// Ink uses string color names (e.g. 'red', 'yellow', 'green') rather
// than chalk function references. Map classifyScore's band → Ink color.
function bandColor(band: 'good' | 'at-risk' | 'critical'): 'green' | 'yellow' | 'red' {
  if (band === 'good') return 'green';
  if (band === 'at-risk') return 'yellow';
  return 'red';
}

export function Header({ scan, blastScore, rangeLabel }: Props): React.ReactElement {
  const score = classifyScore(blastScore);
  const color = bandColor(score.band);
  return (
    <Box flexDirection="column">
      <Box>
        <Text bold>{'🛡  Node9 Scan'}</Text>
        <Text dimColor>{'  ·  '}</Text>
        <Text>{`${scan.sessions} sessions · ${rangeLabel}`}</Text>
      </Box>
      <Box>
        {score.band === 'critical' ? <Text color={color}>{'⚠   '}</Text> : <Text>{'    '}</Text>}
        <Text bold>Score </Text>
        <Text bold color={color}>{`${blastScore}/100`}</Text>
        <Text color={color}>{` ${score.label}`}</Text>
      </Box>
    </Box>
  );
}
