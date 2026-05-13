// src/cli/render/ink/panels/BlastRadiusPanel.tsx
//
// Panel under the "High" band. Lists sensitive files an AI agent on
// this machine can read right now (filesystem-readable by the user's
// process). The score in the header is derived from these paths
// (Σ deductions = 100 - blast.score).
//
// Description is split on em-dash and only the noun phrase kept —
// blast.ts packs "RSA private key — grants SSH access to your
// servers" but the second clause overflows the column. Same fix the
// chalk renderPanelScorecard ships (commit 34320f6).

import React from 'react';
import { Box, Text } from 'ink';

import type { CompactInput } from '../../../commands/scan.js';

// CompactInput.blast carries the BlastResult shape (envFindings is an
// array, not a count). Don't use BlastSnapshot — that's a separate
// dashboard-side type where envFindings is a number.
type BlastInput = CompactInput['blast'];

interface Props {
  blast: BlastInput;
  blastExposures: number;
}

/** Max path rows shown individually. Above this, append a `… +N more`
 *  line. 8 covers the heaviest dev machine we've seen (~5 paths). */
const ROW_LIMIT = 8;

export function BlastRadiusPanel({ blast, blastExposures }: Props): React.ReactElement | null {
  if (blastExposures === 0) return null;

  return (
    <Box borderStyle="round" borderColor="yellow" paddingX={1} flexDirection="column">
      <Text bold color="yellow">
        BLAST RADIUS
      </Text>

      {blast.reachable.slice(0, ROW_LIMIT).map((path, i) => {
        const desc = path.description.split(' — ')[0].split(/—|--/)[0].trim();
        return (
          <Box key={i}>
            <Box width={3}>
              <Text color="red">✗</Text>
            </Box>
            <Box width={36}>
              <Text>{path.label}</Text>
            </Box>
            <Text dimColor>{desc}</Text>
          </Box>
        );
      })}

      {blast.envFindings.slice(0, 3).map((env, i) => (
        <Box key={`env-${i}`}>
          <Box width={3}>
            <Text color="yellow">⚠</Text>
          </Box>
          <Text>{env.key}</Text>
          <Text dimColor>{` (${env.patternName})`}</Text>
        </Box>
      ))}

      {blastExposures > ROW_LIMIT ? (
        <Text dimColor>{`… +${blastExposures - ROW_LIMIT} more`}</Text>
      ) : null}

      <Box marginTop={1}>
        <Text dimColor>{'→ '}</Text>
        <Text bold color="cyan">
          project-jail
        </Text>
        <Text dimColor>{' shield blocks agent reads of these paths'}</Text>
      </Box>
    </Box>
  );
}
