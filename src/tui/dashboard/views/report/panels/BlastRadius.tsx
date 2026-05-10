// src/tui/dashboard/views/report/panels/BlastRadius.tsx
//
// Full-width row panel: sensitive files an AI agent on this machine can
// reach right now. Reuses the snapshot loaded by App.tsx via loadBlast()
// — same data already fed to the Realtime view's Risk panel, just
// rendered with descriptions and a CTA.
//
// Border turns red when paths > 0 (anything reachable means the
// project-jail shield isn't fully covering the user's home dir, which
// is worth visual emphasis on a security report).

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { BlastSnapshot } from '../../../types.js';

const LABEL_WIDTH = 36;

export function BlastRadius({ blast }: { blast: BlastSnapshot | null }): React.ReactElement {
  const paths = blast?.paths ?? [];
  const exposed = paths.length > 0;

  return (
    <Box
      borderStyle="round"
      borderColor={exposed ? 'red' : COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={1}
    >
      <Box>
        <Text bold>BLAST RADIUS</Text>
        <Text dimColor>
          {`  ·  ${paths.length} path${paths.length === 1 ? '' : 's'} an agent can reach right now`}
        </Text>
        {exposed ? (
          <>
            <Text>{'      '}</Text>
            <Text color="yellow">→ enable project-jail</Text>
          </>
        ) : null}
      </Box>
      {exposed ? (
        paths.map((p) => (
          <Box key={p.label}>
            <Text color="red">✗ </Text>
            <Text>{p.label.padEnd(LABEL_WIDTH)}</Text>
            <Text dimColor>{p.description}</Text>
          </Box>
        ))
      ) : (
        <Text color="green">✓ no exposed sensitive files</Text>
      )}
    </Box>
  );
}
