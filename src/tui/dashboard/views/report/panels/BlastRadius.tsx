// src/tui/dashboard/views/report/panels/BlastRadius.tsx
//
// Full-width row panel: sensitive files an AI agent on this machine can
// reach right now (filesystem-readable). Reuses the snapshot loaded by
// App.tsx via loadBlast() — same data already fed to the Realtime view's
// Risk panel, plus the human descriptions from blast.ts.
//
// CTA + border color depend on whether project-jail is active:
//   - exposed AND project-jail active   → dim border, "✓ blocked by project-jail"
//   - exposed AND project-jail inactive → red border, "→ enable project-jail"
//   - not exposed                       → dim border, "✓ no exposed sensitive files"
//
// "Blocked by project-jail" reflects that the shield prevents agent
// tool calls from reading these paths, even though the files are still
// readable by the user's process (which is what blast.ts walks).

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { BlastSnapshot } from '../../../types.js';

const LABEL_WIDTH = 36;
/** Max path rows rendered individually. Anything past this collapses
 *  to a single "… +N more" line so the panel stays bounded on
 *  high-exposure machines. 5 is the sweet spot for typical installs
 *  (most users have 0-5 exposed paths); higher counts overflow
 *  cleanly. */
const PATH_ROW_LIMIT = 5;

export function BlastRadius({
  blast,
  protectedByProjectJail,
}: {
  blast: BlastSnapshot | null;
  /** True when shieldStatus.active includes 'project-jail'. Drives the
   *  border color + CTA copy — see header doc comment. */
  protectedByProjectJail: boolean;
}): React.ReactElement {
  const paths = blast?.paths ?? [];
  const exposed = paths.length > 0;
  const showRedBorder = exposed && !protectedByProjectJail;

  return (
    <Box
      borderStyle="round"
      borderColor={showRedBorder ? 'red' : COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={1}
    >
      <Box>
        <Text bold>BLAST RADIUS</Text>
        {blast === null ? (
          <Text dimColor>{'  ·  loading…'}</Text>
        ) : (
          <>
            <Text dimColor>
              {`  ·  ${paths.length} path${paths.length === 1 ? '' : 's'} on disk`}
            </Text>
            {exposed ? (
              <>
                <Text>{'      '}</Text>
                {protectedByProjectJail ? (
                  <Text color="green">✓ blocked by project-jail</Text>
                ) : (
                  <Text color="yellow">→ enable project-jail</Text>
                )}
              </>
            ) : null}
          </>
        )}
      </Box>
      {blast === null ? null : exposed ? (
        <>
          {paths.slice(0, PATH_ROW_LIMIT).map((p) => (
            // One row per path. Use a single <Text wrap="truncate-end">
            // wrapping all the colored child Texts — Ink renders this as a
            // single line and truncates with ellipsis at the column edge.
            // Wrapping the description in a separate flex Box added phantom
            // empty rows in some terminals (Ink seems to inflate row height
            // when a flex child has wrap="truncate-end").
            <Text key={p.label} wrap="truncate-end">
              <Text color="red">✗ </Text>
              <Text>{p.label.padEnd(LABEL_WIDTH)}</Text>
              <Text dimColor>{p.description}</Text>
            </Text>
          ))}
          {paths.length > PATH_ROW_LIMIT ? (
            <Text dimColor>{`  … +${paths.length - PATH_ROW_LIMIT} more`}</Text>
          ) : null}
        </>
      ) : (
        <Text color="green">✓ no exposed sensitive files</Text>
      )}
    </Box>
  );
}
