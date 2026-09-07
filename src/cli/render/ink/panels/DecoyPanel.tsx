// src/cli/render/ink/panels/DecoyPanel.tsx
//
// Tripped decoy credentials, rendered FIRST inside the Critical band,
// above CREDENTIAL LEAKS. A decoy has no false-positive class: it is a
// value node9 planted itself, so its appearance is proof that something
// read the file. That outranks any number of pattern matches.
//
// There is no sample column and there never can be: a decoy has no safe
// excerpt, and the finding carries no value to print. The row names the
// plant path instead, which is the fact the reader needs.
//
// Hide-when-empty, like every other panel.

import React from 'react';
import { Box, Text } from 'ink';
import os from 'os';

import type { ScanSummary } from '../../../../scan-summary.js';
import { relativeDate } from '../../scan-derive.js';
import { topOf } from './title-count.js';

interface Props {
  summary: ScanSummary;
  width: number;
  now?: Date;
}

const ROW_LIMIT = 4;

/** `~`-relative so the row fits and the home path is not echoed in full. */
function shortPath(p: string): string {
  const home = os.homedir();
  return p.startsWith(home) ? '~' + p.slice(home.length) : p;
}

/** What the seam means, in the reader's terms. A tool call carried the value
 *  outward; a tool result carried it inward. Saying "sent onward" for a read
 *  would overclaim. */
export function decoySeamPhrase(toolName: string): string {
  if (toolName === 'tool-result') return 'read into the agent context';
  if (toolName === 'user-prompt') return 'pasted into a prompt';
  return `appeared in a ${toolName} call`;
}

export function DecoyPanel({ summary, width, now = new Date() }: Props): React.ReactElement | null {
  const rows = summary.canaries;
  if (rows.length === 0) return null;

  return (
    <Box borderStyle="round" borderColor="red" paddingX={1} flexDirection="column" width={width}>
      <Text bold color="red">
        DECOY TRIPPED
        <Text dimColor>{topOf(Math.min(rows.length, ROW_LIMIT), rows.length)}</Text>
      </Text>

      {rows.slice(0, ROW_LIMIT).map((c, i) => (
        <Box key={i} flexDirection="column">
          <Box>
            <Box width={5}>
              <Text dimColor>{relativeDate(c.timestamp, now).padStart(4)}</Text>
            </Box>
            <Box width={16}>
              <Text color="red" bold wrap="truncate-end">
                {c.kind}
                {c.retired ? ' (retired)' : ''}
              </Text>
            </Box>
            <Box width={15}>
              <Text dimColor wrap="truncate-end">{`[${c.toolName}]`}</Text>
            </Box>
            <Text dimColor wrap="truncate-end">
              {c.agent}
            </Text>
          </Box>
          <Text dimColor wrap="truncate-end">
            {`  ${shortPath(c.path)} — ${decoySeamPhrase(c.toolName)}`}
          </Text>
        </Box>
      ))}

      <Box>
        <Text dimColor>{'→ '}</Text>
        <Text bold color="cyan">
          node9 canary status
        </Text>
        <Text dimColor wrap="truncate-end">
          {' (something read that file)'}
        </Text>
      </Box>
    </Box>
  );
}
