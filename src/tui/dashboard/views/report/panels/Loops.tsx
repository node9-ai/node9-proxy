// src/tui/dashboard/views/report/panels/Loops.tsx
//
// Bottom-row panel: agent edit/Bash loops within the period. Header
// is "LOOPS (N · X% wasted)" where X = loop occurrences / total tool
// calls (matches what the CLI scan command shows). Body lists top
// tools by repeat count + the single most-stuck file.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { ScanCache } from '../../../types.js';
import type { FilteredScan } from '../derive.js';
import { fitLabel, num } from '../util.js';

const TOOL_ROWS = 2;

export function Loops({
  scanCache,
  filtered,
}: {
  scanCache: ScanCache;
  filtered: FilteredScan;
}): React.ReactElement {
  const totalLoops = filtered.loops.length;
  const totalOccurrences = filtered.loopsByTool.reduce((s, t) => s + t.count, 0);
  const wastedPct =
    filtered.totalToolCalls > 0
      ? Math.round((totalOccurrences / filtered.totalToolCalls) * 100)
      : 0;
  const ready = scanCache.status === 'ready';
  const hasLoops = totalLoops > 0;

  return (
    <Box
      borderStyle="round"
      borderColor={ready && hasLoops ? 'yellow' : COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={1}
      flexBasis={0}
    >
      <Box>
        <Text bold>LOOPS</Text>
        {ready ? (
          <Text dimColor>
            {`  (${num(totalLoops)}${wastedPct > 0 ? ` · ${wastedPct}% wasted` : ''})`}
          </Text>
        ) : null}
      </Box>
      {scanCache.status === 'loading' ? (
        <Text dimColor>Walking history…</Text>
      ) : scanCache.status === 'error' ? (
        <Text color="red">⚠ scan failed · [r] retry</Text>
      ) : scanCache.status === 'idle' ? (
        <Text dimColor>—</Text>
      ) : !hasLoops ? (
        <Text color="green">✓ no loops this period</Text>
      ) : (
        <>
          {filtered.loopsByTool.slice(0, TOOL_ROWS).map((row) => (
            <Box key={row.tool}>
              <Text>{fitLabel(row.tool, 6)}</Text>
              <Text dimColor>×</Text>
              <Text bold>{num(row.count).padStart(5)}</Text>
              <Text dimColor>{`  (${row.pct}%)`}</Text>
            </Box>
          ))}
          {filtered.topLoopFile ? (
            <Box>
              <Text dimColor>Top: </Text>
              <Box flexGrow={1} flexShrink={1}>
                <Text wrap="truncate-end">{basenameOf(filtered.topLoopFile.path)}</Text>
              </Box>
              <Text dimColor>×</Text>
              <Text bold>{num(filtered.topLoopFile.count)}</Text>
            </Box>
          ) : null}
        </>
      )}
    </Box>
  );
}

/** Last path segment, or the whole string if it has no separators. */
function basenameOf(p: string): string {
  const m = p.match(/[^/\\]+$/);
  return m ? m[0] : p;
}
