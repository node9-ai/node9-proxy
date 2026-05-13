// src/cli/render/ink/panels/AgentLoopsPanel.tsx
//
// Right side of the "Medium" band. Efficiency panel — shows where
// agent time / cost gets burned on repeated work. Counts repeats
// per tool, surfaces the top stuck file/pattern.
//
// Repeats = max(0, finding.count - 1) per loop finding. Aggregated
// by toolName for the breakdown, by file/command for the "Top
// stuck" line.

import React from 'react';
import { Box, Text } from 'ink';

import type { LoopFinding } from '../../../commands/scan.js';

interface Props {
  loopFindings: LoopFinding[];
  width: number;
}

const TOOL_ROW_LIMIT = 5;
const STUCK_ROW_LIMIT = 2;

function fmtNum(n: number): string {
  return n.toLocaleString();
}

/** Truncate a long file path to the rightmost segment + ellipsis if
 *  it doesn't fit. Avoids the "src/foo/bar/baz…" mid-path cut by
 *  prepending ellipsis instead. */
function trimRight(s: string, width: number): string {
  if (s.length <= width) return s;
  return '…' + s.slice(s.length - (width - 1));
}

export function AgentLoopsPanel({ loopFindings, width }: Props): React.ReactElement | null {
  if (loopFindings.length === 0) return null;

  // Per-tool repeat aggregation.
  const byTool = new Map<string, number>();
  let totalRepeats = 0;
  for (const f of loopFindings) {
    const repeats = Math.max(0, f.count - 1);
    byTool.set(f.toolName, (byTool.get(f.toolName) ?? 0) + repeats);
    totalRepeats += repeats;
  }
  const toolEntries = [...byTool.entries()].sort((a, b) => b[1] - a[1]).slice(0, TOOL_ROW_LIMIT);

  // Top stuck files/commands — most-repeated individual findings.
  const topStuck = [...loopFindings].sort((a, b) => b.count - a.count).slice(0, STUCK_ROW_LIMIT);

  return (
    <Box borderStyle="round" borderColor="gray" paddingX={1} flexDirection="column" width={width}>
      <Text bold>AGENT LOOPS</Text>

      {toolEntries.map(([tool, repeats]) => {
        const pct = totalRepeats > 0 ? Math.round((repeats / totalRepeats) * 100) : 0;
        return (
          <Box key={tool}>
            <Box width={10}>
              <Text bold>{tool}</Text>
            </Box>
            <Box width={14}>
              <Text>{`×${fmtNum(repeats)}`}</Text>
            </Box>
            <Text dimColor>{`${pct}%`}</Text>
          </Box>
        );
      })}

      {topStuck.length > 0 ? (
        <>
          <Box>
            <Text> </Text>
          </Box>
          <Text dimColor>Top stuck:</Text>
          {topStuck.map((f, i) => {
            const target = trimRight(f.commandPreview || f.toolName, 32);
            return (
              <Box key={`stuck-${i}`}>
                <Box width={8}>
                  <Text bold>{`×${fmtNum(f.count)}`}</Text>
                </Box>
                <Text dimColor wrap="truncate-end">
                  {target}
                </Text>
              </Box>
            );
          })}
        </>
      ) : null}

      <Box>
        <Text dimColor wrap="truncate-end">
          {'→ '}
        </Text>
        <Text bold color="cyan" wrap="truncate-end">
          live loop-detector
        </Text>
      </Box>
    </Box>
  );
}
