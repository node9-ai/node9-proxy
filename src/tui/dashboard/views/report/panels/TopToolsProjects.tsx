// src/tui/dashboard/views/report/panels/TopToolsProjects.tsx
//
// Middle-row panel: two stacked sections inside one bordered box —
// TOOLS (top tools by call count) and PROJECTS (top projects by
// cost). Designed to fit a 50%-width column in the new middle row
// alongside SHIELDS.
//
// TOOLS data:
//   - audit.data.toolMap → calls only (per the data-honesty decision
//     made on 2026-05-12: per-tool tokens aren't separable from
//     message-level token counts, so we skip tokens/cost columns
//     here rather than fake the math).
//
// PROJECTS data:
//   - audit.data.cost.byProject → cost + total tokens per cwd.
//     Tokens shown as `inputTokens + outputTokens` (excludes cache
//     read/write which aren't directly user-attributed).
//   - Decoded cwd path is shortened to its basename for display so
//     long absolute paths don't overflow the narrow column.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import { formatCost, formatTokens } from '../../../format.js';
import { num } from '../util.js';

const ROW_LIMIT = 4;
const TOOL_LABEL_W = 10;
const TOOL_COUNT_W = 6;
const PROJECT_LABEL_W = 14;

export function TopToolsProjects({ audit }: { audit: AggregateResult | null }): React.ReactElement {
  const data = audit?.data;

  const tools = data
    ? [...data.toolMap.entries()].sort(([, a], [, b]) => b.calls - a.calls).slice(0, ROW_LIMIT)
    : [];

  const projects = data
    ? [...data.cost.byProject.entries()]
        .map(([path, r]) => ({
          name: basenameOf(path),
          cost: r.cost,
          tokens: r.inputTokens + r.outputTokens,
        }))
        .sort((a, b) => b.cost - a.cost)
        .slice(0, ROW_LIMIT)
    : [];

  // 2-column internal layout: tools[i] on the left of row i, projects[i]
  // on the right. The shorter array's missing rows render empty so column
  // widths stay stable. Halves the panel height vs the prior stacked
  // sections layout.
  const rows = Array.from({ length: ROW_LIMIT }, (_, i) => ({
    tool: tools[i],
    project: projects[i],
  }));

  return (
    <Box
      borderStyle="round"
      borderColor={COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={2}
      flexBasis={0}
    >
      <Text bold>TOP TOOLS / PROJECTS</Text>
      {audit === null ? (
        <Text dimColor>loading…</Text>
      ) : tools.length === 0 && projects.length === 0 ? (
        <Text dimColor>—</Text>
      ) : (
        <>
          {/* Inline header row aligning to the two column-groups below. */}
          <Box>
            <Box width={TOOL_LABEL_W + TOOL_COUNT_W}>
              <Text dimColor>TOOLS</Text>
            </Box>
            <Text dimColor>PROJECTS</Text>
          </Box>
          {rows.map((r, i) => (
            <Box key={i} height={1}>
              <Box width={TOOL_LABEL_W + TOOL_COUNT_W}>
                {r.tool ? (
                  <>
                    <Box width={TOOL_LABEL_W}>
                      <Text>{fit(r.tool[0], TOOL_LABEL_W)}</Text>
                    </Box>
                    <Box width={TOOL_COUNT_W} justifyContent="flex-end">
                      <Text bold>{num(r.tool[1].calls)}</Text>
                    </Box>
                  </>
                ) : null}
              </Box>
              {r.project ? (
                <>
                  <Box width={PROJECT_LABEL_W}>
                    <Text>{fit(r.project.name, PROJECT_LABEL_W)}</Text>
                  </Box>
                  <Text dimColor>{`${formatTokens(r.project.tokens)} `}</Text>
                  <Text bold>{formatCost(r.project.cost)}</Text>
                </>
              ) : null}
            </Box>
          ))}
        </>
      )}
    </Box>
  );
}

/** Last path segment, or the whole string if it has no separators.
 *  Used to compact long absolute cwd paths (e.g. /home/u/long/proj →
 *  "proj") for the narrow PROJECTS column. */
function basenameOf(p: string): string {
  const m = p.match(/[^/\\]+$/);
  return m ? m[0] : p;
}

function fit(s: string, w: number): string {
  if (s.length <= w) return s.padEnd(w);
  return s.slice(0, w - 1) + '…';
}
