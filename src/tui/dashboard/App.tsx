// src/tui/dashboard/App.tsx
//
// Spike: experimental Ink-based unified dashboard for node9.
// Renders four panels: live SSE feed, high-level summary, report
// breakdown, and DLP/LOOP/RISK summary. Time-window selector at top.
//
// Status: spike — experimental, not yet a replacement for `node9 tail`.
// Run via `node9 dashboard-spike`. Reversible: delete this directory
// and the CLI registration to fully unwind.
import React from 'react';
import { Box, Text, useApp, useInput } from 'ink';

export function App(): React.ReactElement {
  const { exit } = useApp();
  useInput((input) => {
    if (input === 'q') exit();
  });
  return (
    <Box flexDirection="column" paddingX={1}>
      <Text color="#FF8C42" bold>
        🛡 node9 dashboard
      </Text>
      <Text dimColor>spike — Ink + React proof of concept. Press [q] to quit.</Text>
    </Box>
  );
}
