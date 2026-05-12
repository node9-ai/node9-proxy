// src/cli/render/ink/StaticScorecard.tsx
//
// Entry point for the new Ink-based scan scorecard renderer.
//
// Architecture (per the scan-redesign plan):
//   - `render(<StaticScorecard input={input} />, { patchConsole: false })`
//     mounts the component tree, Ink flushes JSX to stdout via Yoga
//     flexbox layout.
//   - `unmount()` immediately tears it down — for a one-shot CLI
//     render there's no interactive state to retain. CodeBurn does
//     this same pattern in src/dashboard.tsx for its non-TTY path.
//
// Why Ink for a static CLI output (rather than chalk + manual box-
// drawing):
//   - Side-by-side panel rows are trivial via <Box flexDirection="row">
//   - Emoji / CJK / combining-mark widths handled natively by Yoga —
//     no string-width + VS-16 dance like the old renderPanelScorecard
//   - Same Ink components can later compose into the monitor [2]
//     Report view, removing the dual-rendering-system duplication
//
// Spike scope (commit #1): Header + Spend-band + CostPanel only.
// Subsequent commits add ACTIVITY, the Critical/High/Medium bands,
// and the SHIELDS recommendation. See scan-redesign plan.
//
// Gated behind NODE9_SCAN_INK=1 env flag while the redesign matures.
// Default behavior (the existing chalk-based renderPanelScorecard) is
// unchanged until commit #8 of the plan.

import React from 'react';
import { Box, render } from 'ink';

import type { CompactInput } from '../../commands/scan.js';
import { SeverityBand } from './SeverityBand.js';
import { CostPanel } from './panels/CostPanel.js';
import { ActivityPanel } from './panels/ActivityPanel.js';

interface Props {
  input: CompactInput;
}

/** The React tree itself — pure, no I/O. Exported separately so
 *  unit tests can use ink-testing-library to capture rendered
 *  output without going through the full render+unmount dance.
 *
 *  No Header component during the migration window — the chalk hero
 *  block in scan.ts already prints sessions / score / stat-card /
 *  spend BEFORE this Ink renderer runs. Adding an Ink Header now
 *  would duplicate it. When the chalk hero block is itself migrated
 *  (eventually a HeaderPanel later in the stack), we'll restore an
 *  Ink Header here and drop the chalk one. */
export function StaticScorecard({ input }: Props): React.ReactElement {
  const { summary } = input;
  return (
    <Box flexDirection="column" paddingTop={1}>
      <SeverityBand label="Spend & activity" />
      <Box flexDirection="row" gap={1}>
        <CostPanel summary={summary} />
        <ActivityPanel summary={summary} />
      </Box>

      {/* Critical / High / Medium / Recommended-action bands — added
       *  in commits #3-6. */}
    </Box>
  );
}

/**
 * One-shot mount → render → unmount pattern for static output.
 * Returns when the component tree has flushed to stdout. The
 * `patchConsole: false` option keeps Ink from intercepting other
 * console.log calls the caller might still be using.
 *
 * No `waitUntilExit()` — there's no interactive state to wait for;
 * the render is synchronous from the caller's perspective.
 */
export function renderScanScorecardInk(input: CompactInput): void {
  const { unmount } = render(<StaticScorecard input={input} />, {
    patchConsole: false,
  });
  unmount();
}
