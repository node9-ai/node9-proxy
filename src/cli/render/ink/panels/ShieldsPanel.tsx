// src/cli/render/ink/panels/ShieldsPanel.tsx
//
// "Recommended action" band panel — the conversion moment of the
// scan output. Lists every builtin shield ranked by impact on this
// machine, with score-delta math for protective shields (project-jail
// today). Below: collapsed footer row for shields with zero hits.
//
// The closing CTA hands the user the literal `node9 shield enable`
// command for the highest-impact shield. Same content as the chalk
// SHIELDS panel in renderPanelScorecard; rebuilt in Ink with
// proper alignment + cleaner conditional borders.

import React from 'react';
import { Box, Text } from 'ink';

import type { ScanSummary } from '../../../../scan-summary.js';
import { rollupByShield } from '../../scan-derive.js';
import { PROTECTIVE_SHIELD_DISCOUNTS } from '../../../../protection.js';
import { BUILTIN_SHIELDS } from '@node9/policy-engine';

interface Props {
  summary: ScanSummary;
  width: number;
}

export function ShieldsPanel({ summary, width }: Props): React.ReactElement {
  const impacts = rollupByShield(summary.sections);

  // Option B (BUGS.md N1): no score arithmetic in the recommendation — the
  // "+N pts" was exposed × discount, a figure the reader cannot check against
  // anything on screen. The DISCOUNT still ranks protective shields first (it
  // is the sort key and encodes real protective value); it is just never
  // rendered as points.
  // Sort: protective shields first, then by hit count.
  const ranked = [...impacts].sort((a, b) => {
    const aDiscount = PROTECTIVE_SHIELD_DISCOUNTS[a.shieldName] ?? 0;
    const bDiscount = PROTECTIVE_SHIELD_DISCOUNTS[b.shieldName] ?? 0;
    if (aDiscount !== bDiscount) return bDiscount - aDiscount;
    return b.totalCatches - a.totalCatches;
  });

  const hitShields = ranked.filter((i) => i.totalCatches > 0);
  const hitNames = new Set(hitShields.map((i) => i.shieldName));
  const zeroHitBuiltins = Object.keys(BUILTIN_SHIELDS)
    .filter((name) => !hitNames.has(name))
    .sort();

  const topRec = hitShields.find((r) => (PROTECTIVE_SHIELD_DISCOUNTS[r.shieldName] ?? 0) > 0);

  return (
    <Box borderStyle="round" borderColor="cyan" paddingX={1} flexDirection="column" width={width}>
      <Text bold color="cyan">
        SHIELDS
      </Text>

      {hitShields.map((impact) => {
        const discount = PROTECTIVE_SHIELD_DISCOUNTS[impact.shieldName] ?? 0;
        const noun = `op${impact.totalCatches !== 1 ? 's' : ''}`;
        // No icon column — emoji variation-selector widths caused
        // the protective-shield row to overflow the right border on
        // some terminals. The shield name styling (bold cyan for
        // protective, dim otherwise) carries the same signal.
        return (
          <Box key={impact.shieldName}>
            <Box width={16}>
              <Text bold color={discount > 0 ? 'cyan' : undefined} dimColor={discount === 0}>
                {impact.shieldName}
              </Text>
            </Box>
            <Box width={20}>
              <Text dimColor>{`catches ${impact.totalCatches} ${noun}`}</Text>
            </Box>
            {discount > 0 ? <Text bold color="green">{`→ blocks these reads in-path`}</Text> : null}
          </Box>
        );
      })}

      {zeroHitBuiltins.length > 0 ? (
        <Box flexDirection="column">
          <Text dimColor wrap="truncate-end">
            {zeroHitBuiltins.join(' · ') + '  (no hits — install proactively)'}
          </Text>
        </Box>
      ) : null}

      {topRec ? (
        <Box>
          <Text color="cyan" bold>
            {`→ node9 shield enable ${topRec.shieldName}   (start here — widest coverage)`}
          </Text>
        </Box>
      ) : null}
    </Box>
  );
}
