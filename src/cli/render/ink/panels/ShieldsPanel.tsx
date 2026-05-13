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
  blastScore: number;
  width: number;
}

export function ShieldsPanel({ summary, blastScore, width }: Props): React.ReactElement {
  const impacts = rollupByShield(summary.sections);
  const exposed = Math.max(0, 100 - blastScore);

  // Sort: protective shields with score impact first, then by hit count.
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
  const topRecBonus = topRec
    ? Math.round(exposed * (PROTECTIVE_SHIELD_DISCOUNTS[topRec.shieldName] ?? 0))
    : 0;

  return (
    <Box borderStyle="round" borderColor="cyan" paddingX={1} flexDirection="column" width={width}>
      <Text bold color="cyan">
        SHIELDS
      </Text>

      {hitShields.map((impact) => {
        const discount = PROTECTIVE_SHIELD_DISCOUNTS[impact.shieldName] ?? 0;
        const bonus = Math.round(exposed * discount);
        const icon = discount > 0 ? '🛡️ ' : '☐  ';
        const noun = `op${impact.totalCatches !== 1 ? 's' : ''}`;
        return (
          <Box key={impact.shieldName}>
            <Box width={4}>
              <Text color={discount > 0 ? 'cyan' : 'gray'}>{icon}</Text>
            </Box>
            <Box width={14}>
              <Text bold>{impact.shieldName}</Text>
            </Box>
            <Box width={20}>
              <Text dimColor>{`catches ${impact.totalCatches} ${noun}`}</Text>
            </Box>
            {bonus > 0 ? (
              <Text
                bold
                color="green"
              >{`→ +${bonus} pts (${blastScore} → ${blastScore + bonus})`}</Text>
            ) : null}
          </Box>
        );
      })}

      {zeroHitBuiltins.length > 0 ? (
        <Box flexDirection="column" marginTop={hitShields.length > 0 ? 1 : 0}>
          <Text dimColor wrap="truncate-end">
            {zeroHitBuiltins.join(' · ')}
          </Text>
          <Text dimColor>{'  no hits in your history — install proactively'}</Text>
        </Box>
      ) : null}

      {topRec ? (
        <Box marginTop={1}>
          <Text color="cyan" bold>
            {`→ node9 shield enable ${topRec.shieldName}   (start here — +${topRecBonus} pts)`}
          </Text>
        </Box>
      ) : null}
    </Box>
  );
}
