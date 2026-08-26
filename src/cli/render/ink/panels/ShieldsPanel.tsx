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
  /** Gate testimony (policy.appliedShields, N6). Empty/omitted =
   *  pre-install machine → forecast phrasing, unchanged. */
  enabledShields?: string[];
}

export function ShieldsPanel({ summary, width, enabledShields = [] }: Props): React.ReactElement {
  const enabled = new Set(enabledShields);
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
  // Zero-hit builtins split by state (N6): only a shield that is NOT
  // already enforcing may be pitched as "install proactively" — the
  // founder's machine showed an ACTIVE postgres shield under that line.
  const zeroHitAll = Object.keys(BUILTIN_SHIELDS)
    .filter((name) => !hitNames.has(name))
    .sort();
  const zeroHitBuiltins = zeroHitAll.filter((name) => !enabled.has(name));
  const zeroHitEnabled = zeroHitAll.filter((name) => enabled.has(name));

  // The CTA must never hand the user a command that is already true —
  // recommend the highest-impact protective shield they have NOT enabled.
  const topRec = hitShields.find(
    (r) => (PROTECTIVE_SHIELD_DISCOUNTS[r.shieldName] ?? 0) > 0 && !enabled.has(r.shieldName)
  );
  // All protective hit shields already on → say so instead of silence.
  const allCovered =
    !topRec &&
    hitShields.some(
      (r) => (PROTECTIVE_SHIELD_DISCOUNTS[r.shieldName] ?? 0) > 0 && enabled.has(r.shieldName)
    );

  return (
    <Box borderStyle="round" borderColor="cyan" paddingX={1} flexDirection="column" width={width}>
      <Text bold color="cyan">
        SHIELDS
      </Text>

      {hitShields.map((impact) => {
        const discount = PROTECTIVE_SHIELD_DISCOUNTS[impact.shieldName] ?? 0;
        const isOn = enabled.has(impact.shieldName);
        const noun = `op${impact.totalCatches !== 1 ? 's' : ''}`;
        // No icon column — emoji variation-selector widths caused
        // the protective-shield row to overflow the right border on
        // some terminals. The shield name styling (bold cyan for
        // protective, dim otherwise) carries the same signal.
        //
        // Tense honesty (N6): an enabled shield gets `✓ enabled` — a
        // statement about NOW. Never "blocked these" — whether PAST
        // events were blocked is report's claim to make, not scan's.
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
            {isOn ? (
              <Text bold color="green">{`✓ enabled — enforcing in-path`}</Text>
            ) : discount > 0 ? (
              <Text bold color="green">{`→ blocks these reads in-path`}</Text>
            ) : null}
          </Box>
        );
      })}

      {zeroHitEnabled.length > 0 ? (
        <Box flexDirection="column">
          <Text dimColor wrap="truncate-end">
            {'✓ active: ' + zeroHitEnabled.join(' · ') + '  (no hits in this history)'}
          </Text>
        </Box>
      ) : null}

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
      ) : allCovered ? (
        <Box>
          <Text color="green" bold>
            {'✓ recommended shields are enabled'}
          </Text>
        </Box>
      ) : null}
    </Box>
  );
}
