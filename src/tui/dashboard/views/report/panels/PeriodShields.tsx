// src/tui/dashboard/views/report/panels/PeriodShields.tsx
//
// Middle-row right panel: per-shield activity within the selected
// period. Counterpart to the `[1]` Realtime SHIELDS panel, but
// period-bounded (T/W/M/N) instead of since-monitor-opened.
//
// Replaces the FooterStrip's one-line "✓ a · b · c   ✗ N inactive"
// shield summary. The footer's other half — HOUR OF DAY sparkline —
// stays where it is.
//
// Data path:
//   - audit.data.blockMap (per-rule-name fire count, period-bounded
//     by the aggregator) feeds the activity column.
//   - buildRuleToShieldMap() (in data.ts) maps each rule name to its
//     owning shield. checkedBy values not in the map (DLP detector,
//     loop detector, taint) are ignored — they're not user shields.
//   - shieldStatus.active / .inactive tell us which shields are on
//     vs off so we can split the panel into "✓ active + count" rows
//     and "✗ inactive + 'off'" rows.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../../panels.js';
import type { AggregateResult } from '../../../../../cli/aggregate/report-audit.js';
import type { ShieldStatus } from '../../../types.js';
import { buildRuleToShieldMap } from '../../../data.js';
import { num } from '../util.js';

const ROW_LIMIT = 6;
const LABEL_W = 18;

export function PeriodShields({
  audit,
  shieldStatus,
}: {
  audit: AggregateResult | null;
  shieldStatus: ShieldStatus | null;
}): React.ReactElement {
  const data = audit?.data;
  const ruleToShield = buildRuleToShieldMap();

  // Collapse the per-rule ruleMap into per-shield counts. ruleMap is
  // keyed by the SPECIFIC rule name (e.g.
  // `shield:project-jail:block-read-ssh`) which the orchestrator
  // now writes to the local audit log alongside the generic
  // `checkedBy` tag. blockMap (keyed by generic checkedBy) is the
  // wrong shape for shield attribution — its keys are categories
  // like `smart-rule-block` that don't map to specific shields.
  const byShield = new Map<string, number>();
  if (data) {
    for (const [rule, count] of data.ruleMap) {
      const shield = ruleToShield.get(rule);
      if (!shield) continue;
      byShield.set(shield, (byShield.get(shield) ?? 0) + count);
    }
  }

  const active = shieldStatus?.active ?? [];
  const inactive = shieldStatus?.inactive ?? [];

  // Active shields sorted desc by activity (so the noisiest ones
  // surface on top). Shields with zero hits still render — that's
  // useful "yes it's on but didn't fire" feedback.
  const activeRows = [...active]
    .map((name) => ({ name, count: byShield.get(name) ?? 0 }))
    .sort((a, b) => b.count - a.count);

  // Inactive shields: keep registry order. Could sort but no signal
  // to sort by (we don't know which inactive shield is most relevant
  // until Phase 4's "would-catch" counter ships).
  const overflow = Math.max(0, activeRows.length + inactive.length - ROW_LIMIT);
  const visibleActive = activeRows.slice(0, ROW_LIMIT);
  const remainingBudget = Math.max(0, ROW_LIMIT - visibleActive.length);
  const visibleInactive = inactive.slice(0, remainingBudget);

  return (
    <Box
      borderStyle="round"
      borderColor={COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={1}
      flexBasis={0}
    >
      <Text bold>SHIELDS</Text>
      {shieldStatus === null ? (
        <Text dimColor>loading…</Text>
      ) : active.length === 0 && inactive.length === 0 ? (
        <Text dimColor>no shields configured</Text>
      ) : (
        <>
          {visibleActive.map((row) => (
            <Box key={`a-${row.name}`} height={1}>
              <Text color={COL.live}>{'✓ '}</Text>
              <Box width={LABEL_W}>
                <Text>{fit(row.name, LABEL_W)}</Text>
              </Box>
              <Text bold={row.count > 0} color={row.count > 0 ? undefined : COL.textDim}>
                {num(row.count)}
              </Text>
            </Box>
          ))}
          {visibleInactive.map((name) => (
            <Box key={`i-${name}`} height={1}>
              <Text color={COL.panelHigh}>{'✗ '}</Text>
              <Box width={LABEL_W}>
                <Text dimColor>{fit(name, LABEL_W)}</Text>
              </Box>
              <Text color={COL.panelHigh}>off</Text>
            </Box>
          ))}
          {overflow > 0 ? <Text dimColor>{`  … ${overflow} more`}</Text> : null}
        </>
      )}
    </Box>
  );
}

function fit(s: string, w: number): string {
  if (s.length <= w) return s.padEnd(w);
  return s.slice(0, w - 1) + '…';
}
