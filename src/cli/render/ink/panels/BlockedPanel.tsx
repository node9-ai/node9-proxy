// src/cli/render/ink/panels/BlockedPanel.tsx
//
// Second panel under the "Critical" band. Lists rules whose verdict
// is `block` — operations node9 would have hard-stopped if installed
// with default protection + the matching shield enabled.
//
// Returns null when there are no block-verdict findings (per the
// "hide empty bands" design decision).
//
// Each row shows: ✗ icon, rule name, hit count, origin
// (`default` for built-in defaults, `needs shield:<name>` for shield-
// gated rules that the user hasn't enabled yet).

import React from 'react';
import { Box, Text } from 'ink';

import type { ScanSummary } from '../../../../scan-summary.js';
import { originForRule, topRulesByVerdict } from '../../scan-derive.js';
import { topOf } from './title-count.js';

interface Props {
  summary: ScanSummary;
  width: number;
  /** Gate testimony (policy.appliedShields, N6). Empty/omitted =
   *  pre-install machine → forecast phrasing, unchanged. */
  enabledShields?: string[];
}

/** Cap on rule rows. Overflow is signalled in the panel title
 *  (`· top N of M`, see title-count.ts) rather than a `+N more` row. */
const ROW_LIMIT = 12;

export function BlockedPanel({
  summary,
  width,
  enabledShields = [],
}: Props): React.ReactElement | null {
  const enabled = new Set(enabledShields);
  const allRules = topRulesByVerdict(summary.sections, 'block', Number.MAX_SAFE_INTEGER);
  const rules = allRules.slice(0, ROW_LIMIT);
  if (rules.length === 0) return null;

  // Footer phrasing follows the ROWS' own origin tags, so the two can
  // never disagree: any `needs shield:` row → keep the enable CTA; all
  // rows enforced (or default) with shields on → state the coverage.
  const origins = rules.map((r) => originForRule(r.name, summary.sections, enabled));
  const anyNeeds = origins.some((o) => o.startsWith('needs shield:'));
  const footer =
    enabled.size === 0
      ? '→ install node9 + enable shields above'
      : anyNeeds
        ? '→ ✓ marks rules from enabled shields · enable the rest above'
        : '→ ✓ all these rules come from enabled shields';

  return (
    <Box borderStyle="round" borderColor="red" paddingX={1} flexDirection="column" width={width}>
      <Text bold color="red">
        WOULD HAVE BLOCKED
        <Text dimColor>{topOf(rules.length, allRules.length)}</Text>
      </Text>

      {rules.map((rule, i) => (
        <Box key={i}>
          <Box width={3}>
            <Text color="red">✗</Text>
          </Box>
          <Box width={24}>
            <Text bold wrap="truncate-end">
              {rule.name}
            </Text>
          </Box>
          <Box width={6}>
            <Text bold>{`×${rule.count}`}</Text>
          </Box>
          <Text dimColor wrap="truncate-end">
            {originForRule(rule.name, summary.sections, enabled)}
          </Text>
        </Box>
      ))}

      <Box>
        <Text dimColor wrap="truncate-end">
          {footer}
        </Text>
      </Box>
    </Box>
  );
}
