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
import { topRulesByVerdict } from '../../scan-derive.js';

interface Props {
  summary: ScanSummary;
  width: number;
}

/** Find which origin tag (e.g. `default` or `needs shield:project-jail`)
 *  applies to a given rule name. Walks summary sections to find which
 *  one owns the rule. Mirrors the helper that lives inline inside
 *  the chalk renderPanelScorecard — kept duplicated for now to avoid
 *  touching scan.ts; can extract to scan-derive when commit #8
 *  consolidates the helpers. */
function originForRule(ruleName: string, sections: ScanSummary['sections']): string {
  for (const section of sections) {
    if (section.rules.some((r) => r.name === ruleName)) {
      if (section.sourceType === 'default') return 'default';
      if (section.sourceType === 'shield') {
        return `needs shield:${section.shieldKey ?? section.id}`;
      }
    }
  }
  return '';
}

/** Cap on rule rows. Above this, append a `… +N more` line. */
const ROW_LIMIT = 12;

export function BlockedPanel({ summary, width }: Props): React.ReactElement | null {
  const rules = topRulesByVerdict(summary.sections, 'block', ROW_LIMIT);
  if (rules.length === 0) return null;

  return (
    <Box borderStyle="round" borderColor="red" paddingX={1} flexDirection="column" width={width}>
      <Text bold color="red">
        WOULD HAVE BLOCKED
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
            {originForRule(rule.name, summary.sections)}
          </Text>
        </Box>
      ))}

      <Box marginTop={1}>
        <Text dimColor wrap="truncate-end">
          {'→ install node9 + enable shields above'}
        </Text>
      </Box>
    </Box>
  );
}
