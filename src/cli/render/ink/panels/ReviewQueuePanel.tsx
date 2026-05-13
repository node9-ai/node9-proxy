// src/cli/render/ink/panels/ReviewQueuePanel.tsx
//
// Left side of the "Medium" band. Lists review-verdict rules — ops
// node9 would flag for approval rather than hard-block. Same data
// shape as BlockedPanel, different verdict filter.
//
// User-config + cloud rules are pre-stripped at the scan pipeline
// layer (commit d67d5b8) — only `default` and `needs shield:<name>`
// origins ever appear here.

import React from 'react';
import { Box, Text } from 'ink';

import type { ScanSummary } from '../../../../scan-summary.js';
import { topRulesByVerdict } from '../../scan-derive.js';

interface Props {
  summary: ScanSummary;
}

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

const ROW_LIMIT = 8;

export function ReviewQueuePanel({ summary }: Props): React.ReactElement | null {
  const rules = topRulesByVerdict(summary.sections, 'review', ROW_LIMIT);
  if (rules.length === 0) return null;

  return (
    <Box borderStyle="round" borderColor="gray" paddingX={1} flexDirection="column" width={42}>
      <Text bold>REVIEW QUEUE</Text>
      {rules.map((rule, i) => (
        <Box key={i}>
          <Box width={22}>
            <Text wrap="truncate-end">{rule.name}</Text>
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
          {'→ '}
        </Text>
        <Text bold color="cyan" wrap="truncate-end">
          runtime approval
        </Text>
      </Box>
    </Box>
  );
}
