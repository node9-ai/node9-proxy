// src/tui/dashboard/views/report/index.tsx
//
// Report [2] view shell — phase 3c. Replaces the 4-stub placeholder
// (panels.tsx:822-860) with a proper layout: header + period picker +
// score banner + placeholder rows for the panels that land in 3d–3g.
//
// Data flow: App.tsx loads the audit aggregate via loadReportAudit()
// in a useEffect tied to (view, reportPeriod) and passes the result
// in here. The scan-walk cache (for LEAKS / LOOPS / TOP RULES later)
// is plumbed but not consumed yet at this phase.
//
// Hotkey reservation lives in App.tsx — this component just renders
// what the parent gives it.

import React from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../panels.js';
import type { ReportPeriod, ScanCache } from '../../types.js';
import type { AggregateResult } from '../../../../cli/aggregate/report-audit.js';

export interface ReportViewProps {
  period: ReportPeriod;
  /** Result of loadReportAudit(period) — null while initial load runs. */
  audit: AggregateResult | null;
  /** Background scan cache. Phase 3f reads results.{claude,gemini,codex}. */
  scanCache: ScanCache;
}

const PERIOD_LONG_LABEL: Record<ReportPeriod, string> = {
  today: 'Today',
  '7d': 'Last 7 Days',
  '30d': 'Last 30 Days',
  month: 'This Month',
};

export function ReportView({ period, audit }: ReportViewProps): React.ReactElement {
  return (
    <Box flexDirection="column" flexGrow={1} paddingX={1}>
      <ReportHeader period={period} audit={audit} />
      <ScoreBanner audit={audit} />
      <PlaceholderPanels />
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Header — period picker + meta line
// ---------------------------------------------------------------------------

function ReportHeader({
  period,
  audit,
}: {
  period: ReportPeriod;
  audit: AggregateResult | null;
}): React.ReactElement {
  const data = audit?.data;
  const dateRange = data ? `${fmtDate(data.start)} → ${fmtDate(data.end)}` : '—';
  const events = data ? data.total : 0;
  const agentBits = data ? formatAgents(data.agentMap) : '';

  return (
    <Box flexDirection="column" paddingTop={1}>
      <Box>
        <Text color={COL.brand} bold>
          REPORT
        </Text>
        <Text dimColor>{'  ·  Period:  '}</Text>
        <PeriodKey letter="T" label="oday" active={period === 'today'} />
        <Text dimColor>{'  '}</Text>
        <PeriodKey letter="W" label="eek" active={period === '7d'} />
        <Text dimColor>{'  '}</Text>
        <PeriodKey letter="M" label="onth" active={period === '30d' || period === 'month'} />
        <Text dimColor>{`     ${PERIOD_LONG_LABEL[period]}`}</Text>
      </Box>
      <Box>
        <Text dimColor>{`  ${dateRange}  ·  ${events.toLocaleString()} events`}</Text>
        {agentBits ? <Text dimColor>{`  ·  ${agentBits}`}</Text> : null}
      </Box>
    </Box>
  );
}

function PeriodKey({
  letter,
  label,
  active,
}: {
  letter: string;
  label: string;
  active: boolean;
}): React.ReactElement {
  // Highlight active period via brand color + bold; inactive stays dim.
  // The '[X]' brackets remain bracketed in both states so the keypress
  // affordance is always visible.
  return (
    <Text color={active ? COL.brand : undefined} dimColor={!active} bold={active}>
      {`[${letter}]${label}`}
    </Text>
  );
}

// ---------------------------------------------------------------------------
// Score banner — score + headline + spend
//
// Phase 3c renders only the spend (audit-derived). Score and headline
// require the scan-walker cache and are deferred to phase 3f.
// ---------------------------------------------------------------------------

function ScoreBanner({ audit }: { audit: AggregateResult | null }): React.ReactElement {
  const data = audit?.data;
  const spend = data ? data.cost.claudeUSD + data.cost.codexUSD : 0;

  return (
    <Box paddingY={1}>
      <Text dimColor>Score —/100 ⚠ </Text>
      <Text dimColor>(coming in phase 3f)</Text>
      <Text>{'     '}</Text>
      <Text>💰 </Text>
      <Text bold>{fmtCost(spend)}</Text>
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Placeholder panels — 3d/3e/3f/3g fill these in with real content
// ---------------------------------------------------------------------------

function PlaceholderPanels(): React.ReactElement {
  return (
    <Box flexDirection="column" gap={0}>
      <PanelRow>
        <Placeholder label="PROTECTION" hint="6 outcome counters" />
        <Placeholder label="TOP BLOCKS" hint="rule-grouped block bars" />
        <Placeholder label="THIS WEEK" hint="daily activity + cost" />
      </PanelRow>
      <Placeholder label="BLAST RADIUS" hint="reachable paths the agent can read right now" full />
      <PanelRow>
        <Placeholder label="LEAKS" hint="credential types found" />
        <Placeholder label="LOOPS" hint="repeat-tool waste" />
        <Placeholder label="TOP RULES" hint="most-fired rules" />
      </PanelRow>
      <Box paddingX={1} paddingTop={1}>
        <Text dimColor>SHIELDS · HOUR OF DAY (footer strip — phase 3g)</Text>
      </Box>
    </Box>
  );
}

function PanelRow(props: { children: React.ReactNode }): React.ReactElement {
  return (
    <Box flexDirection="row" gap={1}>
      {props.children}
    </Box>
  );
}

function Placeholder({
  label,
  hint,
  full,
}: {
  label: string;
  hint: string;
  full?: boolean;
}): React.ReactElement {
  return (
    <Box
      borderStyle="round"
      borderColor={COL.textDim}
      paddingX={1}
      flexDirection="column"
      flexGrow={full ? 1 : 1}
      flexBasis={full ? undefined : 0}
    >
      <Text bold>{label}</Text>
      <Text dimColor>{`  ${hint}`}</Text>
      <Text dimColor>(coming soon)</Text>
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Tiny formatters — pulled from cli/commands/report.ts but inline here
// because Ink components shouldn't depend on the CLI's chalk-bound helpers.
// ---------------------------------------------------------------------------

function fmtDate(d: Date | string): string {
  const date = typeof d === 'string' ? new Date(d) : d;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function fmtCost(usd: number): string {
  if (usd === 0) return '$0';
  if (usd < 0.01) return '< $0.01';
  if (usd < 1) return '$' + usd.toFixed(3);
  if (usd < 100) return '$' + usd.toFixed(2);
  return '$' + Math.round(usd).toLocaleString();
}

function formatAgents(agentMap: Map<string, number>): string {
  if (agentMap.size === 0) return '';
  const ordered = [...agentMap.entries()].sort((a, b) => b[1] - a[1]);
  return ordered.map(([agent, count]) => `${agent} ${count}`).join(' · ');
}
