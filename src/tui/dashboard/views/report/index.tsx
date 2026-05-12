// src/tui/dashboard/views/report/index.tsx
//
// Report [2] view shell. Header + period picker + score banner with
// real headline + 3 top panels + BLAST RADIUS row + 3 bottom panels +
// footer-strip placeholder (3g lands the sparkline).
//
// Data flow:
//   - App.tsx loads `audit` via loadReportAudit(period) on view/period
//     change. Cheap, ~10ms.
//   - App.tsx kicks off `scanCache` via startScanWalk on first [2] press.
//     Slow (~1-2s); the bottom panels show a loading state until ready.
//   - The audit panels are unaffected by the scan walk — they render
//     immediately on view switch.

import React, { useMemo } from 'react';
import { Box, Text } from 'ink';

import { COL } from '../../panels.js';
import { computeProtection } from '../../data.js';
import type { BlastSnapshot, ReportPeriod, ScanCache, ShieldStatus } from '../../types.js';
import type { AggregateResult } from '../../../../cli/aggregate/report-audit.js';
import { COST_PER_LOOP_ITER_USD } from '@node9/policy-engine';

import { Protection } from './panels/Protection.js';
import { TopBlocks } from './panels/TopBlocks.js';
import { BlastRadius } from './panels/BlastRadius.js';
import { Leaks } from './panels/Leaks.js';
import { Loops } from './panels/Loops.js';
import { TopRules } from './panels/TopRules.js';
import { FooterStrip } from './panels/FooterStrip.js';
import { EMPTY_FILTERED_SCAN, filterScanByPeriod, type FilteredScan } from './derive.js';

export interface ReportViewProps {
  period: ReportPeriod;
  /** Result of loadReportAudit(period) — null while initial load runs. */
  audit: AggregateResult | null;
  /** Blast snapshot — same data the Realtime Risk panel uses. */
  blast: BlastSnapshot | null;
  /** Background scan cache. Phase 3f reads results.{claude,gemini,codex}. */
  scanCache: ScanCache;
  /** Shield activation state — Realtime Risk panel uses the same. */
  shieldStatus: ShieldStatus | null;
}

const PERIOD_LONG_LABEL: Record<ReportPeriod, string> = {
  today: 'Today',
  '7d': 'Last 7 Days',
  '30d': 'Last 30 Days',
  '90d': 'Last 90 Days',
  month: 'This Month',
};

export function ReportView({
  period,
  audit,
  blast,
  scanCache,
  shieldStatus,
}: ReportViewProps): React.ReactElement {
  // Re-filter the scan cache whenever period changes or the cache
  // transitions from loading → ready. While loading/idle/error, fall
  // back to the empty filtered shape so panels can render placeholder
  // states uniformly.
  const filtered = useMemo<FilteredScan>(() => {
    if (scanCache.status !== 'ready') return EMPTY_FILTERED_SCAN;
    return filterScanByPeriod(scanCache, period);
  }, [scanCache, period]);

  return (
    <Box flexDirection="column" flexGrow={1} paddingX={1}>
      <ReportHeader period={period} audit={audit} />
      <ScoreBanner
        audit={audit}
        blast={blast}
        shieldStatus={shieldStatus}
        scanCache={scanCache}
        filtered={filtered}
      />
      <Box flexDirection="row" gap={1}>
        <Protection audit={audit} />
        <TopBlocks audit={audit} />
      </Box>
      <BlastRadius
        blast={blast}
        protectedByProjectJail={shieldStatus?.active.includes('project-jail') ?? false}
      />
      <Box flexDirection="row" gap={1}>
        <Leaks scanCache={scanCache} filtered={filtered} />
        <Loops scanCache={scanCache} filtered={filtered} />
        <TopRules scanCache={scanCache} filtered={filtered} />
      </Box>
      <FooterStrip shieldStatus={shieldStatus} audit={audit} />
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
        <Text dimColor>{'  '}</Text>
        <PeriodKey letter="N" label="inety" active={period === '90d'} />
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
// Score banner — effective score + breakdown + headline + spend
//
// Score: the EFFECTIVE score from computeProtection (blast exposure
// adjusted for active protective shields). Same headline number the
// `[1]` Realtime RISK box uses, so users see one consistent risk
// figure across both views. Prior versions of this banner showed raw
// blast.score (e.g. 25/100) while `[1]` showed effective (78/100)
// after project-jail kicked in — confusing inconsistency.
//
// Breakdown line: shows the three-number story (exposed N · protect
// +X · effective Y) so the user can see WHY the score is what it is
// and what changes if shields toggle.
//
// Headline: priority cascade — first match wins. Surfaces the most
// alarming signal in one line so users glance at the banner and know
// "is anything bad". Loading state shows a dim placeholder until the
// scan walk completes.
// ---------------------------------------------------------------------------

export function ScoreBanner({
  audit,
  blast,
  shieldStatus,
  scanCache,
  filtered,
}: {
  audit: AggregateResult | null;
  blast: BlastSnapshot | null;
  /** Optional. When omitted, the effective score equals the raw blast
   *  score (no protect bonus applied). The dashboard always passes
   *  it; some unit tests render the banner in isolation without
   *  shield state. */
  shieldStatus?: ShieldStatus | null;
  scanCache: ScanCache;
  filtered: FilteredScan;
}): React.ReactElement {
  const data = audit?.data;
  const spend = data ? data.cost.claudeUSD + data.cost.codexUSD : 0;
  const protection = computeProtection(blast, shieldStatus ?? null);
  const hasBlast = blast !== null;
  const tier = hasBlast ? scoreTier(protection.effective) : null;
  const headline = computeHeadline(scanCache, filtered, blast);

  return (
    <Box flexDirection="column" paddingY={1}>
      {/* Row 1: Effective score + tier + headline + spend */}
      <Box>
        {hasBlast && tier ? (
          <>
            <Text bold color={tier.color}>{`Score ${protection.effective}/100`}</Text>
            <Text>{'  '}</Text>
            <Text color={tier.color}>{tier.icon + ' ' + tier.label}</Text>
          </>
        ) : (
          <Text dimColor>Score —/100</Text>
        )}
        <Text>{'     '}</Text>
        {headline ? (
          <Text color={headline.color} dimColor={headline.dim}>
            {headline.text}
          </Text>
        ) : null}
        <Text>{'     '}</Text>
        <Text>💰 </Text>
        <Text bold>{fmtCost(spend)}</Text>
      </Box>
      {/* Row 2: Score breakdown — exposed / protect / effective. Only
          when blast is loaded; suppressed if exposed is 0 (perfect
          score, breakdown is just "100 = 100, nothing to explain"). */}
      {hasBlast && protection.exposed > 0 ? (
        <Box marginTop={0}>
          <Text dimColor>{`  exposed ${protection.exposed} · protect `}</Text>
          <Text bold color={protection.protect > 0 ? '#5BF58C' : undefined}>
            {`+${protection.protect}`}
          </Text>
          <Text dimColor>{` · effective ${protection.effective}/100`}</Text>
          {protection.suggestedShield ? (
            <>
              <Text dimColor>{'     ↑ enable '}</Text>
              <Text bold>{protection.suggestedShield}</Text>
              <Text dimColor>{` → +${protection.suggestedBonus}`}</Text>
            </>
          ) : null}
        </Box>
      ) : null}
    </Box>
  );
}

interface ScoreTier {
  label: string;
  icon: string;
  color: string;
}

function scoreTier(score: number): ScoreTier {
  if (score >= 80) return { label: 'Good', icon: '✓', color: 'green' };
  if (score >= 50) return { label: 'Moderate', icon: '⚠', color: 'yellow' };
  if (score >= 25) return { label: 'High risk', icon: '⚠', color: 'red' };
  return { label: 'Critical', icon: '⚠', color: 'red' };
}

interface Headline {
  text: string;
  color?: string;
  dim?: boolean;
}

/** Priority cascade — first match wins. Returns null while there's no
 *  data to assess (e.g. scan still loading and audit/blast both empty). */
function computeHeadline(
  scanCache: ScanCache,
  filtered: FilteredScan,
  blast: BlastSnapshot | null
): Headline | null {
  if (scanCache.status === 'loading') {
    return { text: '(scanning history…)', dim: true };
  }
  if (scanCache.status === 'error') {
    return { text: '⚠ scan failed · [r] to retry', color: 'red' };
  }
  if (scanCache.status === 'idle') {
    // Idle is now transient (entering [2] auto-starts the walk). If the
    // user somehow lingers here, [r] will rescan — same affordance.
    return { text: '(scan idle · [r] to start)', dim: true };
  }
  // Tier 1 — `sessionsWithEarlySecrets` cascade rule removed 2026-05-12.
  // The count was a lifetime-of-history sum (not period-bounded), so
  // [T]oday could still show "1 session loaded secrets pre-edit" from
  // a session 6 months ago. Once tripped it became a permanent red
  // badge that no workflow fix could clear — bad signal-to-noise.
  // To restore: make scan walker emit per-session timestamps so we can
  // filter by period in derive.ts (~1-2 hrs of work, deferred).
  if (filtered.leaks.length > 0) {
    const n = filtered.leaks.length;
    return {
      text: `📌 ${n} leak${n === 1 ? '' : 's'} this period`,
      color: 'yellow',
    };
  }
  if (filtered.loops.length > 100) {
    const wasted = filtered.loops.reduce((s, l) => s + (l.count ?? 0) * COST_PER_LOOP_ITER_USD, 0);
    return {
      text: `📌 ${filtered.loops.length} loops · ~${fmtCost(wasted)} wasted`,
      color: 'yellow',
    };
  }
  const exposed = blast?.paths.length ?? 0;
  if (exposed > 0) {
    return {
      text: `📌 ${exposed} exposed path${exposed === 1 ? '' : 's'}`,
      color: 'yellow',
    };
  }
  if (scanCache.status === 'ready') {
    return { text: 'no critical issues this period', dim: true };
  }
  return null;
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
