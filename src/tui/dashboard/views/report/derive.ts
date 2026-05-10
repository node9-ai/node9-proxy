// src/tui/dashboard/views/report/derive.ts
//
// Period-aware filtering and rollup derivation for the Report [2]
// scan-derived panels (LEAKS / LOOPS / TOP RULES). The walker cache
// holds full ScanResult triples (claude/gemini/codex); panels need
// per-period summaries — that's what filterScanByPeriod produces.
//
// Pure: no I/O, no React. Driven entirely by inputs so the same code
// runs in tests + at render time.

import { getReportDateRange } from '../../../../cli/aggregate/report-audit.js';
import type { ScanResult } from '../../../../cli/commands/scan.js';
import type { ReportPeriod, ScanCache } from '../../types.js';

// Type-indexed shapes — Finding and DlpFinding aren't exported from scan.ts,
// so reach through ScanResult.* instead of importing them by name.
type Finding = ScanResult['findings'][number];
type DlpFinding = ScanResult['dlpFindings'][number];
type LoopFinding = ScanResult['loopFindings'][number];

export interface FilteredScan {
  /** Period-filtered raw arrays — kept around for drill-down later. */
  leaks: DlpFinding[];
  loops: LoopFinding[];
  findings: Finding[];

  /** Total tool calls across all 3 agents for the period. Approximates
   *  the denominator the CLI scan command uses for "% wasted" — comes
   *  from ScanResult.totalToolCalls (which is across the whole 90d
   *  walker window, not the period). For now we use the unfiltered
   *  totalToolCalls; future work could re-walk per period if exact. */
  totalToolCalls: number;

  /** Sessions where a credential read happened before the first edit.
   *  Used by the headline cascade. Sum across all 3 agents. */
  sessionsWithEarlySecrets: number;

  /** Top leak types within the period, sorted by count desc. */
  leaksByType: Array<{ type: string; count: number }>;

  /** Top loop tools within the period, sorted by count desc. `pct` is
   *  the share of *loop occurrences*, not of all tool calls. */
  loopsByTool: Array<{ tool: string; count: number; pct: number }>;

  /** Most-fired rules within the period, sorted by count desc. */
  topRules: Array<{ rule: string; count: number }>;

  /** Single most-looped file in the period. Undefined if no loops. */
  topLoopFile?: { path: string; count: number };
}

/** Empty filtered-scan placeholder used while the cache hasn't loaded. */
export const EMPTY_FILTERED_SCAN: FilteredScan = {
  leaks: [],
  loops: [],
  findings: [],
  totalToolCalls: 0,
  sessionsWithEarlySecrets: 0,
  leaksByType: [],
  loopsByTool: [],
  topRules: [],
  topLoopFile: undefined,
};

/**
 * Filter a ready scan-cache to the requested period and derive the
 * top-N rollups each panel needs. Best-effort timestamp filtering —
 * findings whose timestamp doesn't parse are dropped (better than
 * misattributing them to the wrong period).
 */
export function filterScanByPeriod(
  ready: Extract<ScanCache, { status: 'ready' }>,
  period: ReportPeriod,
  now: Date = new Date()
): FilteredScan {
  const { start, end } = getReportDateRange(period, now);
  const startMs = start.getTime();
  const endMs = end.getTime();

  const inPeriod = (ts: string): boolean => {
    const t = Date.parse(ts);
    if (Number.isNaN(t)) return false;
    return t >= startMs && t <= endMs;
  };

  // Combine the three agent slots into single arrays. ScanResult shapes are
  // identical across agents, so concat is safe.
  const allLeaks: DlpFinding[] = [
    ...ready.results.claude.dlpFindings,
    ...ready.results.gemini.dlpFindings,
    ...ready.results.codex.dlpFindings,
  ].filter((f) => inPeriod(f.timestamp));

  const allLoops: LoopFinding[] = [
    ...ready.results.claude.loopFindings,
    ...ready.results.gemini.loopFindings,
    ...ready.results.codex.loopFindings,
  ].filter((f) => inPeriod(f.timestamp));

  const allFindings: Finding[] = [
    ...ready.results.claude.findings,
    ...ready.results.gemini.findings,
    ...ready.results.codex.findings,
  ].filter((f) => inPeriod(f.timestamp));

  const totalToolCalls =
    ready.results.claude.totalToolCalls +
    ready.results.gemini.totalToolCalls +
    ready.results.codex.totalToolCalls;

  const sessionsWithEarlySecrets =
    ready.results.claude.sessionsWithEarlySecrets +
    ready.results.gemini.sessionsWithEarlySecrets +
    ready.results.codex.sessionsWithEarlySecrets;

  return {
    leaks: allLeaks,
    loops: allLoops,
    findings: allFindings,
    totalToolCalls,
    sessionsWithEarlySecrets,
    leaksByType: rollupLeaksByType(allLeaks),
    loopsByTool: rollupLoopsByTool(allLoops),
    topRules: rollupTopRules(allFindings),
    topLoopFile: pickTopLoopFile(allLoops),
  };
}

// ---------------------------------------------------------------------------
// Top-N rollups — pure helpers
// ---------------------------------------------------------------------------

function rollupLeaksByType(leaks: DlpFinding[]): Array<{ type: string; count: number }> {
  const map = new Map<string, number>();
  for (const l of leaks) {
    const k = l.patternName || 'unknown';
    map.set(k, (map.get(k) ?? 0) + 1);
  }
  return [...map.entries()].sort((a, b) => b[1] - a[1]).map(([type, count]) => ({ type, count }));
}

function rollupLoopsByTool(
  loops: LoopFinding[]
): Array<{ tool: string; count: number; pct: number }> {
  // Sum per tool across all loops. The `count` field on each LoopFinding
  // is the per-finding repeat count, so we sum those rather than
  // counting findings.
  const map = new Map<string, number>();
  let total = 0;
  for (const l of loops) {
    const c = typeof l.count === 'number' ? l.count : 0;
    map.set(l.toolName, (map.get(l.toolName) ?? 0) + c);
    total += c;
  }
  if (total === 0) return [];
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([tool, count]) => ({
      tool,
      count,
      pct: Math.round((count / total) * 100),
    }));
}

function rollupTopRules(findings: Finding[]): Array<{ rule: string; count: number }> {
  const map = new Map<string, number>();
  for (const f of findings) {
    // Finding.source.rule is a SmartRule; rule.name is the stable id.
    const rule = f.source?.rule?.name ?? 'unknown';
    map.set(rule, (map.get(rule) ?? 0) + 1);
  }
  return [...map.entries()].sort((a, b) => b[1] - a[1]).map(([rule, count]) => ({ rule, count }));
}

function pickTopLoopFile(loops: LoopFinding[]): { path: string; count: number } | undefined {
  // commandPreview holds the file path for Edit/Read/Write loops and a
  // command preview for Bash loops. Either way, use it as the dedupe key
  // — the user just wants to see "where the agent got stuck".
  const map = new Map<string, number>();
  for (const l of loops) {
    const k = l.commandPreview || '';
    if (!k) continue;
    map.set(k, (map.get(k) ?? 0) + (l.count ?? 0));
  }
  if (map.size === 0) return undefined;
  const [path, count] = [...map.entries()].sort((a, b) => b[1] - a[1])[0];
  return { path, count };
}
