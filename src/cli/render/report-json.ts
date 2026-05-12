// src/cli/render/report-json.ts
//
// Machine-readable output for `node9 report --json`.
//
// Mirrors the envelope shape of scan-json.ts (schemaVersion 1, generatedAt,
// totals block hoisted) so consumers see a consistent shape across both
// commands. The inner data is different — scan reads raw agent history,
// report reads ~/.node9/audit.log — but the wrapping is the same.
//
// Pure: no I/O. Takes the aggregated state already computed in the report
// action handler and produces a JSON-friendly envelope. Maps become arrays
// of {key, value} objects sorted by frequency, untruncated.

// ---------------------------------------------------------------------------
// Input — the aggregated state collected by the action handler
// ---------------------------------------------------------------------------

export type ReportPeriod = 'today' | '7d' | '30d' | '90d' | 'month';

export interface BuildReportJsonInput {
  period: ReportPeriod;
  start: Date;
  end: Date;
  /** Number of test-runner entries excluded by --no-tests, 0 if not set. */
  excludedTests: number;

  // Top-line counters (computed from PreToolUse audit entries in range)
  total: number;
  userApproved: number;
  userDenied: number;
  timedOut: number;
  hardBlocked: number;
  dlpBlocked: number;
  observeDlp: number;
  loopHits: number;
  testPasses: number;
  testFails: number;
  unackedDlp: number;

  /** Block rate of the prior equal-length window. null if no prior data. */
  priorBlockRate: number | null;

  cost: {
    claudeUSD: number;
    codexUSD: number;
    inputTokens: number;
    outputTokens: number;
    cacheWriteTokens: number;
    cacheReadTokens: number;
    byDay: Map<string, number>; // ISO day (YYYY-MM-DD) → USD
    byModel: Map<string, number>; // Claude model id → USD
    /** Project (decoded cwd) → cost + token rollup. Drives the
     *  [2] TOP PROJECTS panel. */
    byProject: Map<string, { cost: number; inputTokens: number; outputTokens: number }>;
  };

  toolMap: Map<string, { calls: number; blocked: number }>;
  blockMap: Map<string, number>;
  agentMap: Map<string, number>;
  mcpMap: Map<string, number>;
  dailyMap: Map<string, { calls: number; blocked: number }>;
  hourMap: Map<number, number>;

  /** ISO 8601, injected for testability. */
  generatedAt: string;
}

// ---------------------------------------------------------------------------
// Output — the wire shape
// ---------------------------------------------------------------------------

export interface ReportJsonOutput {
  schemaVersion: 1;
  generatedAt: string;
  period: ReportPeriod;
  range: { start: string; end: string };
  excludedTests: number;

  /** Convenience block — derived counts hoisted for jq one-liners. */
  totals: {
    events: number;
    blocked: number; // sum of all block paths (timedOut + hardBlocked + dlpBlocked + loopHits + userDenied)
    blockRate: number; // 0..1
    userApproved: number;
    userDenied: number;
    timedOut: number;
    hardBlocked: number;
    dlpBlocked: number;
    observeDlp: number;
    loopHits: number;
    unackedDlp: number;
  };

  tests: {
    passes: number;
    fails: number;
  };

  cost: {
    totalUSD: number;
    claudeUSD: number;
    codexUSD: number;
    inputTokens: number;
    outputTokens: number;
    cacheWriteTokens: number;
    cacheReadTokens: number;
    byDay: Array<{ day: string; usd: number }>;
    byModel: Array<{ model: string; usd: number }>;
  };

  byTool: Array<{ tool: string; calls: number; blocked: number }>;
  byBlock: Array<{ rule: string; count: number }>;
  byAgent: Array<{ agent: string; calls: number }>;
  byMcp: Array<{ server: string; calls: number }>;
  byDay: Array<{ day: string; calls: number; blocked: number }>;
  byHour: Array<{ hour: number; calls: number }>;

  trend: {
    priorBlockRate: number | null;
    /** Whole-percent delta vs prior. null if no prior data. */
    deltaPct: number | null;
  };
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

export function buildReportJson(input: BuildReportJsonInput): ReportJsonOutput {
  const totalBlocked =
    input.timedOut + input.hardBlocked + input.dlpBlocked + input.loopHits + input.userDenied;
  const blockRate = input.total > 0 ? totalBlocked / input.total : 0;

  const deltaPct =
    input.priorBlockRate === null ? null : Math.round((blockRate - input.priorBlockRate) * 100);

  return {
    schemaVersion: 1,
    generatedAt: input.generatedAt,
    period: input.period,
    range: { start: input.start.toISOString(), end: input.end.toISOString() },
    excludedTests: input.excludedTests,

    totals: {
      events: input.total,
      blocked: totalBlocked,
      blockRate,
      userApproved: input.userApproved,
      userDenied: input.userDenied,
      timedOut: input.timedOut,
      hardBlocked: input.hardBlocked,
      dlpBlocked: input.dlpBlocked,
      observeDlp: input.observeDlp,
      loopHits: input.loopHits,
      unackedDlp: input.unackedDlp,
    },

    tests: {
      passes: input.testPasses,
      fails: input.testFails,
    },

    cost: {
      totalUSD: input.cost.claudeUSD + input.cost.codexUSD,
      claudeUSD: input.cost.claudeUSD,
      codexUSD: input.cost.codexUSD,
      inputTokens: input.cost.inputTokens,
      outputTokens: input.cost.outputTokens,
      cacheWriteTokens: input.cost.cacheWriteTokens,
      cacheReadTokens: input.cost.cacheReadTokens,
      byDay: [...input.cost.byDay.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([day, usd]) => ({ day, usd })),
      byModel: [...input.cost.byModel.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([model, usd]) => ({ model, usd })),
    },

    byTool: [...input.toolMap.entries()]
      .sort((a, b) => b[1].calls - a[1].calls)
      .map(([tool, v]) => ({ tool, calls: v.calls, blocked: v.blocked })),
    byBlock: [...input.blockMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([rule, count]) => ({ rule, count })),
    byAgent: [...input.agentMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([agent, calls]) => ({ agent, calls })),
    byMcp: [...input.mcpMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([server, calls]) => ({ server, calls })),
    byDay: [...input.dailyMap.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([day, v]) => ({ day, calls: v.calls, blocked: v.blocked })),
    byHour: [...input.hourMap.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([hour, calls]) => ({ hour, calls })),

    trend: {
      priorBlockRate: input.priorBlockRate,
      deltaPct,
    },
  };
}
