// src/tui/dashboard/types.ts
//
// Shared types for the `node9 monitor` dashboard. Kept in one file for navigability.

export type TimeWindow = 'now' | '1d' | '7d' | '30d' | '60d';

/** Top-level dashboard view. `[1]` selects realtime; `[2]` selects report.
 *  Realtime answers "what's happening now"; report answers "what has
 *  happened over time". Header + footer are shared chrome; only the body
 *  swaps. See doc/roadmap/monitor-two-view.md for the full plan. */
export type View = 'realtime' | 'report';

/** Period selector for the Report view. Re-exported from cli/render/report-json
 *  so the dashboard, the `node9 report` CLI, and the shared aggregator
 *  (cli/aggregate/report-audit) all agree on which periods exist. The four
 *  values are bound to T/W/M hotkeys in the Report view's input handler.
 *  Independent from TimeWindow (the realtime monitor's window-tabs concept,
 *  retired in phase 2). */
export type { ReportPeriod } from '../../cli/render/report-json.js';
import type { ReportPeriod as _ReportPeriod } from '../../cli/render/report-json.js';

export const REPORT_PERIODS: readonly _ReportPeriod[] = ['today', '7d', '30d', 'month'] as const;

export const TIME_WINDOWS: readonly TimeWindow[] = ['now', '1d', '7d', '30d', '60d'] as const;

/** Compute the earliest epoch-ms the window covers. `now` returns Date.now() so
 *  audit aggregation excludes everything; only SSE since open will be counted. */
export function windowStartMs(window: TimeWindow, openedAt: number): number {
  if (window === 'now') return openedAt;
  const day = 86_400_000;
  switch (window) {
    case '1d':
      return Date.now() - day;
    case '7d':
      return Date.now() - 7 * day;
    case '30d':
      return Date.now() - 30 * day;
    case '60d':
      return Date.now() - 60 * day;
  }
}

/**
 * Two kinds of rows show up in the LIVE feed:
 *   - `tool`     — a real agent tool call (Bash, Read, Edit, …) that
 *                  the daemon either allowed, blocked, or queued for
 *                  review. The default and most common case.
 *   - `snapshot` — the daemon recorded a working-directory snapshot
 *                  before a write. Different shape (hash + fileCount,
 *                  no verdict) and different visual; matches what
 *                  `node9 tail` already prints.
 */
export type ActivityEvent =
  | {
      kind: 'tool';
      id: string;
      ts: string; // ISO 8601
      agent?: string; // 'claude' | 'gemini' | 'codex' | ...
      tool: string;
      /** First ~70 chars of the tool's command/path arg. */
      preview: string;
      verdict: 'allow' | 'block' | 'review' | 'pending';
      reason?: string;
      /** Rule that fired (`block-force-push`, `dlp-block`, `loop-detected`, …). */
      checkedBy?: string;
      sessionId?: string;
      mcpServer?: string;
      /**
       * True only for SSE 'add' events — the daemon broadcasts those to
       * approval listeners, so they represent real "queued for human
       * approval" requests. Plain 'activity' events with status:'pending'
       * also lack a decision but are transient (sub-second) and must
       * NOT trigger the APPROVAL notification flash.
       */
      isApprovalRequest?: boolean;
    }
  | {
      kind: 'snapshot';
      id: string;
      ts: string;
      hash: string;
      /** Short summary line (path or tool name). */
      summary: string;
      fileCount: number;
    };

export interface AuditAggregates {
  total: number;
  allow: number;
  block: number;
  review: number;
  /** Audit entries blocked by loop-detection (subset of block, surfaced separately for the HUD). */
  loops: number;
  /** Audit entries flagged by any DLP rule (`dlp-block`, `dlp-saas:*`, etc.).
   *  Computed from ALL entries, not just byBlock top-6, so the count is honest. */
  dlpHits: number;
  sessions: number;
  mcpServers: number;
  mcpCalls: number;
  byTool: Array<{ tool: string; calls: number; blocked: number }>;
  byBlock: Array<{ rule: string; count: number }>;
  byShell: Array<{ cmd: string; count: number; blocked: number }>;
}

export interface BlastSnapshot {
  score: number;
  paths: string[]; // top reachable paths
  envFindings: number;
}

/** Shield-config snapshot — names of shields registered (builtin + user)
 *  vs the names actually active in ~/.node9/shields.json. */
export interface ShieldStatus {
  active: string[];
  inactive: string[];
}

/** Forensic scan-signal counts — derived by walking ~/.claude/projects
 *  JSONL files and running the canonical extractor per line. Reflects
 *  ALL of the user's recent agent history, NOT the dashboard's selected
 *  time window. The same data `node9 scan` reports under each section.
 *  `loaded: false` is shown while the initial async walk is in flight. */
export interface ScanSignalsSnapshot {
  loaded: boolean;
  pii: number;
  sensitiveFileRead: number;
  privilegeEscalation: number;
  destructiveOp: number;
  pipeToShell: number;
  evalOfRemote: number;
  longOutputRedacted: number;
}

/** Live (since-monitor-opened) forensic counts. Same shape as
 *  ScanSignalsSnapshot's data fields, no `loaded` flag (always live —
 *  starts at zero and increments on every 'forensic' SSE event from
 *  the daemon). Keyed identical to ScanSignalsSnapshot for symmetry
 *  in the RISK panel. */
export interface SessionForensicAgg {
  pii: number;
  sensitiveFileRead: number;
  privilegeEscalation: number;
  destructiveOp: number;
  pipeToShell: number;
  evalOfRemote: number;
  longOutputRedacted: number;
}

export const EMPTY_SESSION_FORENSIC: SessionForensicAgg = {
  pii: 0,
  sensitiveFileRead: 0,
  privilegeEscalation: 0,
  destructiveOp: 0,
  pipeToShell: 0,
  evalOfRemote: 0,
  longOutputRedacted: 0,
};

/** SSE 'forensic' event payload. Mirrors the ForensicEvent shape the
 *  daemon broadcasts in src/daemon/state.ts. Carries categorical
 *  metadata only — never raw matched content. */
export interface ForensicSseEvent {
  type: 'forensic';
  id: string;
  ts: number;
  sessionId: string;
  category:
    | 'dlp'
    | 'pii'
    | 'sensitive-file-read'
    | 'privilege-escalation'
    | 'network-exfil'
    | 'pipe-to-shell'
    | 'eval-of-remote'
    | 'destructive-op'
    | 'loop'
    | 'long-output-redacted';
  patternName?: string;
  severity: 'critical' | 'warning';
}

/** Aggregated cost + tokens within the selected window. Computed off
 *  costSync.collectEntries(). `loaded: false` is shown while the
 *  initial async walk is in flight. */
export interface CostSnapshot {
  totalUSD: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  /** Per-model rollup, sorted desc by cost. Top 3 surfaced in REPORT. */
  byModel: Array<{ model: string; costUSD: number; calls: number }>;
  loaded: boolean;
}

// ---------------------------------------------------------------------------
// Report [2] view — scan-walker cache state
// ---------------------------------------------------------------------------

import type { ScanResult } from '../../cli/commands/scan.js';

/**
 * Lazy cache for the agent-history scan walk. The dashboard's Report [2]
 * view consumes scan-derived panels (LEAKS / LOOPS / TOP RULES) and the
 * walk takes 1–2 s on warm machines, so it's deferred until the user
 * actually presses [2]. State machine:
 *
 *   idle    — first dashboard mount, walk hasn't started yet
 *   loading — startScanWalk() has been kicked off in the background;
 *             scan-derived panels render a loading placeholder while
 *             non-scan panels render normally
 *   ready   — walk finished. results.{claude,gemini,codex} hold full
 *             ScanResult triples; period filtering is in-memory after this
 *   error   — walk threw; scan-derived panels render an error state with
 *             [r] retry hint
 */
export type ScanCache =
  | { status: 'idle' }
  | { status: 'loading' }
  | {
      status: 'ready';
      results: { claude: ScanResult; gemini: ScanResult; codex: ScanResult };
      /** ms epoch when the walk finished — used to invalidate on [r] refresh. */
      readyAt: number;
    }
  | { status: 'error'; error: Error };
