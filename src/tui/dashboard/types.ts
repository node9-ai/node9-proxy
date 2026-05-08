// src/tui/dashboard/types.ts
//
// Shared types for the dashboard spike. Kept in one file for navigability.

export type TimeWindow = 'now' | '1d' | '7d' | '30d' | '60d';

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

/** Aggregated cost + tokens within the selected window. Computed off
 *  costSync.collectEntries(). `loaded: false` is shown while the
 *  initial async walk is in flight. */
export interface CostSnapshot {
  totalUSD: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  loaded: boolean;
}
