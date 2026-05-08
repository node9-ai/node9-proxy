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

export interface ActivityEvent {
  /** Stable id for React keys. Comes from SSE payload `id`. */
  id: string;
  ts: string; // ISO 8601
  agent?: string; // 'claude' | 'gemini' | 'codex' | ...
  tool: string;
  /** First ~70 chars of the tool's command/path arg, for the live row. */
  preview: string;
  /** Verdict from the daemon: allow / block / review / pending. */
  verdict: 'allow' | 'block' | 'review' | 'pending';
  /** Optional reason text for review/block rows (shown beneath the row). */
  reason?: string;
  /** Optional rule that fired (`block-force-push`, `dlp-block`, …). */
  checkedBy?: string;
  sessionId?: string;
  mcpServer?: string;
}

export interface AuditAggregates {
  total: number;
  allow: number;
  block: number;
  review: number;
  costUSD: number;
  tokens: number;
  sessions: number;
  mcpServers: number;
  mcpCalls: number;
  byTool: Array<{ tool: string; calls: number; blocked: number }>;
  byBlock: Array<{ rule: string; count: number }>;
  byShell: Array<{ cmd: string; count: number }>;
}

export interface BlastSnapshot {
  score: number;
  paths: string[]; // top reachable paths
  envFindings: number;
}
