// src/tui/dashboard/format.ts
//
// Pure display-formatting helpers for the dashboard. No React, no Ink,
// no I/O — safe to unit-test without booting the TUI runtime.
// Extracted from panels.tsx so tests don't drag in the React+Ink graph
// (which slows test imports + makes vitest's loader complain).

import type { CostSnapshot } from './types.js';

/** Compact cost format:
 *    0       → "$0"
 *    < 100   → "$0.42"  (two-decimal cents)
 *    < 10K   → "$1,234"
 *    >= 10K  → "$12.4K"
 */
export function formatCost(usd: number): string {
  if (usd === 0) return '$0';
  if (usd < 1) return `$${usd.toFixed(2)}`;
  if (usd < 100) return `$${usd.toFixed(2)}`;
  if (usd < 10_000) return `$${Math.round(usd).toLocaleString()}`;
  return `$${(usd / 1000).toFixed(1)}K`;
}

/** Compact token format:
 *    < 1K       → raw integer
 *    < 1M       → "1.2K" / "12K"
 *    >= 1M      → "1.2M"
 */
export function formatTokens(n: number): string {
  if (n < 1000) return `${n}`;
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}K`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

/** Whole-percent format: `94%`. Returns "—" when input is non-finite. */
export function formatPct(pct: number): string {
  if (!Number.isFinite(pct)) return '—';
  return `${Math.round(pct)}%`;
}

/** Cache hit rate from a CostSnapshot.
 *  Reads / (reads + new input). Mirrors `node9 report`'s definition. */
export function cacheHitRate(cost: CostSnapshot): number {
  const denom = cost.cacheReadTokens + cost.inputTokens;
  if (denom <= 0) return 0;
  return (cost.cacheReadTokens / denom) * 100;
}

/** Strip noise from a model id for compact display:
 *    'claude-opus-4-7'           → 'opus-4-7'
 *    'claude-haiku-4-5-20251001' → 'haiku-4-5'
 *    'gpt-5'                     → 'gpt-5' (unchanged)
 */
export function shortenModel(model: string): string {
  return model.replace(/^claude-/, '').replace(/-2025\d{4}$/, '');
}

/** Truncate to width with single-char `…` overflow marker. Pad-friendly:
 *  result is always ≤ width chars. Strings ≤ width pass through unchanged. */
export function truncate(s: string, width: number): string {
  return s.length <= width ? s : s.slice(0, width - 1) + '…';
}

/**
 * Local-time `HH:MM:SS` (24-hour) from an ISO timestamp string OR an
 * epoch-millisecond number. Returns a placeholder when the input can't
 * be parsed. Used by the LIVE row (ISO strings) and the StatusBar's
 * last-refresh indicator (epoch ms from Date.now()).
 */
export function localTimeOf(ts: unknown): string {
  let d: Date;
  if (typeof ts === 'number' && Number.isFinite(ts)) {
    d = new Date(ts);
  } else if (typeof ts === 'string' && ts.length > 0) {
    d = new Date(ts);
  } else {
    return '--:--:--';
  }
  if (Number.isNaN(d.getTime())) return '--:--:--';
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss}`;
}
