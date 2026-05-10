// src/tui/dashboard/views/report/util.ts
//
// Pure formatting + bar-rendering helpers shared by the Report [2] panels.
// Mirrors the CLI's report.ts helpers but avoids the chalk import — Ink
// components handle color via <Text color="..."> wrappers, not inline ANSI.

const FILLED = '█';
const EMPTY = '░';

/** Horizontal bar of `width` cells; cells filled proportionally to value/max.
 *  Always renders at least one filled cell when value > 0 (so a tiny non-zero
 *  count is visible). Returns an empty string when width <= 0. */
export function renderBar(value: number, max: number, width: number): string {
  if (width <= 0) return '';
  if (max === 0) return EMPTY.repeat(width);
  const ratio = value / max;
  const filled = value > 0 ? Math.min(width, Math.max(1, Math.round(ratio * width))) : 0;
  return FILLED.repeat(filled) + EMPTY.repeat(width - filled);
}

// `checkedBy` audit values are stable but cryptic; map a few common ones to
// human strings. Anything unmapped passes through (better than hiding info).
const BLOCK_REASON_LABELS: Record<string, string> = {
  timeout: 'Approval timeout',
  'smart-rule-block': 'Smart rule',
  'observe-mode-dlp-would-block': 'DLP (observe)',
  'persistent-deny': 'Persistent deny',
  'local-decision': 'User denied',
  'dlp-block': 'DLP block',
  'loop-detected': 'Loop detected',
};

export function humanBlockReason(reason: string): string {
  return BLOCK_REASON_LABELS[reason] ?? reason;
}

export function fmtCost(usd: number): string {
  if (usd === 0) return '$0';
  if (usd < 0.01) return '< $0.01';
  if (usd < 1) return '$' + usd.toFixed(3);
  if (usd < 100) return '$' + usd.toFixed(2);
  return '$' + Math.round(usd).toLocaleString();
}

export function fmtShortDate(d: Date | string): string {
  const date = typeof d === 'string' ? new Date(d) : d;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/** Truncate with ellipsis if longer than width. Right-padded to exact width. */
export function fitLabel(s: string, width: number): string {
  if (s.length <= width) return s.padEnd(width);
  return s.slice(0, Math.max(0, width - 1)) + '…';
}

/** Pretty integer with thousand separators. */
export function num(n: number): string {
  return n.toLocaleString();
}

/**
 * Vertical-bar sparkline from a list of values. Each value maps to one of
 * 9 block heights ' ▁▂▃▄▅▆▇█' based on its share of max(values). Returns
 * a string of length values.length — one cell per value.
 *
 * Used by the Report [2] HOUR OF DAY footer (24 cells, one per hour).
 * Mirrors the same block set the CLI's `node9 report` already uses so
 * the visual is consistent across surfaces.
 */
export function sparkline(values: readonly number[]): string {
  if (values.length === 0) return '';
  const BLOCKS = ' ▁▂▃▄▅▆▇█';
  const max = Math.max(...values, 1);
  return values
    .map((v) => {
      const idx = Math.max(0, Math.min(8, Math.round((v / max) * 8)));
      return BLOCKS[idx];
    })
    .join('');
}
