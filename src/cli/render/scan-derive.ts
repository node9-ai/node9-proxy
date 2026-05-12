// src/cli/render/scan-derive.ts
//
// Pure derivation helpers used by the three scan renderers
// (default inline / --compact / --narrative).
//
// Before extraction, the same score-band, top-N, and loop-waste
// arithmetic was inlined three times in scan.ts and quietly drifting.
// These helpers are the single source of truth so the renderers stay
// in sync. No I/O, no console — safe to unit-test.
import chalk from 'chalk';
import type { Section } from '../../scan-summary';

// ---------------------------------------------------------------------------
// Score classification
// ---------------------------------------------------------------------------

export type ScoreBand = 'good' | 'at-risk' | 'critical';

export interface ScoreClassification {
  band: ScoreBand;
  label: string; // 'Good' | 'At Risk' | 'Critical'
  color: chalk.Chalk; // green / yellow / red — matches band
}

/**
 * Bucket a 0–100 security score into a band, plus a display label and a
 * chalk colorizer. Thresholds match the existing renderers exactly:
 *   ≥80 good · ≥50 at-risk · <50 critical
 */
export function classifyScore(score: number): ScoreClassification {
  if (score >= 80) return { band: 'good', label: 'Good', color: chalk.green };
  if (score >= 50) return { band: 'at-risk', label: 'At Risk', color: chalk.yellow };
  return { band: 'critical', label: 'Critical', color: chalk.red };
}

// ---------------------------------------------------------------------------
// Top-N DLP patterns by frequency
// ---------------------------------------------------------------------------

export interface PatternCount {
  name: string;
  count: number;
}

/**
 * Group DLP findings by pattern name and return the top-N most frequent.
 * Stable across both compact and narrative scorecards.
 */
export function topDlpPatterns(
  findings: ReadonlyArray<{ patternName: string }>,
  n: number
): PatternCount[] {
  const counts = new Map<string, number>();
  for (const f of findings) {
    counts.set(f.patternName, (counts.get(f.patternName) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([name, count]) => ({ name, count }));
}

// ---------------------------------------------------------------------------
// Top-N rules by verdict
// ---------------------------------------------------------------------------

export interface RuleCount {
  name: string;
  count: number;
}

/**
 * Flatten all rules across sections that match `verdict`, sort by finding
 * count descending, return the top-N. Used by --compact for both the
 * "blocked" and "review" callout lines.
 */
export function topRulesByVerdict(
  sections: ReadonlyArray<Section>,
  verdict: 'block' | 'review',
  n: number
): RuleCount[] {
  const matched: RuleCount[] = [];
  for (const section of sections) {
    for (const rule of section.rules) {
      // The compact "review" line treats anything non-block as review,
      // matching the original inline logic at scan.ts:1975.
      const matches = verdict === 'block' ? rule.verdict === 'block' : rule.verdict !== 'block';
      if (matches) matched.push({ name: rule.name, count: rule.findings.length });
    }
  }
  return matched.sort((a, b) => b.count - a.count).slice(0, n);
}

// ---------------------------------------------------------------------------
// Loop waste
// ---------------------------------------------------------------------------

export interface LoopWaste {
  wastedCalls: number;
  /** Whole-percent integer (matches the existing renderer rounding). */
  wastePct: number;
}

/**
 * Compute total wasted iterations and a percent-of-total-tool-calls
 * figure. Long-iteration findings (sustained deep work) are excluded
 * from the compact + default views; pass the pre-filtered list, or
 * leave them in for the narrative view which counts them with the rest.
 *
 * waste-per-loop = max(0, count - 1), matching the existing inline math.
 */
export function computeLoopWaste(
  loops: ReadonlyArray<{ count: number }>,
  totalToolCalls: number
): LoopWaste {
  const wastedCalls = loops.reduce((s, l) => s + Math.max(0, l.count - 1), 0);
  const wastePct = totalToolCalls > 0 ? Math.round((wastedCalls / totalToolCalls) * 100) : 0;
  return { wastedCalls, wastePct };
}

// ---------------------------------------------------------------------------
// Shield rollup — "how many ops would each shield catch?"
// ---------------------------------------------------------------------------

export interface ShieldImpact {
  /** Shield name, matches SHIELDS registry key (e.g. 'project-jail'). */
  shieldName: string;
  /** Total findings attributable to this shield (block + review). */
  totalCatches: number;
  blockCatches: number;
  reviewCatches: number;
  /** Top rule labels for the panel's per-shield description line. */
  topRuleLabels: string[];
}

/**
 * Aggregate a ScanSummary's per-rule findings into per-shield "would
 * catch" counts. Only sections with sourceType === 'shield' are
 * counted — default-rule fires don't belong to any shield and are
 * counted separately in the BLOCKED / REVIEW QUEUE panels.
 *
 * Used by the new panel-mode scan renderer to power the SHIELDS
 * recommendation panel ("project-jail would catch 9 ops on your
 * machine"). Sorted by totalCatches desc so the biggest-impact
 * shield surfaces at the top.
 */
export function rollupByShield(
  sections: ReadonlyArray<Section>,
  topRulesPerShield = 3
): ShieldImpact[] {
  const out: ShieldImpact[] = [];
  for (const section of sections) {
    if (section.sourceType !== 'shield') continue;
    if (!section.shieldKey) continue;
    const totalCatches = section.blockedCount + section.reviewCount;
    const topRuleLabels = [...section.rules]
      .sort((a, b) => b.findings.length - a.findings.length)
      .slice(0, topRulesPerShield)
      .map((r) => (r.findings.length > 1 ? `${r.name} ×${r.findings.length}` : r.name));
    out.push({
      shieldName: section.shieldKey,
      totalCatches,
      blockCatches: section.blockedCount,
      reviewCatches: section.reviewCount,
      topRuleLabels,
    });
  }
  return out.sort((a, b) => b.totalCatches - a.totalCatches);
}

// ---------------------------------------------------------------------------
// Box-drawing + date formatting helpers — used by the panel renderer
// ---------------------------------------------------------------------------

/** Default panel width in columns. Wider than the legacy 70-char
 *  divider so multi-column rows (LEAKS, BLAST RADIUS file descriptions,
 *  loop top-stuck paths) fit without overflow on a standard 80-col
 *  terminal — the 2-char leading indent + 76-char panel = 78 cols,
 *  leaving 2 cols of margin even at the strictest width. */
export const PANEL_WIDTH = 76;

/**
 * Wrap a list of content lines in a Unicode box-drawing frame:
 *
 *   ╭─ title ───────────────────────────────────────╮
 *   │  body line 1                                  │
 *   │  body line 2                                  │
 *   ╰────────────────────────────────────────────────╯
 *
 * `visibleLen` measures the WIDTH of each content line (callers strip
 * ANSI escapes before passing). The function pads each line with spaces
 * to keep the right border aligned, dimming the box characters
 * themselves so the box reads as scaffolding rather than content.
 *
 * Returns the rendered lines as an array — callers join with '\n' or
 * pipe to console.log line-by-line. Pure (no I/O) so it's snapshot-
 * testable in isolation.
 */
export function boxPanel(
  title: string,
  bodyLines: ReadonlyArray<{ rendered: string; width: number }>,
  width: number = PANEL_WIDTH
): string[] {
  // Inner width = panel width minus the two border columns ('│ ' + ' │').
  const inner = width - 4;
  const out: string[] = [];

  // Top border with embedded title:  "╭─ title ─────────╮"
  const titlePad = ` ${title} `;
  const titleSegment = titlePad.length <= inner ? titlePad : titlePad.slice(0, inner);
  const dashFill = '─'.repeat(Math.max(0, inner - titleSegment.length));
  out.push(chalk.dim('╭─') + chalk.bold(titleSegment) + chalk.dim(`${dashFill}─╮`));

  for (const line of bodyLines) {
    const padding = ' '.repeat(Math.max(0, inner - line.width));
    out.push(chalk.dim('│ ') + line.rendered + padding + chalk.dim(' │'));
  }

  out.push(chalk.dim('╰' + '─'.repeat(inner + 2) + '╯'));
  return out;
}

/**
 * Render a relative-time label for the panel renderer:
 *   "today" / "1d" / "30d" / "90d+"
 *
 * Pre-computed against an injected `now` for deterministic snapshot
 * tests. Tight by design — the panel rows are narrow.
 */
export function relativeDate(timestamp: string, now: Date = new Date()): string {
  const t = new Date(timestamp).getTime();
  if (Number.isNaN(t)) return '?';
  const days = Math.floor((now.getTime() - t) / 86_400_000);
  if (days < 1) return 'today';
  if (days > 90) return '90d+';
  return `${days}d`;
}
