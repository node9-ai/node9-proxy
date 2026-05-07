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
