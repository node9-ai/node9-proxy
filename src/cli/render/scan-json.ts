// src/cli/render/scan-json.ts
//
// Machine-readable output for `node9 scan --json`.
//
// Reuses src/scan-summary.ts ScanSummary (the same shape the daemon
// browser endpoint already serves) so we don't introduce a fourth
// data shape. Adds a thin envelope: a stable schemaVersion, a
// generated-at timestamp, the score band, and a top-level `totals`
// block hoisted for jq-friendly one-liners.
//
// Pure: no I/O, no chalk. Safe to unit-test.

import type { ScanResult } from '../commands/scan';
import type { ScanSummary } from '../../scan-summary';
import type { BlastResult } from '../commands/blast';
import { classifyScore, type ScoreBand } from './scan-derive';

/**
 * Wire schema for `node9 scan --json`. schemaVersion is locked at 1;
 * additive changes to ScanSummary or BlastResult propagate through
 * automatically. A breaking rename or removal must bump schemaVersion.
 */
export interface ScanJsonOutput {
  schemaVersion: 1;
  generatedAt: string; // ISO 8601
  isWired: boolean; // node9 hooks installed in any agent's settings
  score: number; // 0–100, headline blast score
  band: ScoreBand; // 'good' | 'at-risk' | 'critical'
  /** Convenience block — same numbers as summary.byVerdict, hoisted. */
  totals: {
    blocked: number;
    review: number;
    leaks: number;
    loops: number;
    blastExposures: number;
  };
  /** Full scan summary — sections, agents, leaks, loops, etc. */
  summary: ScanSummary;
  /** Reachable credentials + env findings the user has on disk. */
  blast: {
    score: number;
    reachable: BlastResult['reachable'];
    envFindings: BlastResult['envFindings'];
  };
}

export interface BuildScanJsonInput {
  scan: ScanResult;
  summary: ScanSummary;
  blast: BlastResult;
  isWired: boolean;
  /** ISO 8601. Injected for testability. */
  generatedAt: string;
}

export function buildScanJson(input: BuildScanJsonInput): ScanJsonOutput {
  const { summary, blast, isWired, generatedAt } = input;
  const { band } = classifyScore(blast.score);
  return {
    schemaVersion: 1,
    generatedAt,
    isWired,
    score: blast.score,
    band,
    totals: {
      blocked: summary.byVerdict.blocked,
      review: summary.byVerdict.supervised,
      leaks: summary.byVerdict.leaks,
      loops: summary.byVerdict.loops,
      blastExposures: blast.reachable.length + blast.envFindings.length,
    },
    summary,
    blast: {
      score: blast.score,
      reachable: blast.reachable,
      envFindings: blast.envFindings,
    },
  };
}
