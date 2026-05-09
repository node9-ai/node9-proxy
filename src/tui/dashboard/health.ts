// src/tui/dashboard/health.ts
//
// Unified security-health badge for the dashboard. Aggregates every
// signal source the dashboard already tracks (live SSE counters, audit
// aggregates, mount-time forensic scan, blast snapshot, shield config)
// into a single tri-state badge rendered in the Header.
//
// Pure function — easy to unit-test, no side effects, no React.

import type {
  AuditAggregates,
  BlastSnapshot,
  ScanSignalsSnapshot,
  SessionForensicAgg,
  ShieldStatus,
} from './types.js';

export type HealthSeverity = 'secure' | 'warning' | 'critical';

export interface HealthBadge {
  severity: HealthSeverity;
  /** Short labels (max 3) explaining what tripped the badge. Empty when secure. */
  reasons: string[];
  /** Hint shown alongside non-secure badges, e.g. "see node9 scan". */
  hint?: string;
}

interface HealthInput {
  agg: AuditAggregates;
  blast: BlastSnapshot;
  scanSignals: ScanSignalsSnapshot | null;
  shieldStatus: ShieldStatus | null;
  forensicAgg: SessionForensicAgg;
}

/**
 * Compute the unified health badge from every signal source.
 *
 * Severity tiers:
 *   🛑 critical — DLP / loop in this window, severe forensic finding
 *                 (privesc / destructive-op / eval-of-remote, live or
 *                 historical), or blast score < 25
 *   ⚠ warning  — non-severe forensic finding (PII / sensitive-file-read /
 *                 pipe-to-shell / long-output-redacted), reachable blast
 *                 paths, inactive shields, or blast score 25–49
 *   ✓ secure   — none of the above
 *
 * Critical wins over warning. The reasons array is bounded to 3 items
 * for header rendering — the most-load-bearing reasons are pushed first.
 */
export function computeHealthBadge(input: HealthInput): HealthBadge {
  const reasons: string[] = [];
  let severity: HealthSeverity = 'secure';

  // ── CRITICAL signals ──────────────────────────────────────────────────────
  // Live security alerts in the current window — high-priority context.
  if (input.agg.dlpHits > 0) {
    severity = 'critical';
    reasons.push(`${input.agg.dlpHits} DLP`);
  }
  if (input.agg.loops > 0) {
    severity = 'critical';
    reasons.push(`${input.agg.loops} loops`);
  }

  // Severe forensic categories — live (since-open) + historical (90-day).
  // Both surfaces matter: live tells you about right-now exposure;
  // historical tells you about past-but-unresolved exposure.
  const liveSevere =
    input.forensicAgg.privilegeEscalation +
    input.forensicAgg.destructiveOp +
    input.forensicAgg.evalOfRemote;
  const histSevere = input.scanSignals
    ? input.scanSignals.privilegeEscalation +
      input.scanSignals.destructiveOp +
      input.scanSignals.evalOfRemote
    : 0;
  const totalSevere = liveSevere + histSevere;
  if (totalSevere > 0) {
    severity = 'critical';
    reasons.push(`${totalSevere} severe forensic`);
  }

  // Blast score below 25 — exposure threshold consistent with the
  // existing color scheme in panels.tsx (red below 50, but 25 is the
  // critical-tier cut for the badge specifically).
  if (input.blast.score < 25) {
    severity = 'critical';
    reasons.push(`score ${input.blast.score}/100`);
  }

  // ── WARNING signals ───────────────────────────────────────────────────────
  // Only evaluated if not already critical. Critical wins.
  if (severity !== 'critical') {
    const liveWarn =
      input.forensicAgg.pii +
      input.forensicAgg.sensitiveFileRead +
      input.forensicAgg.pipeToShell +
      input.forensicAgg.longOutputRedacted;
    const histWarn = input.scanSignals
      ? input.scanSignals.pii +
        input.scanSignals.sensitiveFileRead +
        input.scanSignals.pipeToShell +
        input.scanSignals.longOutputRedacted
      : 0;
    const totalWarn = liveWarn + histWarn;
    if (totalWarn > 0) {
      severity = 'warning';
      reasons.push(`${totalWarn} forensic`);
    }
    if (input.blast.paths.length > 0) {
      severity = 'warning';
      reasons.push(`${input.blast.paths.length} paths`);
    }
    if (input.shieldStatus && input.shieldStatus.inactive.length > 0) {
      severity = 'warning';
      reasons.push(`${input.shieldStatus.inactive.length} shields off`);
    }
    if (input.blast.score >= 25 && input.blast.score < 50) {
      severity = 'warning';
      reasons.push(`score ${input.blast.score}/100`);
    }
  }

  // Render-budget cap — Header has limited horizontal real estate.
  const cappedReasons = reasons.slice(0, 3);

  return {
    severity,
    reasons: cappedReasons,
    hint: severity === 'secure' ? undefined : 'see node9 scan',
  };
}
