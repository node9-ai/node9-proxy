// src/posture/score.ts
// Maps posture findings onto the SAME scoring function the SaaS Risk Posture
// uses (`computeSecurityScore`), so the posture score and the dashboard score
// are produced by one formula — no second number for users to reconcile.
//
// Advisory findings are shown but do NOT deduct (they're detect-only, e.g.
// "no container" — node9 can't fix them, so they don't lower node9's grade).

import { computeSecurityScore } from '@node9/policy-engine';
import type { Finding, Severity } from './types';

export function scorePosture(
  findings: Finding[],
  checksRun: number
): { score: number; tier: 'good' | 'at-risk' | 'critical' } {
  // Covered findings (node9 is already enforcing) and can't-fix advisories are
  // not OPEN risks — the score measures what's still open, not what's on disk.
  const open = findings.filter(
    (f) => f.coverage?.state !== 'covered' && f.coverage?.state !== 'cant-fix'
  );

  // Two scoring tracks, combined:
  //
  // 1. GENUINE EXPOSURES (open Secrets/Egress/Gate/Coverage…) → the existing
  //    severity-bucket formula, unchanged. Any critical still forces the
  //    critical tier; this is the well-tested behavior we must not regress.
  //    Hardening findings carry a scoreWeight and are excluded here so they're
  //    never double-counted.
  const count = (sev: Severity) => open.filter((f) => f.severity === sev && !f.scoreWeight).length;
  const base = computeSecurityScore({
    critical: count('critical'),
    high: count('high'),
    medium: count('medium'),
    total: Math.max(checksRun, 1),
  });

  // 2. HARDENING OPPORTUNITIES node9 offers but the bucket formula ignores
  //    (Isolation → sandbox, an exposed DB → db-shields). Each deducts a fixed
  //    weight while open, so a fully-covered-but-unsandboxed host reads ~84
  //    (headroom you choose to close), not a contradictory 100.
  const headroom = open.reduce((sum, f) => sum + (f.scoreWeight ?? 0), 0);

  const score = Math.max(0, base.score - headroom);
  const tier: 'good' | 'at-risk' | 'critical' =
    score >= 80 ? 'good' : score >= 50 ? 'at-risk' : 'critical';
  return { score, tier };
}

/** Total open hardening headroom (Σ scoreWeight) — the "N pts you can close"
 *  the renderer shows under the score. Exported so the render + tests share it. */
export function openHeadroom(findings: Finding[]): number {
  return findings
    .filter((f) => f.coverage?.state !== 'covered' && f.coverage?.state !== 'cant-fix')
    .reduce((sum, f) => sum + (f.scoreWeight ?? 0), 0);
}
