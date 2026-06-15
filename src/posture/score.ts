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
  const count = (sev: Severity) => findings.filter((f) => f.severity === sev).length;
  return computeSecurityScore({
    critical: count('critical'),
    high: count('high'),
    medium: count('medium'),
    // Denominator = number of checks evaluated. With computeSecurityScore's
    // caps this makes any critical → critical tier, any high → at-risk, and a
    // fully clean run (0 findings, checksRun > 0) → 100/good.
    total: Math.max(checksRun, 1),
  });
}
