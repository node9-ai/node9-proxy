// @node9/policy-engine — severity classification & risk scoring.
//
// Single source of truth for "how bad is this?" used by:
//   - node9-proxy `scan --narrative` (local rule classification, by name)
//   - node9 SaaS Report (audit-log classification, by checkedBy + tool)
//
// Pure functions. No I/O. Stateless.

import { SCAN_SIGNAL_WEIGHTS, type ScanSignals } from '../scan';

export type Severity = 'critical' | 'high' | 'medium';

export type ScoreTier = 'good' | 'at-risk' | 'critical';

/**
 * Classify a rule by its name + verdict. Used by the proxy when scanning a
 * Claude Code session — the rule that matched is known by name.
 *
 * Tiers:
 *   - critical: irreversible damage or credential exfiltration
 *       (rm -rf $HOME, eval-of-remote, AWS/SSH/GCP credential reads,
 *       repo deletion, helm uninstall, drop-table, drop-database, flushall,
 *       curl | bash, pipe-shell)
 *   - high: significant damage, recoverable
 *       (force push, git reset --hard, rebase, branch deletion, all other
 *       block-verdict rules)
 *   - medium: workflow / cost risk, not security
 *       (rm review, sudo review, redis config-set, dynamic eval, all other
 *       review-verdict rules)
 */
export function classifyRuleSeverity(
  name: string,
  verdict: 'block' | 'review' | 'allow'
): Severity {
  const n = name.toLowerCase();

  const criticalPatterns = [
    'rm-rf',
    'eval-remote',
    'eval-curl',
    'read-aws',
    'read-ssh',
    'read-gcp',
    'read-cred',
    'delete-repo',
    'helm-uninstall',
    'drop-table',
    'drop-database',
    'drop-collection',
    'truncate',
    'flushall',
    'flushdb',
    'pipe-shell',
  ];
  if (criticalPatterns.some((p) => n.includes(p))) return 'critical';

  const highPatterns = [
    'force-push',
    'force_push',
    'git-destructive',
    'reset-hard',
    'rebase',
    'delete-branch',
    'delete-remote',
  ];
  if (highPatterns.some((p) => n.includes(p))) return 'high';

  if (verdict === 'block') return 'high';
  return 'medium';
}

/**
 * Map a rule slug to a friendly label suitable for narrative output.
 *
 *   "block-read-aws"                 → "AWS credentials read"
 *   "shield:k8s:block-helm-uninstall" → "helm uninstall"
 *   "review-force-push"              → "force pushes"
 *
 * Strips common prefixes (block-, review-, allow-, shield:..., org:) before
 * matching, so cloud-tagged rules ("org:block-read-aws") map the same way.
 */
export function narrativeRuleLabel(name: string): string {
  const stripped = stripRulePrefixes(name);
  const map: Record<string, string> = {
    'read-aws': 'AWS credentials read',
    'read-ssh': 'SSH private key read',
    'read-gcp': 'GCP credentials read',
    'read-cred': 'credential file read',
    'delete-repo': 'GitHub repository deletion',
    'helm-uninstall': 'helm uninstall',
    'rm-rf-home': 'rm -rf on home directory',
    'rm-rf': 'rm -rf',
    'eval-remote': 'eval of remote download',
    'eval-curl': 'eval of curl output',
    'pipe-shell': 'curl | bash',
    'drop-table': 'DROP TABLE',
    'drop-database': 'DROP DATABASE',
    'drop-collection': 'DROP COLLECTION',
    truncate: 'TRUNCATE',
    flushall: 'Redis FLUSHALL',
    flushdb: 'Redis FLUSHDB',
    'force-push': 'force pushes',
    force_push: 'force pushes',
    'reset-hard': 'git reset --hard',
    'git-destructive': 'destructive git operations',
    'delete-branch': 'branch deletion',
    'delete-remote': 'remote deletion',
    rebase: 'git rebase',
    rm: 'rm calls',
    sudo: 'sudo calls',
    'eval-dynamic': 'dynamic eval',
    'config-set': 'Redis CONFIG SET',
  };
  for (const [key, label] of Object.entries(map)) {
    if (stripped.includes(key)) return label;
  }
  return stripped;
}

/**
 * Strips known prefixes from a rule slug:
 *   - "org:" (cloud-pushed rule tag)
 *   - "shield:<scope>:" (e.g. "shield:k8s:")
 *   - "block-", "review-", "allow-" (verdict prefix)
 */
function stripRulePrefixes(name: string): string {
  let n = name.toLowerCase();
  if (n.startsWith('org:')) n = n.slice(4);
  // shield:scope:rest → rest
  const shieldMatch = /^shield:[^:]+:(.+)$/.exec(n);
  if (shieldMatch) n = shieldMatch[1];
  n = n.replace(/^(block|review|allow)-/, '');
  return n;
}

/**
 * Audit-log entry for backend classification. Mirrors the relevant subset of
 * AuditLog rows so backend code can pass them in without a Prisma dependency
 * here.
 */
export interface AuditEntryForClassify {
  checkedBy?: string | null;
  toolName: string;
  action: string;
  riskMetadata?: { ruleName?: string; dlpPattern?: string; [k: string]: unknown } | null;
}

/**
 * Classify a single audit-log entry by what fired and which tool ran. Used by
 * the SaaS /report endpoint to bucket audit events into severity tiers.
 *
 * Resolution order — first hit wins:
 *   1. riskMetadata.ruleName    → defer to classifyRuleSeverity (best signal)
 *   2. checkedBy === 'dlp-block' or starts with 'dlp-saas:' → critical
 *      (any credential leak is critical regardless of which pattern matched)
 *   3. checkedBy starts with 'eval-saas' or 'pipe-chain-saas:critical' → critical
 *   4. checkedBy === 'loop-detected' → medium (cost / workflow, not security)
 *   5. Block-status entries with no rule name → high (default for unattributed
 *      blocks; better than dropping the signal)
 *   6. Otherwise → null (allowed actions don't have a severity)
 */
export function classifyAuditEntry(entry: AuditEntryForClassify): Severity | null {
  const ruleName = entry.riskMetadata?.ruleName;
  if (typeof ruleName === 'string' && ruleName.length > 0) {
    const verdict =
      entry.action === 'AUTO_BLOCKED' || entry.action === 'DENIED'
        ? 'block'
        : entry.action === 'APPROVED' || entry.action === 'AUTO_ALLOWED'
          ? 'allow'
          : 'review';
    return classifyRuleSeverity(ruleName, verdict);
  }

  const cb = entry.checkedBy ?? '';
  if (cb === 'dlp-block' || cb.startsWith('dlp-saas:')) return 'critical';
  if (cb.startsWith('eval-saas') || cb === 'pipe-chain-saas:critical') {
    return 'critical';
  }
  if (cb === 'loop-detected') return 'medium';

  const isBlocked = entry.action === 'AUTO_BLOCKED' || entry.action === 'DENIED';
  if (isBlocked) return 'high';

  return null;
}

/**
 * Compute a 0-100 risk-posture score from severity counts + total events.
 *
 * Heuristic: each severity tier has a "cost" against a clean 100 score.
 * Critical findings deduct the most, medium the least. Counts are normalised
 * by total events so a workspace with 1 critical out of 10 events scores
 * worse than one with 1 critical out of 10,000 — exposure rate matters more
 * than absolute count.
 *
 * Tiers:
 *   - good     : score ≥ 80
 *   - at-risk  : 50 ≤ score < 80
 *   - critical : score < 50
 *
 * Empty workspaces (total === 0) score 100/good — no evidence of exposure
 * is the only honest answer.
 */
export function computeSecurityScore(opts: {
  critical: number;
  high: number;
  medium: number;
  total: number;
}): { score: number; tier: ScoreTier } {
  const { critical, high, medium, total } = opts;
  if (total === 0) return { score: 100, tier: 'good' };

  // Per-tier weights chosen so 1 critical / 100 events ≈ -30 (forces at-risk),
  // 5 highs / 100 ≈ -25, 20 mediums / 100 ≈ -20. Tuned so a "noisy but
  // mostly-medium" workspace lands in at-risk rather than critical.
  const criticalRate = critical / total;
  const highRate = high / total;
  const mediumRate = medium / total;

  const deduction =
    Math.min(criticalRate * 3000, 60) +
    Math.min(highRate * 500, 30) +
    Math.min(mediumRate * 100, 15);

  const score = Math.max(0, Math.min(100, Math.round(100 - deduction)));
  const tier: ScoreTier = score >= 80 ? 'good' : score >= 50 ? 'at-risk' : 'critical';
  return { score, tier };
}

// ---------------------------------------------------------------------------
// Scan-signal classification & blended scoring
// ---------------------------------------------------------------------------
//
// The proxy's forward-only scanner produces per-signal counts (see
// ScanSignals in ../scan). The SaaS Report blends these into the same
// 0-100 risk-posture score that audit-log findings drive, so users see
// one number — not a live score next to a separate "scan score" they
// have to reconcile.
//
// classifyScanSignal maps each signal key to a Severity tier using the
// existing SCAN_SIGNAL_WEIGHTS thresholds (≥25 critical, ≥11 high,
// otherwise medium). This matches the SessionsTab severity chips on the
// FE so a "Credentials" chip on a session row corresponds to the same
// "Critical" bucket on the Risk Posture card.

/**
 * Map a ScanSignals key to its severity tier. Uses the existing
 * SCAN_SIGNAL_WEIGHTS so adding a new scan signal type only requires
 * updating the weights table; classification follows automatically.
 *
 * Thresholds:
 *   - ≥ 25  → critical (dlp, pipeToShell, evalOfRemote, networkExfil)
 *   - ≥ 11  → high     (sensitiveFileReads, privilegeEscalation,
 *                       destructiveOps)
 *   - else  → medium   (piiFindings, loops, longOutputRedactions)
 */
export function classifyScanSignal(key: keyof ScanSignals): Severity {
  const w = SCAN_SIGNAL_WEIGHTS[key];
  if (w >= 25) return 'critical';
  if (w >= 11) return 'high';
  return 'medium';
}

/**
 * Compute a 0-100 risk-posture score that blends audit-log severity counts
 * with forward-only scan signal counts.
 *
 * Why this exists: the live audit log answers "what did the firewall block
 * in this window?" and the scan answers "what's sitting in past sessions?".
 * Both are real risk; surfacing them as two separate scores forced users
 * to reconcile two numbers. This function bins scan signals into the same
 * critical/high/medium buckets via classifyScanSignal, sums them with the
 * audit counts, and runs the existing computeSecurityScore math.
 *
 * Denominator handling: a workspace with zero audit traffic but non-zero
 * scan findings would otherwise hit the `total === 0` short-circuit and
 * return 100/good — a false-healthy reading. We add the scan contribution
 * to `total` so the rate-based math runs:
 *
 *   - If `scan.totalToolCalls` is provided, use it as the scan-side
 *     denominator (best signal — "1 finding per 10000 calls" should
 *     score better than "1 per 10").
 *   - Otherwise fall back to the count of scan findings, so a scan-only
 *     workspace with one credential leak resolves to 1/1 = 100% bad
 *     rate and lands in critical, not 0/0 = 100/good.
 *
 * Backwards compatible: calling with `audit` only and no `scan` produces
 * the exact same result as `computeSecurityScore(audit)`.
 */
export function computeBlendedSecurityScore(opts: {
  audit: { critical: number; high: number; medium: number; total: number };
  scan?: { signals: ScanSignals; totalToolCalls?: number };
}): { score: number; tier: ScoreTier } {
  const { audit, scan } = opts;

  let critical = audit.critical;
  let high = audit.high;
  let medium = audit.medium;
  let total = audit.total;

  if (scan) {
    let scanFindingSum = 0;
    for (const key of Object.keys(scan.signals) as Array<keyof ScanSignals>) {
      const count = scan.signals[key];
      if (count <= 0) continue;
      const tier = classifyScanSignal(key);
      if (tier === 'critical') critical += count;
      else if (tier === 'high') high += count;
      else medium += count;
      scanFindingSum += count;
    }
    // Use totalToolCalls when available (gives "rate of findings per call",
    // which is the metric the audit-side already uses). Fall back to the
    // finding count itself so we don't divide-by-zero in scan-only flows.
    const scanContribution = Math.max(scan.totalToolCalls ?? 0, scanFindingSum);
    total += scanContribution;
  }

  return computeSecurityScore({ critical, high, medium, total });
}
