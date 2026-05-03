// @node9/policy-engine — severity classification & risk scoring.
//
// Single source of truth for "how bad is this?" used by:
//   - node9-proxy `scan --narrative` (local rule classification, by name)
//   - node9 SaaS Report (audit-log classification, by checkedBy + tool)
//
// Pure functions. No I/O. Stateless.

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
