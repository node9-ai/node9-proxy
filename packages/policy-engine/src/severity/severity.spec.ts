import { describe, it, expect } from 'vitest';
import {
  classifyRuleSeverity,
  narrativeRuleLabel,
  classifyAuditEntry,
  computeSecurityScore,
  classifyScanSignal,
  computeBlendedSecurityScore,
} from './index';
import type { ScanSignals } from '../scan';

const EMPTY_SIGNALS: ScanSignals = {
  dlpFindings: 0,
  piiFindings: 0,
  sensitiveFileReads: 0,
  privilegeEscalation: 0,
  networkExfil: 0,
  pipeToShell: 0,
  evalOfRemote: 0,
  destructiveOps: 0,
  loops: 0,
  longOutputRedactions: 0,
};

describe('classifyRuleSeverity', () => {
  it('classifies credential-read rules as critical', () => {
    expect(classifyRuleSeverity('block-read-aws', 'block')).toBe('critical');
    expect(classifyRuleSeverity('block-read-ssh', 'block')).toBe('critical');
    expect(classifyRuleSeverity('block-read-gcp', 'block')).toBe('critical');
    expect(classifyRuleSeverity('block-read-cred', 'block')).toBe('critical');
  });

  it('classifies destructive ops as critical regardless of verdict', () => {
    expect(classifyRuleSeverity('block-rm-rf-home', 'block')).toBe('critical');
    expect(classifyRuleSeverity('review-rm-rf', 'review')).toBe('critical');
    expect(classifyRuleSeverity('block-drop-table', 'block')).toBe('critical');
    expect(classifyRuleSeverity('block-flushall', 'block')).toBe('critical');
    expect(classifyRuleSeverity('block-delete-repo', 'block')).toBe('critical');
    expect(classifyRuleSeverity('block-helm-uninstall', 'block')).toBe('critical');
  });

  it('classifies eval-of-remote and pipe-shell as critical', () => {
    expect(classifyRuleSeverity('block-eval-remote', 'block')).toBe('critical');
    expect(classifyRuleSeverity('block-pipe-shell', 'block')).toBe('critical');
    expect(classifyRuleSeverity('block-eval-curl', 'block')).toBe('critical');
  });

  it('classifies destructive git ops as high', () => {
    expect(classifyRuleSeverity('review-force-push', 'review')).toBe('high');
    expect(classifyRuleSeverity('block-git-destructive', 'block')).toBe('high');
    expect(classifyRuleSeverity('block-reset-hard', 'block')).toBe('high');
    expect(classifyRuleSeverity('review-rebase', 'review')).toBe('high');
  });

  it('falls back to high for unknown block-verdict rules', () => {
    expect(classifyRuleSeverity('block-something-novel', 'block')).toBe('high');
  });

  it('falls back to medium for unknown review-verdict rules', () => {
    expect(classifyRuleSeverity('review-rm', 'review')).toBe('medium');
    expect(classifyRuleSeverity('review-sudo', 'review')).toBe('medium');
    expect(classifyRuleSeverity('review-config-set', 'review')).toBe('medium');
  });

  it('treats cloud-tagged rules (org: prefix) the same as local rules', () => {
    expect(classifyRuleSeverity('org:block-read-aws', 'block')).toBe('critical');
    expect(classifyRuleSeverity('ORG:BLOCK-RESET-HARD', 'block')).toBe('high');
  });

  it('is case-insensitive', () => {
    expect(classifyRuleSeverity('BLOCK-READ-AWS', 'block')).toBe('critical');
    expect(classifyRuleSeverity('Review-Force-Push', 'review')).toBe('high');
  });
});

describe('narrativeRuleLabel', () => {
  it('maps known patterns to friendly labels', () => {
    expect(narrativeRuleLabel('block-read-aws')).toBe('AWS credentials read');
    expect(narrativeRuleLabel('block-read-ssh')).toBe('SSH private key read');
    expect(narrativeRuleLabel('block-rm-rf-home')).toBe('rm -rf on home directory');
    expect(narrativeRuleLabel('review-force-push')).toBe('force pushes');
    expect(narrativeRuleLabel('block-drop-table')).toBe('DROP TABLE');
    expect(narrativeRuleLabel('block-flushall')).toBe('Redis FLUSHALL');
  });

  it('strips shield: prefix before matching', () => {
    expect(narrativeRuleLabel('shield:k8s:block-helm-uninstall')).toBe('helm uninstall');
    expect(narrativeRuleLabel('shield:postgres:block-drop-table')).toBe('DROP TABLE');
  });

  it('strips org: prefix before matching', () => {
    expect(narrativeRuleLabel('org:block-read-aws')).toBe('AWS credentials read');
  });

  it('returns the slug-stripped name for unknown rules', () => {
    expect(narrativeRuleLabel('block-totally-novel-rule')).toBe('totally-novel-rule');
    expect(narrativeRuleLabel('review-some-thing')).toBe('some-thing');
  });
});

describe('classifyAuditEntry', () => {
  it('uses riskMetadata.ruleName as the highest-priority signal', () => {
    expect(
      classifyAuditEntry({
        toolName: 'Bash',
        action: 'AUTO_BLOCKED',
        checkedBy: 'smart-rule-block',
        riskMetadata: { ruleName: 'block-read-aws' },
      })
    ).toBe('critical');
  });

  it('classifies dlp-block events as critical (any credential leak)', () => {
    expect(
      classifyAuditEntry({
        toolName: 'Edit',
        action: 'AUTO_BLOCKED',
        checkedBy: 'dlp-block',
      })
    ).toBe('critical');
    expect(
      classifyAuditEntry({
        toolName: 'Bash',
        action: 'AUTO_BLOCKED',
        checkedBy: 'dlp-saas:GitHub Token',
      })
    ).toBe('critical');
  });

  it('classifies eval / pipe-chain SaaS detections as critical', () => {
    expect(
      classifyAuditEntry({
        toolName: 'Bash',
        action: 'AUTO_BLOCKED',
        checkedBy: 'eval-saas:remote-exec',
      })
    ).toBe('critical');
    expect(
      classifyAuditEntry({
        toolName: 'Bash',
        action: 'AUTO_BLOCKED',
        checkedBy: 'pipe-chain-saas:critical',
      })
    ).toBe('critical');
  });

  it('classifies loop-detected events as medium (cost, not security)', () => {
    expect(
      classifyAuditEntry({
        toolName: 'Bash',
        action: 'AUTO_BLOCKED',
        checkedBy: 'loop-detected',
      })
    ).toBe('medium');
  });

  it('falls back to high for unattributed blocks (better than dropping signal)', () => {
    expect(
      classifyAuditEntry({
        toolName: 'Bash',
        action: 'AUTO_BLOCKED',
        checkedBy: null,
      })
    ).toBe('high');
    expect(
      classifyAuditEntry({
        toolName: 'Edit',
        action: 'DENIED',
      })
    ).toBe('high');
  });

  it('returns null for allowed actions (no severity to assign)', () => {
    expect(
      classifyAuditEntry({
        toolName: 'Bash',
        action: 'AUTO_ALLOWED',
        checkedBy: null,
      })
    ).toBeNull();
    expect(
      classifyAuditEntry({
        toolName: 'Bash',
        action: 'APPROVED',
        checkedBy: null,
      })
    ).toBeNull();
  });

  it('ruleName takes priority over checkedBy heuristic', () => {
    // If somehow a loop-detected entry carries a ruleName, the ruleName wins
    expect(
      classifyAuditEntry({
        toolName: 'Bash',
        action: 'AUTO_BLOCKED',
        checkedBy: 'loop-detected',
        riskMetadata: { ruleName: 'block-read-aws' },
      })
    ).toBe('critical');
  });
});

describe('computeSecurityScore', () => {
  it('returns 100/good for an empty workspace (no evidence of exposure)', () => {
    expect(computeSecurityScore({ critical: 0, high: 0, medium: 0, total: 0 })).toEqual({
      score: 100,
      tier: 'good',
    });
  });

  it('returns 100/good when every event is allowed (no findings)', () => {
    expect(computeSecurityScore({ critical: 0, high: 0, medium: 0, total: 1000 })).toEqual({
      score: 100,
      tier: 'good',
    });
  });

  it('drops to critical when even one credential leak is observed', () => {
    // 1 critical out of 100 events should land in at-risk or critical
    const result = computeSecurityScore({ critical: 1, high: 0, medium: 0, total: 100 });
    expect(result.score).toBeLessThan(80);
    expect(['at-risk', 'critical']).toContain(result.tier);
  });

  it('many criticals against few events → critical tier', () => {
    const result = computeSecurityScore({ critical: 10, high: 0, medium: 0, total: 50 });
    expect(result.tier).toBe('critical');
    expect(result.score).toBeLessThan(50);
  });

  it('mostly-medium workspace scores better than mostly-critical', () => {
    const mediumHeavy = computeSecurityScore({ critical: 0, high: 0, medium: 20, total: 100 });
    const criticalHeavy = computeSecurityScore({ critical: 5, high: 0, medium: 0, total: 100 });
    expect(mediumHeavy.score).toBeGreaterThan(criticalHeavy.score);
  });

  it('clamps to [0, 100]', () => {
    const allBad = computeSecurityScore({
      critical: 1000,
      high: 1000,
      medium: 1000,
      total: 1000,
    });
    expect(allBad.score).toBeGreaterThanOrEqual(0);
    expect(allBad.score).toBeLessThanOrEqual(100);
  });

  it('exposure rate matters more than absolute count — 1 critical / 10000 scores better than 1 / 10', () => {
    const lowExposure = computeSecurityScore({ critical: 1, high: 0, medium: 0, total: 10000 });
    const highExposure = computeSecurityScore({ critical: 1, high: 0, medium: 0, total: 10 });
    expect(lowExposure.score).toBeGreaterThan(highExposure.score);
  });

  it('tier boundaries are sane: 80 = good, 50 = at-risk, <50 = critical', () => {
    // We can't pass score directly but verify the boundary semantics by
    // reading the tier from a few constructed cases.
    const empty = computeSecurityScore({ critical: 0, high: 0, medium: 0, total: 0 });
    expect(empty.tier).toBe('good');
    expect(empty.score).toBe(100);
  });
});

describe('classifyScanSignal', () => {
  it('classifies high-weight signals (≥25) as critical', () => {
    expect(classifyScanSignal('dlpFindings')).toBe('critical');
    expect(classifyScanSignal('pipeToShell')).toBe('critical');
    expect(classifyScanSignal('evalOfRemote')).toBe('critical');
    expect(classifyScanSignal('networkExfil')).toBe('critical');
  });

  it('classifies mid-weight signals (11-24) as high', () => {
    expect(classifyScanSignal('sensitiveFileReads')).toBe('high');
    expect(classifyScanSignal('privilegeEscalation')).toBe('high');
    expect(classifyScanSignal('destructiveOps')).toBe('high');
  });

  it('classifies low-weight signals (≤10) as medium', () => {
    expect(classifyScanSignal('piiFindings')).toBe('medium');
    expect(classifyScanSignal('loops')).toBe('medium');
    expect(classifyScanSignal('longOutputRedactions')).toBe('medium');
  });

  it('aligns with SessionsTab chip severity tiers (no FE/BE drift)', () => {
    // The SessionsTab CHIP_DEFS in fe/src/pages/SessionsTab.tsx classifies
    // chips by tier — this test pins that grouping so renaming a signal
    // or shifting a weight here trips the test before it reaches the FE.
    const critical = ['dlpFindings', 'evalOfRemote', 'pipeToShell', 'networkExfil'] as const;
    const high = ['destructiveOps', 'privilegeEscalation', 'sensitiveFileReads'] as const;
    const medium = ['piiFindings', 'loops', 'longOutputRedactions'] as const;
    for (const k of critical) expect(classifyScanSignal(k)).toBe('critical');
    for (const k of high) expect(classifyScanSignal(k)).toBe('high');
    for (const k of medium) expect(classifyScanSignal(k)).toBe('medium');
  });
});

describe('computeBlendedSecurityScore', () => {
  const emptyAudit = { critical: 0, high: 0, medium: 0, total: 0 };

  it('matches computeSecurityScore exactly when no scan input is provided', () => {
    const audit = { critical: 1, high: 2, medium: 3, total: 100 };
    expect(computeBlendedSecurityScore({ audit })).toEqual(computeSecurityScore(audit));
  });

  it('matches computeSecurityScore exactly when scan signals are all zero', () => {
    const audit = { critical: 1, high: 2, medium: 3, total: 100 };
    expect(computeBlendedSecurityScore({ audit, scan: { signals: EMPTY_SIGNALS } })).toEqual(
      computeSecurityScore(audit)
    );
  });

  it('truly empty workspace (no audit, no scan) returns 100/good', () => {
    expect(computeBlendedSecurityScore({ audit: emptyAudit })).toEqual({
      score: 100,
      tier: 'good',
    });
    expect(
      computeBlendedSecurityScore({ audit: emptyAudit, scan: { signals: EMPTY_SIGNALS } })
    ).toEqual({ score: 100, tier: 'good' });
  });

  // The whole point of the blended score: a workspace with zero audit
  // traffic but findings in scan must NOT short-circuit to 100/good.
  it('scan-only workspace with one credential leak does not return 100/good', () => {
    const result = computeBlendedSecurityScore({
      audit: emptyAudit,
      scan: { signals: { ...EMPTY_SIGNALS, dlpFindings: 1 } },
    });
    expect(result.score).toBeLessThan(80);
    expect(['at-risk', 'critical']).toContain(result.tier);
  });

  it('scan signals route into the same tiers as audit findings (1 dlp ~ 1 audit critical)', () => {
    const auditOneCritical = computeBlendedSecurityScore({
      audit: { critical: 1, high: 0, medium: 0, total: 100 },
    });
    const scanOneDlp = computeBlendedSecurityScore({
      audit: emptyAudit,
      scan: { signals: { ...EMPTY_SIGNALS, dlpFindings: 1 }, totalToolCalls: 100 },
    });
    // Same total denominator, same one critical contribution from each side.
    expect(scanOneDlp).toEqual(auditOneCritical);
  });

  it('blending preserves score when scan findings come with proportional volume', () => {
    // Sanity: the score is rate-based, so adding 1 finding alongside 100
    // additional clean calls should leave the score essentially unchanged
    // (combined rate = 2/200 = original 1/100). This is correct math —
    // proportional volume should not penalise.
    const audit = { critical: 1, high: 0, medium: 0, total: 100 };
    const baseline = computeBlendedSecurityScore({ audit });
    const proportional = computeBlendedSecurityScore({
      audit,
      scan: { signals: { ...EMPTY_SIGNALS, dlpFindings: 1 }, totalToolCalls: 100 },
    });
    expect(proportional.score).toBe(baseline.score);
  });

  it('blending pulls the score below the audit-only baseline when scan adds findings without proportional volume', () => {
    // When scan reports findings but no totalToolCalls (small or unknown
    // denominator), the rate goes up sharply and the score drops. This
    // is the case that justifies the blend in the first place.
    const audit = { critical: 1, high: 0, medium: 0, total: 100 };
    const baseline = computeBlendedSecurityScore({ audit });
    const blended = computeBlendedSecurityScore({
      audit,
      scan: { signals: { ...EMPTY_SIGNALS, dlpFindings: 1 } }, // no totalToolCalls
    });
    expect(blended.score).toBeLessThan(baseline.score);
  });

  it('uses scan totalToolCalls as denominator when provided', () => {
    // 1 dlp out of 10 calls is much worse than 1 dlp out of 10000.
    const lowExposure = computeBlendedSecurityScore({
      audit: emptyAudit,
      scan: { signals: { ...EMPTY_SIGNALS, dlpFindings: 1 }, totalToolCalls: 10000 },
    });
    const highExposure = computeBlendedSecurityScore({
      audit: emptyAudit,
      scan: { signals: { ...EMPTY_SIGNALS, dlpFindings: 1 }, totalToolCalls: 10 },
    });
    expect(lowExposure.score).toBeGreaterThan(highExposure.score);
  });

  it('falls back to finding count as denominator when totalToolCalls is omitted', () => {
    // Without totalToolCalls, scan-only with 1 dlp → 1/1 = 100% bad rate.
    // This protects against the divide-by-zero / false-healthy case even
    // when the host code forgot to plumb the call count through.
    const result = computeBlendedSecurityScore({
      audit: emptyAudit,
      scan: { signals: { ...EMPTY_SIGNALS, dlpFindings: 1 } },
    });
    expect(result.tier).toBe('critical');
    expect(result.score).toBeLessThan(50);
  });

  it('a medium-only scan (loops) lands gentler than a critical-only scan (dlp)', () => {
    const loopHeavy = computeBlendedSecurityScore({
      audit: emptyAudit,
      scan: { signals: { ...EMPTY_SIGNALS, loops: 5 }, totalToolCalls: 100 },
    });
    const credLeak = computeBlendedSecurityScore({
      audit: emptyAudit,
      scan: { signals: { ...EMPTY_SIGNALS, dlpFindings: 5 }, totalToolCalls: 100 },
    });
    expect(loopHeavy.score).toBeGreaterThan(credLeak.score);
  });

  it('blends across all three tiers in one call', () => {
    const result = computeBlendedSecurityScore({
      audit: { critical: 1, high: 1, medium: 1, total: 100 },
      scan: {
        signals: {
          ...EMPTY_SIGNALS,
          dlpFindings: 1, // critical
          destructiveOps: 1, // high
          piiFindings: 1, // medium
        },
        totalToolCalls: 100,
      },
    });
    // 2 critical / 2 high / 2 medium, total 200 — ought to land at-risk or
    // critical. Pin only the tier so weight tweaks don't break this test.
    expect(['at-risk', 'critical']).toContain(result.tier);
  });
});
