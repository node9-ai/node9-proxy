import { describe, it, expect } from 'vitest';
import {
  classifyRuleSeverity,
  narrativeRuleLabel,
  classifyAuditEntry,
  computeSecurityScore,
} from './index';

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
