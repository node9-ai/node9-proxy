/**
 * Unit tests for buildRuleSources() — the function that picks which
 * smart rules the scan pipeline applies to history.
 *
 * Locked behavior (2026-05-12 scan-redesign decision):
 *   Scan is a pre-install forecast. It must reflect what node9 catches
 *   OUT OF THE BOX — defaults + shield rules — and nothing else.
 *   Specifically:
 *     1. User-custom rules from ~/.node9/config.json are excluded
 *     2. Cloud-synced rules (cloud:* prefix) are excluded
 *     3. User-modified defaults still resolve to the CANONICAL default
 *        (we source from DEFAULT_CONFIG, not the merged getConfig() result)
 *
 * If these guarantees regress, the scan output silently starts showing
 * either a user's customizations or completely misleading "Your Rules"
 * sections that would never exist for a fresh user.
 */
import { describe, it, expect } from 'vitest';
import { buildRuleSources } from '../cli/commands/scan';
import { DEFAULT_CONFIG } from '../config';

describe('buildRuleSources', () => {
  it('returns only default-source + shield-source rules — no user, no cloud', () => {
    const sources = buildRuleSources();
    for (const s of sources) {
      expect(s.sourceType).not.toBe('user');
      // RuleSourceType has 'default' | 'shield' | 'user'; cloud rules
      // would be tagged 'user' by the old code with shieldName='cloud',
      // so the check above also catches them. Belt and braces:
      expect(s.shieldName).not.toBe('cloud');
      expect(s.shieldName).not.toBe('custom');
    }
  });

  it('includes every non-shield default rule from DEFAULT_CONFIG', () => {
    const sources = buildRuleSources();
    const defaultRuleNames = new Set(
      sources.filter((s) => s.sourceType === 'default').map((s) => s.rule.name)
    );
    const expected = DEFAULT_CONFIG.policy.smartRules
      .map((r) => r.name)
      .filter((n): n is string => typeof n === 'string' && !n.startsWith('shield:'));
    for (const name of expected) {
      expect(defaultRuleNames.has(name)).toBe(true);
    }
  });

  it('uses the canonical DEFAULT_CONFIG rule body, not a user-merged override', () => {
    // Pick any default rule by name, find it in both DEFAULT_CONFIG and
    // the scan sources, assert they're the same object reference. This
    // proves the source code reads DEFAULT_CONFIG directly rather than
    // routing through getConfig() (which would clone + merge).
    const sources = buildRuleSources();
    const someDefault = DEFAULT_CONFIG.policy.smartRules.find(
      (r) => r.name && !r.name.startsWith('shield:')
    );
    expect(someDefault).toBeDefined();
    const found = sources.find((s) => s.rule.name === someDefault!.name);
    expect(found).toBeDefined();
    expect(found!.rule).toBe(someDefault); // same reference, not clone
  });

  it('produces shield-source rules from every builtin shield', () => {
    const sources = buildRuleSources();
    const shieldNames = new Set(
      sources.filter((s) => s.sourceType === 'shield').map((s) => s.shieldName)
    );
    // Sanity-check a few builtins we know ship (regex bypass fixes
    // landed in earlier commits this session — these shields exist).
    expect(shieldNames.has('project-jail')).toBe(true);
    expect(shieldNames.has('bash-safe')).toBe(true);
    expect(shieldNames.has('filesystem')).toBe(true);
  });
});
