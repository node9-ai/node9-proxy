// The OWASP table in the engine (packages/policy-engine/src/owasp.ts) must
// cover what the proxy emits: every posture category a finding can carry, and
// every scan-repo rule id. The engine cannot see those sources, so this test
// reads them from the proxy's own files. A new category or rule without a risk
// fails here, which is what keeps `node9 owasp` from printing an empty row.
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import {
  POSTURE_CATEGORY_OWASP,
  scanRepoRuleOwasp,
  SCAN_REPO_RULES_WITHOUT_RISK,
} from '@node9/policy-engine';
import { POSTURE_CHECKS } from '../posture';

const SRC = path.join(__dirname, '..');

function readDir(dir: string): string {
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.spec.ts') && !f.endsWith('.test.ts'))
    .map((f) => fs.readFileSync(path.join(dir, f), 'utf8'))
    .join('\n');
}

describe('OWASP mapping covers what the proxy emits', () => {
  it('every posture category, as declared and as written on a finding, has a risk', () => {
    for (const c of POSTURE_CHECKS)
      expect(POSTURE_CATEGORY_OWASP[c.category], c.category).toBeDefined();
    const source = readDir(path.join(SRC, 'posture'));
    const written = new Set([...source.matchAll(/category: '([A-Za-z ]+)'/g)].map((m) => m[1]));
    expect(written.size).toBeGreaterThan(10);
    for (const category of written)
      expect(POSTURE_CATEGORY_OWASP[category], `posture category "${category}"`).toBeDefined();
  });

  it('every scan-repo rule id has a risk or is listed as carrying none', () => {
    const source = readDir(path.join(SRC, 'ci-check'));
    const rules = new Set([...source.matchAll(/'(CI-\d+\.[a-z0-9.-]+)'/g)].map((m) => m[1]));
    // Script findings are `${rulePrefix}.${suffix}`; the prefixes are fixed.
    rules.add('CI-1.hook-script.any');
    rules.add('CI-6.skill-script.any');
    expect(rules.size).toBeGreaterThan(20);
    for (const rule of rules) {
      const risk = scanRepoRuleOwasp(rule);
      const exempt = SCAN_REPO_RULES_WITHOUT_RISK.some((p) => rule.startsWith(p));
      expect(risk !== undefined || exempt, `scan-repo rule "${rule}" has no OWASP risk`).toBe(true);
      expect(risk !== undefined && exempt, `"${rule}" is both mapped and exempt`).toBe(false);
    }
  });
});
