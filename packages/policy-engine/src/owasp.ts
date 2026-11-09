// The OWASP Top 10 for Agentic Applications (published 2025-12-09), and the
// risk each thing node9 reports falls under. One table, read by the catalog
// (`CheckDef.owasp`), by posture and by scan-repo, so the local report, the
// dashboard and the benchmark name the same risk for the same harm.
//
// Rules (node9Firewall#320, phase 1, agreed 2026-11-02):
//   - every check names exactly one primary risk; context (a tainted session,
//     content read earlier) may add ASI01 at report time, never here;
//   - the risk is the harm the check prevents, not the mechanism that catches
//     it, so a pack row and the product check it mirrors share a risk;
//   - the table agrees with the benchmark's rule (agentverdict,
//     src/scope/owasp.ts), which maps a case by its channel: secrets ASI03,
//     personal data, egress, shell and MCP actions ASI02, packages ASI04,
//     instructions in content ASI01, dangerous actions that need a person's
//     approval ASI09, code from outside ASI05. owasp.spec.ts pins that.

export const ASI = {
  ASI01: 'Agent Goal Hijack',
  ASI02: 'Tool Misuse and Exploitation',
  ASI03: 'Identity and Privilege Abuse',
  ASI04: 'Agentic Supply Chain Vulnerabilities',
  ASI05: 'Unexpected Code Execution',
  ASI06: 'Memory and Context Poisoning',
  ASI07: 'Insecure Inter-Agent Communication',
  ASI08: 'Cascading Failures',
  ASI09: 'Human-Agent Trust Exploitation',
  ASI10: 'Rogue Agents',
} as const;

export type AsiId = keyof typeof ASI;

export const ASI_IDS: readonly AsiId[] = Object.keys(ASI) as AsiId[];

export function isAsiId(v: unknown): v is AsiId {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(ASI, v);
}

// ── Pack rows ─────────────────────────────────────────────────────────────────
//
// A pack row is `packs.<shield>.<rule>`. The shield decides the risk, a few
// rules override it: a payment or identity app asks a person before money or
// access moves (ASI09, the human-in-the-loop control the benchmark's
// dangerous-actions test measures); an infrastructure shield stops a
// destructive command (ASI02); bash-safe's download-and-run rules are code
// execution (ASI05); a permission change is privilege (ASI03).

const PACK_SHIELD_OWASP: Readonly<Record<string, AsiId>> = {
  aws: 'ASI02',
  'bash-safe': 'ASI02',
  docker: 'ASI02',
  filesystem: 'ASI02',
  github: 'ASI02',
  k8s: 'ASI02',
  mongodb: 'ASI02',
  postgres: 'ASI02',
  redis: 'ASI02',
  stripe: 'ASI09',
  paypal: 'ASI09',
  square: 'ASI09',
  plaid: 'ASI09',
  okta: 'ASI09',
  auth0: 'ASI09',
};

const PACK_RULE_OWASP: Readonly<Record<string, AsiId>> = {
  'packs.bash-safe.pipe-to-shell': 'ASI05',
  'packs.bash-safe.obfuscated-exec': 'ASI05',
  'packs.bash-safe.eval-remote': 'ASI05',
  'packs.bash-safe.eval-dynamic': 'ASI05',
  'packs.aws.iam-changes': 'ASI03',
  'packs.postgres.grant-revoke': 'ASI03',
};

/** The risk of a pack row, or undefined for a shield this table does not
 *  know. The catalog refuses to build a row without a risk, so a new shield
 *  cannot ship unmapped. */
export function packRowOwasp(id: string, shield: string): AsiId | undefined {
  return PACK_RULE_OWASP[id] ?? PACK_SHIELD_OWASP[shield];
}

// ── Posture ───────────────────────────────────────────────────────────────────
//
// Every category a posture finding carries (src/posture in the proxy). A
// finding says what is exposed now; its risk is the harm an agent could do
// through that exposure. Coverage (node9 not wired, or recording only) is the
// guard itself being off, which is what ASI10 names.

export const POSTURE_CATEGORY_OWASP: Readonly<Record<string, AsiId>> = {
  Secrets: 'ASI03',
  Data: 'ASI03',
  Privilege: 'ASI03',
  Egress: 'ASI02',
  'Approval gate': 'ASI02',
  'Agent permissions': 'ASI02',
  'Tool governance': 'ASI02',
  Files: 'ASI02',
  Inbound: 'ASI02',
  'Agent inbound': 'ASI02',
  'Network exposure': 'ASI02',
  'Supply chain': 'ASI04',
  'Instruction files': 'ASI06',
  'Outside content': 'ASI01',
  'Agent-to-agent': 'ASI07',
  Isolation: 'ASI05',
  Approvals: 'ASI09',
  Cost: 'ASI08',
  Coverage: 'ASI10',
};

export function postureCategoryOwasp(category: string): AsiId | undefined {
  return POSTURE_CATEGORY_OWASP[category];
}

// ── scan-repo ─────────────────────────────────────────────────────────────────
//
// A scan-repo finding carries a rule id `CI-<n>.<name>`; script findings add
// a suffix (`CI-1.hook-script.<what>`, `CI-6.skill-script.<what>`). The risk
// follows the rule, the longest matching prefix wins. CI-0 rows are about the
// suppression comments themselves, not a risk, and stay unmapped on purpose.

const SCAN_REPO_RULE_OWASP: readonly (readonly [prefix: string, risk: AsiId])[] = [
  // CI-1: tool rules and hooks in agent config
  ['CI-1.broad-allow', 'ASI02'],
  ['CI-1.exec-escape-grant', 'ASI02'],
  ['CI-1.allow-rule-credential', 'ASI03'],
  ['CI-1.local-settings-committed', 'ASI02'],
  ['CI-1.codex-unsafe-defaults', 'ASI02'],
  ['CI-1.skill-allowed-tools', 'ASI02'],
  ['CI-1.skill-untrusted-input', 'ASI01'],
  ['CI-1.hook-remote-code', 'ASI05'],
  ['CI-1.hook-script', 'ASI05'],
  ['CI-1.unfollowable-symlink', 'ASI04'],
  // CI-2: workflows that run agents on outside content
  ['CI-2.', 'ASI01'],
  // CI-3: MCP servers and plugins
  ['CI-3.mcp-inline-credential', 'ASI03'],
  ['CI-3.mcp-unpinned', 'ASI04'],
  ['CI-3.plugin-unpinned', 'ASI04'],
  // CI-4: secrets an agent step can reach
  ['CI-4.', 'ASI03'],
  // CI-6: instruction files and skills
  ['CI-6.skill-script', 'ASI05'],
  ['CI-6.', 'ASI06'],
];

/** Rule prefixes that carry no risk of their own (listed so a test can tell
 *  "unmapped on purpose" from "forgotten"). */
export const SCAN_REPO_RULES_WITHOUT_RISK: readonly string[] = ['CI-0.'];

export function scanRepoRuleOwasp(rule: string): AsiId | undefined {
  let best: readonly [string, AsiId] | undefined;
  for (const entry of SCAN_REPO_RULE_OWASP) {
    if (rule === entry[0] || rule.startsWith(entry[0])) {
      if (!best || entry[0].length > best[0].length) best = entry;
    }
  }
  return best?.[1];
}
