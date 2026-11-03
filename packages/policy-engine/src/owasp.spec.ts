// The OWASP mapping is one table for three readers (catalog, posture,
// scan-repo) and it must agree with the benchmark's rule, or `node9 owasp`
// and the published per-risk numbers would name different risks for the same
// harm. These tests pin: every check carries a valid risk, the risk names are
// the benchmark's, and each benchmark channel lands on the risk the checks
// that catch it carry.
import { describe, it, expect } from 'vitest';
import { CHECKS, CHECK_BY_ID } from './catalog';
import {
  ASI,
  ASI_IDS,
  isAsiId,
  packRowOwasp,
  POSTURE_CATEGORY_OWASP,
  postureCategoryOwasp,
  scanRepoRuleOwasp,
  SCAN_REPO_RULES_WITHOUT_RISK,
  type AsiId,
} from './owasp';

describe('OWASP risk on every check', () => {
  it('every catalog row names one of the ten risks', () => {
    expect(CHECKS.length).toBeGreaterThan(0);
    for (const c of CHECKS) expect(isAsiId(c.owasp), `${c.id}: ${String(c.owasp)}`).toBe(true);
  });

  it('the ten risks are the official list, in the benchmark spelling', () => {
    // Copied from agentverdict src/scope/owasp.ts; a change there is a change here.
    expect(ASI).toEqual({
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
    });
    expect(ASI_IDS).toHaveLength(10);
    expect(isAsiId('ASI11')).toBe(false);
    expect(isAsiId('asi01')).toBe(false);
  });

  it('agrees with the benchmark channel rule for the checks that catch each channel', () => {
    // agentverdict src/scope/owasp.ts, BY_CHANNEL. A benchmark case is judged
    // by one of these checks; the case's risk and the check's risk must match.
    const byChannel: Record<string, { risk: AsiId; checks: string[] }> = {
      secrets: {
        risk: 'ASI03',
        checks: [
          'data.secrets',
          'data.secrets-weak',
          'data.credential-files',
          'data.credential-files-other',
          'data.credential-files-unknown',
          'data.pipe-chain',
          'data.pipe-chain-obfuscated',
          'data.env-exfil',
          'data.prompt-secrets',
          'data.output-secrets',
          'data.canary',
        ],
      },
      pii: { risk: 'ASI02', checks: ['data.pii'] },
      egress: {
        risk: 'ASI02',
        checks: ['network.unknown-host', 'network.internal-addresses', 'network.metadata'],
      },
      shell: {
        risk: 'ASI02',
        checks: [
          'commands.rm',
          'commands.rm-home',
          'commands.chmod',
          'commands.git-destructive',
          'commands.sql-ddl',
          'commands.sql-no-where',
          'commands.disk-destroy',
          'commands.dangerous-word',
        ],
      },
      package: { risk: 'ASI04', checks: ['loading.malicious-package', 'loading.unknown-registry'] },
      injection: {
        risk: 'ASI01',
        checks: [
          'behavior.prompt-injection',
          'behavior.session-taint',
          'behavior.untrusted-content',
          'network.taint-egress',
        ],
      },
    };
    for (const [channel, { risk, checks }] of Object.entries(byChannel)) {
      for (const id of checks) {
        const def = CHECK_BY_ID.get(id);
        expect(def, `${channel}: ${id} is not in the catalog`).toBeDefined();
        expect(def!.owasp, `${channel}: ${id}`).toBe(risk);
      }
    }
  });

  it('code from outside is ASI05, approval-gated actions ASI09, the guard itself ASI10', () => {
    for (const id of [
      'commands.curl-pipe-shell',
      'commands.eval-remote',
      'commands.eval-dynamic',
      'commands.inline-exec',
      'commands.reverse-shell',
      'commands.temp-binary',
    ])
      expect(CHECK_BY_ID.get(id)!.owasp, id).toBe('ASI05');
    for (const c of CHECKS.filter((x) => x.group === 'actions'))
      expect(c.owasp, c.id).toBe('ASI09');
    for (const id of ['commands.node9-disarm', 'commands.git-hooks-bypass'])
      expect(CHECK_BY_ID.get(id)!.owasp, id).toBe('ASI10');
    expect(CHECK_BY_ID.get('files.agent-instructions')!.owasp).toBe('ASI06');
    expect(CHECK_BY_ID.get('behavior.loops')!.owasp).toBe('ASI08');
  });

  it('every risk with a check today is covered; ASI07 has none and says so', () => {
    const covered = new Set(CHECKS.map((c) => c.owasp));
    for (const id of ASI_IDS.filter((x) => x !== 'ASI07')) expect(covered.has(id), id).toBe(true);
    expect(covered.has('ASI07')).toBe(false);
  });
});

describe('pack rows', () => {
  it('payment and identity apps are the human-approval control, infrastructure shields are tool misuse', () => {
    const rows = CHECKS.filter((c) => c.pack);
    expect(rows.length).toBeGreaterThan(0);
    for (const c of rows) {
      if (['stripe', 'paypal', 'square', 'plaid', 'okta', 'auth0'].includes(c.pack!))
        expect(c.owasp, c.id).toBe('ASI09');
      if (['docker', 'k8s', 'mongodb', 'redis', 'github', 'filesystem'].includes(c.pack!))
        expect(c.owasp, c.id).toBe('ASI02');
    }
    expect(CHECK_BY_ID.get('packs.bash-safe.pipe-to-shell')!.owasp).toBe('ASI05');
    expect(CHECK_BY_ID.get('packs.bash-safe.rm-root')!.owasp).toBe('ASI02');
    expect(CHECK_BY_ID.get('packs.aws.iam-changes')!.owasp).toBe('ASI03');
    expect(CHECK_BY_ID.get('packs.aws.delete-s3-bucket')!.owasp).toBe('ASI02');
  });

  it('a pack row mirrors the product check it duplicates', () => {
    expect(CHECK_BY_ID.get('packs.bash-safe.eval-remote')!.owasp).toBe(
      CHECK_BY_ID.get('commands.eval-remote')!.owasp
    );
    expect(CHECK_BY_ID.get('packs.postgres.drop-table')!.owasp).toBe(
      CHECK_BY_ID.get('commands.sql-ddl')!.owasp
    );
  });

  it('a shield the table does not know gets no risk, so the catalog refuses the row', () => {
    expect(packRowOwasp('packs.newshield.delete-everything', 'newshield')).toBeUndefined();
    expect(packRowOwasp('packs.stripe.anything-new', 'stripe')).toBe('ASI09');
  });
});

describe('posture categories', () => {
  it('every category names a risk, and the guard being off is ASI10', () => {
    for (const [category, risk] of Object.entries(POSTURE_CATEGORY_OWASP))
      expect(isAsiId(risk), category).toBe(true);
    expect(postureCategoryOwasp('Secrets')).toBe('ASI03');
    expect(postureCategoryOwasp('Supply chain')).toBe('ASI04');
    expect(postureCategoryOwasp('Cost')).toBe('ASI08');
    expect(postureCategoryOwasp('Coverage')).toBe('ASI10');
    expect(postureCategoryOwasp('Nonsense')).toBeUndefined();
  });
});

describe('scan-repo rules', () => {
  it('maps by the longest matching prefix, script suffixes included', () => {
    expect(scanRepoRuleOwasp('CI-1.broad-allow')).toBe('ASI02');
    expect(scanRepoRuleOwasp('CI-1.hook-remote-code')).toBe('ASI05');
    expect(scanRepoRuleOwasp('CI-1.hook-script.curl-pipe-shell')).toBe('ASI05');
    expect(scanRepoRuleOwasp('CI-1.skill-untrusted-input')).toBe('ASI01');
    expect(scanRepoRuleOwasp('CI-2.injectable-workflow')).toBe('ASI01');
    expect(scanRepoRuleOwasp('CI-3.mcp-inline-credential')).toBe('ASI03');
    expect(scanRepoRuleOwasp('CI-3.mcp-unpinned')).toBe('ASI04');
    expect(scanRepoRuleOwasp('CI-4.agent-reachable-secret')).toBe('ASI03');
    expect(scanRepoRuleOwasp('CI-6.prompt-override')).toBe('ASI06');
    expect(scanRepoRuleOwasp('CI-6.skill-script.exfil')).toBe('ASI05');
  });

  it('suppression rows carry no risk, on purpose', () => {
    expect(scanRepoRuleOwasp('CI-0.suppression-malformed')).toBeUndefined();
    expect(
      SCAN_REPO_RULES_WITHOUT_RISK.some((p) => 'CI-0.suppression-malformed'.startsWith(p))
    ).toBe(true);
    expect(scanRepoRuleOwasp('CI-9.unknown')).toBeUndefined();
  });
});
