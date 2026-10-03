// The catalog is the one list of what node9 checks. These tests pin its
// integrity (ids unique, defaults legal, locked rows locked), the translation
// from today's rule names and labels, and the resolver's reading of today's
// config shape. The end-to-end rule "every non-allow verdict names a check" is
// exercised against the real merged config in the proxy
// (src/__tests__/catalog-coverage.spec.ts).
import { describe, it, expect } from 'vitest';
import {
  CHECKS,
  CHECK_BY_ID,
  CHECK_GROUPS,
  VERDICTS,
  checkIdForRule,
  checkIdForCheckedBy,
  isLockedCheck,
  resolveCheck,
  resolveAllChecks,
  ssrfCheckId,
} from './catalog';
import { BUILTIN_SHIELDS } from './shields';

describe('catalog integrity', () => {
  it('every id is unique and spelled group.name', () => {
    const seen = new Set<string>();
    for (const c of CHECKS) {
      expect(seen.has(c.id), `duplicate id ${c.id}`).toBe(false);
      seen.add(c.id);
      expect(c.id, c.id).toMatch(
        /^(commands|data|network|files|behavior|loading|packs)\.[a-z0-9.-]+$/
      );
      const groupIds = CHECK_GROUPS.map((g) => g.id);
      expect(groupIds, c.id).toContain(c.group);
    }
  });

  it('every default is one of the values the row offers', () => {
    for (const c of CHECKS) {
      expect(c.values, c.id).toContain(c.defaultValue);
      for (const v of c.values) expect(VERDICTS, c.id).toContain(v);
    }
  });

  it('a locked row offers block only, and exactly three rows are locked', () => {
    const locked = CHECKS.filter(isLockedCheck);
    expect(locked.map((c) => c.id).sort()).toEqual([
      'commands.eval-remote',
      'commands.rm-home',
      'network.metadata',
    ]);
    for (const c of locked) expect(c.values).toEqual(['block']);
  });

  it('every row has a title and a one-line description', () => {
    for (const c of CHECKS) {
      expect(c.title.length, c.id).toBeGreaterThan(0);
      expect(c.catches.length, c.id).toBeGreaterThan(0);
      expect(c.catches, c.id).not.toContain('\n');
    }
  });

  it('each builtin shield except project-jail contributes one pack row per named rule', () => {
    for (const shield of Object.values(BUILTIN_SHIELDS)) {
      const rows = CHECKS.filter((c) => c.pack === shield.name);
      if (shield.name === 'project-jail') {
        expect(rows).toEqual([]);
        continue;
      }
      // The chmod rule is folded into commands.chmod, so filesystem has one row fewer.
      const expected = shield.smartRules.filter(
        (r) => r.name && r.name !== 'shield:filesystem:review-chmod-777'
      ).length;
      expect(rows.length, shield.name).toBe(expected);
    }
  });
});

describe("checkIdForRule: today's names and labels map to a check", () => {
  const cases: [string, string | undefined][] = [
    ['review-sudo', 'commands.sudo'],
    ['Smart Rule: review-sudo', 'commands.sudo'],
    ['review-force-push', 'commands.git-destructive'],
    ['review-git-destructive', 'commands.git-destructive'],
    ['review-curl-pipe-shell', 'commands.curl-pipe-shell'],
    ['block-rm-rf-home', 'commands.rm-home'],
    ['Node9 (AST): block-rm-rf-home', 'commands.rm-home'],
    ['review-rm', 'commands.rm'],
    ['allow-rm-safe-paths', 'commands.rm'],
    ['review-drop-truncate-shell', 'commands.sql-ddl'],
    ['review-drop-table-sql', 'commands.sql-ddl'],
    ['no-delete-without-where', 'commands.sql-no-where'],
    ['shield:filesystem:review-chmod-777', 'commands.chmod'],
    ['project-jail (AST): shield:filesystem:review-chmod-777', 'commands.chmod'],
    ['shield:project-jail:block-read-ssh', 'data.credential-files'],
    ['shield:project-jail:block-read-env-any-tool', 'data.credential-files'],
    ['shield:project-jail:review-read-credentials', 'data.credential-files-other'],
    ['shield:project-jail:review-copy-ssh', 'data.credential-files-other'],
    ['shield:postgres:block-drop-table', 'packs.postgres.drop-table'],
    ['shield:k8s:review-scale-zero', 'packs.k8s.scale-zero'],
    ['Node9 Standard (Inline Execution)', 'commands.inline-exec'],
    ['⚠️ Override block rule: Smart Rule: review-curl-pipe-shell', 'commands.curl-pipe-shell'],
    ['Node9: Eval Dynamic Content', 'commands.eval-dynamic'],
    ['Node9: Eval Remote Execution', 'commands.eval-remote'],
    ['Node9: Pipe-Chain Exfiltration (critical)', 'data.pipe-chain-obfuscated'],
    ['Node9: Pipe-Chain Exfiltration (high)', 'data.pipe-chain'],
    ['Node9: Suspect Binary', 'commands.temp-binary'],
    ['Manual Nuclear Protection', 'commands.disk-destroy'],
    ['Global Config (Strict Mode Active)', 'commands.unknown'],
    ['Project/Global Config — dangerous word: "dropdb"', 'commands.dangerous-word'],
    ['egress:curl:evil.example.com', 'network.unknown-host'],
    ['🌐 Node9 Egress (Review)', 'network.unknown-host'],
    ['ssrf:metadata:curl:169.254.169.254', 'network.metadata'],
    ['ssrf:private:curl:10.0.0.5', 'network.internal-addresses'],
    ['🌐 Node9 Egress (Protected Address)', 'network.metadata'],
    ['DLP: AWS Access Key ID', 'data.secrets'],
    ['🚨 Node9 DLP (Decoy Credential)', 'data.canary'],
    ['🔒 Node9 PII (Detected)', 'data.pii'],
    ['🔄 Loop Detected', 'behavior.loops'],
    ['🔴 Node9 Taint (Exfiltration Prevention)', 'behavior.session-taint'],
    ['🔴 Node9 Taint+Egress (Exfiltration Blocked)', 'network.taint-egress'],
    ['Skill Pin Quarantine', 'loading.skill-tamper'],
    ['package-check:evil-pkg', 'loading.malicious-package'],
    ['📦 Node9 Package Check (Malicious)', 'loading.malicious-package'],
    // Rules, not checks.
    ['org:block-path-secrets-bash', undefined],
    ['my-local-rule', undefined],
    ['app-permission:edit_file', undefined],
    ['User Decision (Native)', undefined],
    ['', undefined],
  ];
  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} -> ${expected ?? 'none'}`, () => {
      expect(checkIdForRule(input)).toBe(expected);
    });
  }

  it('every id a translation yields exists in the catalog', () => {
    for (const [input, expected] of cases) {
      if (expected) expect(CHECK_BY_ID.has(expected), input).toBe(true);
    }
  });

  it('every pack rule name translates to its own pack row', () => {
    for (const shield of Object.values(BUILTIN_SHIELDS)) {
      if (shield.name === 'project-jail') continue;
      for (const rule of shield.smartRules) {
        const id = checkIdForRule(rule.name);
        expect(id, rule.name).toBeDefined();
        expect(CHECK_BY_ID.has(id!), rule.name).toBe(true);
      }
    }
  });
});

describe('checkIdForCheckedBy: audit tags without a rule name', () => {
  it('maps the DLP, PII, loop, taint and package tags, observe-mode variants included', () => {
    expect(checkIdForCheckedBy('dlp-block')).toBe('data.secrets');
    expect(checkIdForCheckedBy('dlp-review-flagged')).toBe('data.secrets-weak');
    expect(checkIdForCheckedBy('observe-mode-dlp-would-block')).toBe('data.secrets');
    expect(checkIdForCheckedBy('dlp-canary-block')).toBe('data.canary');
    expect(checkIdForCheckedBy('pii-block')).toBe('data.pii');
    expect(checkIdForCheckedBy('observe-mode-pii-would-block')).toBe('data.pii');
    expect(checkIdForCheckedBy('loop-detected')).toBe('behavior.loops');
    expect(checkIdForCheckedBy('taint-egress-block')).toBe('network.taint-egress');
    expect(checkIdForCheckedBy('taint')).toBe('behavior.session-taint');
    expect(checkIdForCheckedBy('package-malicious')).toBe('loading.malicious-package');
  });

  it('leaves the generic tags alone', () => {
    for (const tag of ['local-policy', 'smart-rule-block', 'inline-review', 'cloud', 'timeout'])
      expect(checkIdForCheckedBy(tag), tag).toBeUndefined();
  });
});

describe('ssrfCheckId', () => {
  it('splits the floor by whether the tier is strict-gated', () => {
    expect(ssrfCheckId('metadata')).toBe('network.metadata');
    expect(ssrfCheckId('link-local')).toBe('network.metadata');
    expect(ssrfCheckId('private')).toBe('network.internal-addresses');
    expect(ssrfCheckId('cgnat')).toBe('network.internal-addresses');
  });
});

describe("resolveCheck reads today's config shape without changing a verdict", () => {
  it('an unset config answers the catalog default for every row', () => {
    for (const r of resolveAllChecks({})) {
      const def = CHECK_BY_ID.get(r.id)!;
      if (isLockedCheck(def)) {
        expect(r).toEqual({ id: r.id, value: 'block', source: 'locked' });
      } else if (def.pack) {
        expect(r.value, r.id).toBe('off');
      } else {
        expect(r.value, r.id).toBe(def.defaultValue);
        expect(r.source, r.id).toBe('default');
      }
    }
  });

  it('commandChecks knobs map one to one', () => {
    const s = { commandChecks: { inlineExec: 'off', rmAdvisory: 'block', evalDynamic: 'block' } };
    expect(resolveCheck(s, 'commands.inline-exec')).toEqual({
      id: 'commands.inline-exec',
      value: 'off',
      source: 'configured',
    });
    expect(resolveCheck(s, 'commands.rm')?.value).toBe('block');
    expect(resolveCheck(s, 'commands.eval-dynamic')?.value).toBe('block');
    expect(resolveCheck(s, 'commands.chmod')?.source).toBe('default');
  });

  it('a locked check ignores any knob', () => {
    expect(resolveCheck({ mode: 'observe' }, 'commands.eval-remote')).toEqual({
      id: 'commands.eval-remote',
      value: 'block',
      source: 'locked',
    });
  });

  it('dlp: enabled, reviewAction and pii', () => {
    expect(resolveCheck({ dlp: { enabled: false } }, 'data.secrets')?.value).toBe('off');
    expect(resolveCheck({ dlp: { enabled: false } }, 'data.secrets-weak')?.value).toBe('off');
    expect(resolveCheck({ dlp: { enabled: true } }, 'data.secrets-weak')?.value).toBe('review');
    expect(resolveCheck({ dlp: { reviewAction: 'block' } }, 'data.secrets-weak')?.value).toBe(
      'block'
    );
    expect(resolveCheck({ dlp: { pii: 'off' } }, 'data.pii')?.value).toBe('off');
    expect(resolveCheck({ dlp: { pii: 'block' } }, 'data.pii')?.value).toBe('block');
  });

  it('egress: enabled plus mode is one row, ssrfStrict is another', () => {
    expect(resolveCheck({ egress: { enabled: false } }, 'network.unknown-host')?.value).toBe('off');
    expect(
      resolveCheck({ egress: { enabled: true, mode: 'review' } }, 'network.unknown-host')?.value
    ).toBe('review');
    expect(
      resolveCheck({ egress: { enabled: true, mode: 'block' } }, 'network.unknown-host')?.value
    ).toBe('block');
    expect(
      resolveCheck({ egress: { ssrfStrict: true } }, 'network.internal-addresses')?.value
    ).toBe('block');
  });

  it('mode strict turns the catch-all on', () => {
    expect(resolveCheck({ mode: 'strict' }, 'commands.unknown')?.value).toBe('review');
    expect(resolveCheck({ mode: 'standard' }, 'commands.unknown')?.value).toBe('off');
  });

  it('skill pinning warn is log, block is block', () => {
    expect(
      resolveCheck({ skillPinning: { enabled: true, mode: 'warn' } }, 'loading.skill-tamper')?.value
    ).toBe('log');
    expect(
      resolveCheck({ skillPinning: { enabled: true, mode: 'block' } }, 'loading.skill-tamper')
        ?.value
    ).toBe('block');
    expect(resolveCheck({ skillPinning: { enabled: false } }, 'loading.skill-tamper')?.value).toBe(
      'off'
    );
  });

  it('a pack row is on only while its pack is applied', () => {
    expect(resolveCheck({}, 'packs.postgres.drop-table')?.value).toBe('off');
    expect(resolveCheck({ appliedShields: ['postgres'] }, 'packs.postgres.drop-table')?.value).toBe(
      'block'
    );
  });

  it('an unknown id answers undefined', () => {
    expect(resolveCheck({}, 'commands.does-not-exist')).toBeUndefined();
  });
});
