import { describe, it, expect } from 'vitest';
import { BUILTIN_SHIELDS } from './index';
import { evaluateSmartConditions } from '../rules';

/**
 * The Redis shield matched bare uppercase keywords on the `command` field with
 * no requirement that Redis be involved at all. Two observed false positives,
 * both from heredocs writing FILES:
 *
 *   • a test fixture: description: "FLUSHALL deletes every key"
 *   • a commit message naming the rule: shield:redis:block-flushall
 *
 * Every other builtin shield already requires the invoking command in its
 * pattern (`aws s3 …`, `docker system prune`, `kubectl delete …`,
 * `gh repo delete`, `chmod …`). Redis was the outlier.
 *
 * The fix must satisfy BOTH callers, which is the whole difficulty:
 *   1. shell — `redis-cli FLUSHALL`, where a client names itself
 *   2. MCP   — the redis_command tool sends { command: "FLUSHALL", args: [] },
 *              so the field holds the bare keyword and NOTHING else. Requiring
 *              "redis-cli" alone would create a false negative on the most
 *              direct route an agent has to the database.
 */

const rule = (name: string) => {
  const r = BUILTIN_SHIELDS.redis.smartRules.find((x) => x.name?.endsWith(name));
  if (!r) throw new Error(`redis rule not found: ${name}`);
  return r;
};

const matches = (ruleName: string, command: string) =>
  evaluateSmartConditions({ command }, rule(ruleName));

describe('redis shield — must still catch real Redis operations', () => {
  const TRUE_POSITIVES: Array<[string, string]> = [
    // shell, client names itself
    ['block-flushall', 'redis-cli FLUSHALL'],
    ['block-flushall', 'redis-cli -h prod.example.com -p 6379 FLUSHALL'],
    ['block-flushall', 'valkey-cli FLUSHALL'],
    ['block-flushall', 'docker exec -it cache redis-cli FLUSHALL'],
    ['block-flushall', 'redis-cli -u redis://prod/0 flushall'],
    // client AFTER the keyword — a real invocation shape
    ['block-flushall', 'echo FLUSHALL | redis-cli'],
    // MCP: the tool sends the bare keyword as the whole command field
    ['block-flushall', 'FLUSHALL'],
    // Client LIBRARY calls in one-liners. The first cut of this fix dropped
    // these — a review caught it by running old vs new patterns side by side.
    // A literal dot+paren is self-limiting (the same property mongodb's rules
    // rely on: `.dropDatabase(`), so it costs no false positives.
    ['block-flushall', 'python3 -c "import redis; r = redis.Redis(); r.flushall()"'],
    ['block-flushall', 'node -e "await client.flushAll()"'],
    ['block-flushall', 'redis.flushall()'],
    ['block-flushdb', 'redis-cli FLUSHDB'],
    ['block-flushdb', 'FLUSHDB'],
    ['block-flushdb', 'python3 -c "r.flushdb()"'],
    // Whitespace: the CLOUD path (BE matchesParamsFilter) tests the raw value
    // with NO whitespace collapsing, so these rules keep \s+ rather than a
    // literal space.
    ['review-config-set', 'redis-cli CONFIG  SET maxmemory 0'],
    ['block-config-resetstat', 'redis-cli CONFIG RESETSTAT'],
    ['block-config-resetstat', 'CONFIG RESETSTAT'],
    ['review-config-set', 'redis-cli CONFIG SET maxmemory 0'],
    ['review-config-set', 'CONFIG SET appendonly no'],
  ];

  for (const [ruleName, command] of TRUE_POSITIVES) {
    it(`${ruleName} still catches: ${command}`, () => {
      expect(matches(ruleName, command)).toBe(true);
    });
  }
});

describe('redis shield — must NOT fire on text that merely mentions Redis', () => {
  // The two REAL false positives, verbatim in shape.
  const FALSE_POSITIVES: Array<[string, string]> = [
    [
      'block-flushall',
      `python3 - <<'PYEOF'\ns = s.replace("x", 'description: "FLUSHALL deletes every key"')\nPYEOF`,
    ],
    [
      'block-flushall',
      `git commit -F - <<'EOF'\nfix(audit): one decision mapper\n[Blocked] (shield:redis:block-flushall)\nEOF`,
    ],
    // Same class, other rules — all four share the bare-keyword shape.
    ['block-flushdb', `git commit -m "docs: explain block-flushdb"`],
    ['block-config-resetstat', `cat > notes.md <<'EOF'\nCONFIG RESETSTAT wipes stats\nEOF`],
    [
      'review-config-set',
      `python3 - <<'EOF'\nprint("CONFIG SET changes live server configuration")\nEOF`,
    ],
    // Prose about the shield, in ordinary tooling.
    ['block-flushall', 'grep -rn "FLUSHALL" docs/'],
    ['block-flushall', 'rg FLUSHALL --type ts'],
    ['review-config-set', 'echo "CONFIG SET is reviewed by the redis shield"'],
  ];

  for (const [ruleName, command] of FALSE_POSITIVES) {
    it(`${ruleName} ignores: ${command.split('\n')[0].slice(0, 52)}…`, () => {
      expect(matches(ruleName, command)).toBe(false);
    });
  }
});

describe('redis shield — stays cloud-manageable', () => {
  // cloudEnableable is false when ANY rule needs more than one condition (the
  // legacy Policy.paramsFilter holds a single {path, regex}). Adding a second
  // condition here would flip the WHOLE shield to CLI-only — exactly like
  // docker — and break the cloud toggle the Apps page depends on.
  it('every redis rule keeps exactly one condition', () => {
    for (const r of BUILTIN_SHIELDS.redis.smartRules) {
      expect(r.conditions?.length ?? 0).toBe(1);
    }
  });
});
