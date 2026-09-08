// The blast radius of an invalid config field.
//
// sanitizeConfig drops what fails validation so a broken value cannot override
// a valid one from another layer. The question this file pins is HOW MUCH it
// drops: dropping the whole top-level block for one bad field is fail-open,
// because `policy` carries egress, DLP, the jail and the smart rules, and a
// machine that loses it silently keeps running with much less enforcement.
//
// Measured on 2026-09-08 before the fix: of 202 single-field mutations, 151
// erased a whole top-level block and 108 of those erased `policy`.
//
// The corpus is GENERATED here rather than stored, so it cannot rot into a
// snapshot of whatever the code happens to do.
import { describe, it, expect } from 'vitest';
import { sanitizeConfig, ConfigFileSchema } from '../config-schema';

const BASE = {
  version: '1.0',
  settings: { mode: 'standard', autoStartDaemon: true, approvers: { native: true, cloud: true } },
  policy: {
    egress: {
      enabled: true,
      mode: 'block',
      allow: ['api.github.com'],
      deny: ['evil.example.com'],
      allowPrivate: false,
      ssrfStrict: true,
      ssrfAllow: ['100.64.0.1'],
    },
    dlp: { enabled: true, pii: 'block', reviewAction: 'block' },
    loopDetection: { enabled: true, threshold: 5, windowSeconds: 120 },
    ignoredTools: ['Read'],
    smartRules: [
      {
        name: 'r1',
        tool: 'Bash',
        verdict: 'block',
        conditions: [{ field: 'command', op: 'matches', value: 'rm -rf /' }],
      },
    ],
  },
  environments: { staging: { requireApproval: true } },
} as const;

type Json = Record<string, unknown>;
const clone = (o: unknown): Json => JSON.parse(JSON.stringify(o)) as Json;

/** Every leaf path in the base config. Arrays are DESCENDED INTO, not treated
 *  as leaves: three mutants survived while they were, because a required field
 *  nested inside a smart rule was never damaged and the prune's array handling,
 *  ordering and second pass were therefore never exercised. */
function leafPaths(o: unknown, prefix: string[] = []): string[][] {
  if (Array.isArray(o)) {
    return o.flatMap((v, i) => leafPaths(v, [...prefix, String(i)]));
  }
  if (o !== null && typeof o === 'object') {
    return Object.entries(o).flatMap(([k, v]) => leafPaths(v, [...prefix, k]));
  }
  return [prefix];
}
function setPath(o: Json, path: string[], value: unknown, del = false): void {
  let cur: Json = o;
  for (const k of path.slice(0, -1)) cur = cur[k] as Json;
  const last = path[path.length - 1];
  if (!del) {
    cur[last] = value;
    return;
  }
  // Splice out of an array, delete from an object: leaving a hole in an array
  // is not a shape a hand-edited config ever has.
  if (Array.isArray(cur)) (cur as unknown as unknown[]).splice(Number(last), 1);
  else delete cur[last];
}
const VARIANTS: Array<[string, unknown, boolean]> = [
  ['string', 'not-a-value', false],
  ['number', 42, false],
  ['bool', true, false],
  ['null', null, false],
  ['empty-string', '', false],
  ['array', ['x'], false],
  ['object', { k: 'v' }, false],
  ['delete', undefined, true],
];

const ALL_PATHS = leafPaths(BASE);
const corpus: Array<{ id: string; cfg: Json }> = [{ id: 'base-valid', cfg: clone(BASE) }];
for (const path of ALL_PATHS) {
  for (const [tag, value, del] of VARIANTS) {
    const cfg = clone(BASE);
    setPath(cfg, path, value, del);
    corpus.push({ id: `${path.join('.')} := ${tag}`, cfg });
  }
}
// Rows with SEVERAL failures at once. A single-fault corpus cannot see whether
// the prune removes them in an order that keeps sibling indices valid, nor
// whether one pass is enough.
const SECOND_RULE = {
  name: 'r2',
  tool: 'Read',
  verdict: 'review',
  conditions: [{ field: 'file_path', op: 'contains', value: '.env' }],
};
for (const [tag, mutate] of Object.entries<(c: Json) => void>({
  'two-rules-both-bad': (c) => {
    const p = c.policy as Json;
    p.smartRules = [clone(BASE.policy.smartRules[0]), clone(SECOND_RULE)];
    setPath(c, ['policy', 'smartRules', '0', 'verdict'], 'nope');
    setPath(c, ['policy', 'smartRules', '1', 'tool'], 42);
  },
  'first-of-two-rules-bad': (c) => {
    const p = c.policy as Json;
    p.smartRules = [clone(BASE.policy.smartRules[0]), clone(SECOND_RULE)];
    setPath(c, ['policy', 'smartRules', '0', 'verdict'], 'nope');
  },
  'bad-in-two-different-blocks': (c) => {
    setPath(c, ['policy', 'egress', 'enabled'], 'yes');
    setPath(c, ['settings', 'mode'], 99);
  },
  'required-field-missing': (c) => {
    setPath(c, ['policy', 'smartRules', '0', 'tool'], undefined, true);
  },
  'nested-condition-bad': (c) => {
    setPath(c, ['policy', 'smartRules', '0', 'conditions', '0', 'op'], 'sideways');
  },
})) {
  const cfg = clone(BASE);
  mutate(cfg);
  corpus.push({ id: `multi:${tag}`, cfg });
}

/** The paths zod itself objects to, as dotted strings. */
function failingPaths(cfg: unknown): Set<string> {
  const r = ConfigFileSchema.safeParse(cfg);
  if (r.success) return new Set();
  return new Set(r.error.issues.map((i) => i.path.join('.')));
}

// Structural damage the leaf mutations cannot express: a whole block of the
// wrong SHAPE. These are what the top-level floor exists for, and without them
// the floor is unreachable and therefore untested.
for (const [tag, cfg] of Object.entries<unknown>({
  'settings-array': { ...clone(BASE), settings: [] },
  'policy-null': { ...clone(BASE), policy: null },
  'policy-string': { ...clone(BASE), policy: 'nope' },
  'unknown-top-level': { ...clone(BASE), totallyUnknown: { a: 1 } },
  'empty-object': {},
})) {
  corpus.push({ id: `struct:${tag}`, cfg: cfg as Json });
}

describe('sanitizeConfig blast radius', () => {
  it('the corpus is big enough and the base is genuinely valid', () => {
    // Instrument first: if the base does not validate, every row below is
    // measuring a config whose `policy` was already gone and proves nothing.
    // That exact mistake produced a meaningless "zero differences" earlier.
    expect(corpus.length).toBeGreaterThan(150);
    expect(sanitizeConfig(BASE).error).toBeNull();
    expect(Object.keys(sanitizeConfig(BASE).sanitized).sort()).toEqual([
      'environments',
      'policy',
      'settings',
      'version',
    ]);
  });

  it('P1 nothing invalid survives: the sanitized output validates', () => {
    for (const { id, cfg } of corpus) {
      const { sanitized } = sanitizeConfig(cfg);
      expect(ConfigFileSchema.safeParse(sanitized).success, `${id} left invalid data behind`).toBe(
        true
      );
    }
  });

  it('P3 a valid sibling survives its broken neighbour', () => {
    // P2 only looks at top-level blocks, so it cannot see how much was removed
    // INSIDE one. Four mutations of the prune survived until this row existed.
    const rules = (cfg: Json): Array<{ name?: string }> =>
      (((sanitizeConfig(cfg).sanitized.policy as Json) ?? {}).smartRules ?? []) as Array<{
        name?: string;
      }>;
    const one = corpus.find((r) => r.id === 'multi:first-of-two-rules-bad')!;
    expect(
      rules(one.cfg).map((r) => r.name),
      'only the broken rule goes'
    ).toEqual(['r2']);

    const nested = corpus.find((r) => r.id === 'multi:nested-condition-bad')!;
    const kept = sanitizeConfig(nested.cfg).sanitized.policy as Json;
    expect(rules(nested.cfg).length, 'a rule with a bad condition goes').toBe(0);
    expect(kept.egress, 'and everything beside it stays').toEqual(BASE.policy.egress);
    expect(kept.dlp).toEqual(BASE.policy.dlp);

    const both = corpus.find((r) => r.id === 'multi:two-rules-both-bad')!;
    expect(rules(both.cfg), 'two broken rules, both go, nothing else does').toEqual([]);
    expect((sanitizeConfig(both.cfg).sanitized.policy as Json).egress).toEqual(BASE.policy.egress);

    const across = corpus.find((r) => r.id === 'multi:bad-in-two-different-blocks')!;
    const s = sanitizeConfig(across.cfg).sanitized;
    expect((s.policy as Json).dlp, 'a fault in settings does not cost policy').toEqual(
      BASE.policy.dlp
    );
    expect((s.settings as Json).autoStartDaemon, 'nor the rest of settings').toBe(true);
  });

  it('P2 a bad field costs its own subtree, not a whole top-level block', () => {
    const casualties: string[] = [];
    for (const { id, cfg } of corpus) {
      if (id === 'base-valid') continue;
      const bad = failingPaths(cfg);
      if (bad.size === 0) continue; // the variant happened to be valid
      const kept = new Set(Object.keys(sanitizeConfig(cfg).sanitized));
      for (const top of Object.keys(BASE)) {
        if (kept.has(top)) continue;
        // `top` vanished. That is only honest when zod objected to `top` itself,
        // not to something nested under it.
        if (!bad.has(top)) casualties.push(`${id} -> lost the whole "${top}" block`);
      }
    }
    expect(casualties.slice(0, 6)).toEqual([]);
    expect(casualties.length, `${casualties.length} rows lost a whole block`).toBe(0);
  });
});
