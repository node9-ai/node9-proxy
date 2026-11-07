// src/supply-chain/lookalike.ts
// A package name that looks like a popular one (node9Firewall#385, wave 3).
//
// The install name is compared with the most downloaded names of its
// registry (popular-names.ts, loaded on the first call so the hook's start-up
// never pays for it). A near miss is one of:
//
//   1. one edit away (insert, delete, substitute, swap two neighbours) from a
//      popular name of 5 or more characters; two edits from one of 10 or more
//      (`dajngo`, `requuest`, `aysnc`)
//   2. the same letters once `-`, `_` and `.` are removed (`setup-tools`)
//   3. npm: the unscoped tail of a popular scoped name (`arm-quota` for
//      `@azure/arm-quota`), when the tail has 6 or more characters
//   4. a popular name of 4 or more characters with one padding token at either
//      end (`axios-http`, `django-server`, `python-requests`)
//
// A near miss alone flagged about 3% of real names in an earlier trial, so the
// caller keeps the finding only when the name has no standing of its own
// (check.ts: not on the registry, first published under a year ago, or few
// downloads). A name that is itself on the popular list is never a near miss.
import type { PackageEcosystem } from '@node9/policy-engine';

export interface NearMiss {
  /** The popular name the install name resembles. */
  popular: string;
  rule: 'edit' | 'separators' | 'scope-dropped' | 'padding';
  /** For `edit`: the distance (1 or 2). */
  distance?: number;
}

const PADDING = [
  'python-',
  'py-',
  '-py',
  '-python',
  'js-',
  '-js',
  'node-',
  '-node',
  '-http',
  '-util',
  '-utils',
  '-plus',
  '-server',
  '-lib',
  'lib',
];

type Lists = Partial<Record<PackageEcosystem, readonly string[]>>;
let lists: Promise<Lists> | null = null;
let override: Lists | null = null;

async function popular(): Promise<Lists> {
  if (override) return override;
  if (!lists) {
    lists = import('./popular-names.js').then((m) => ({
      npm: m.POPULAR_NPM,
      PyPI: m.POPULAR_PYPI,
    }));
  }
  return lists;
}

/** Test seam: compare against these names instead of the generated lists. */
export function _setPopularNamesForTests(value: Lists | null): void {
  override = value;
}

/** The form the lists hold: lowercase; PyPI per PEP 503. */
export function normalizedName(eco: PackageEcosystem, name: string): string {
  const lower = name.toLowerCase();
  return eco === 'PyPI' ? lower.replace(/[-_.]+/g, '-') : lower;
}

/**
 * Damerau-Levenshtein distance (optimal string alignment), stopping as soon
 * as every cell of a row is over `max`; returns `max + 1` then.
 */
export function editDistance(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const n = b.length;
  let prev2: number[] | null = null;
  let prev: number[] = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur: number[] = [i];
    let rowMin = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1] && prev2) {
        v = Math.min(v, prev2[j - 2] + 1);
      }
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[n];
}

const stripSeparators = (s: string): string => s.replace(/[-_.]/g, '');

/** The near miss of `name` among the popular names of its registry, or null. */
export async function nearMiss(eco: PackageEcosystem, name: string): Promise<NearMiss | null> {
  const list = (await popular())[eco];
  if (!list) return null;
  return nearMissIn(eco, name, list);
}

export function nearMissIn(
  eco: PackageEcosystem,
  name: string,
  list: readonly string[]
): NearMiss | null {
  const c = normalizedName(eco, name);
  if (list.includes(c)) return null;
  const stripped = stripSeparators(c);
  for (const p of list) {
    if (stripSeparators(p) === stripped) return { popular: p, rule: 'separators' };
    const diff = Math.abs(p.length - c.length);
    if (p.length >= 5 && diff <= 2) {
      const max = p.length >= 10 ? 2 : 1;
      if (diff <= max) {
        const d = editDistance(c, p, max);
        if (d <= max) return { popular: p, rule: 'edit', distance: d };
      }
    }
    if (eco === 'npm' && p.startsWith('@')) {
      const tail = p.slice(p.indexOf('/') + 1);
      if (tail.length >= 6 && tail === c) return { popular: p, rule: 'scope-dropped' };
    }
    if (p.length >= 4 && c.length > p.length && c.includes(p)) {
      for (const t of PADDING) {
        const padded = t.endsWith('-') || t === 'lib' ? t + p : p + t;
        if (c === padded) return { popular: p, rule: 'padding' };
      }
    }
  }
  return null;
}

/** The words of the finding: how the name differs from the popular one. */
export function describeNearMiss(m: NearMiss): string {
  switch (m.rule) {
    case 'edit':
      return m.distance === 1 ? 'one letter off' : 'two letters off';
    case 'separators':
      return 'the same letters with a separator moved';
    case 'scope-dropped':
      return 'its name without the scope';
    case 'padding':
      return 'its name with a word added';
  }
}
