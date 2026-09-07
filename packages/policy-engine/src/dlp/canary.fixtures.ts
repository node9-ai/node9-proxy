// Fixture GENERATORS for the canary corpus (canary-corpus.md section A).
//
// No assembled credential-shaped value exists anywhere in this file or at
// import time: every generator is called inside a test body with a seed, and
// every prefix that could complete a credential shape is split so the source
// text never carries one. Production planting uses crypto.randomBytes; these
// only reproduce the SHAPE, deterministically, from one PRNG (mulberry32 seeded
// by FNV-1a of the seed string), never from crypto.
//
// Every generator is a rejection loop over the properties the design requires
// (no reachable stopword, length floor, and for the DB URL the whole-URL
// entropy floor). The spec proves the properties again through the engine's
// own scanArgs as an oracle, so ground truth is code that is not under test.

const fnv1a = (s: string): number => {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
};
const mulberry32 = (seed: number) => (): number => {
  seed = (seed + 0x6d2b79f5) >>> 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
export const rng = (seed: string): (() => number) => mulberry32(fnv1a(seed));

const pick = (r: () => number, alphabet: string, n: number): string => {
  let out = '';
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(r() * alphabet.length)];
  return out;
};
const choose = <T>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];

export const ALPHA_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const ALPHA_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const ALPHA_B64 = ALPHA_ALNUM + '+/';

/** Stopwords reachable in the generated alphabets (corpus A1/A3/A4); the
 *  engine's own list is module-private, so this is the diagnostic mirror. */
export const REACHABLE_STOPWORDS = [
  'example',
  'placeholder',
  'changeme',
  'fake',
  'dummy',
  'sample',
  'aaaaaa',
  'bbbbbb',
  'your',
  'here',
  'xxxxxxxx',
  '00000000',
] as const;
export const hasReachableStopword = (s: string): boolean => {
  const l = s.toLowerCase();
  return REACHABLE_STOPWORDS.some((w) => l.includes(w));
};

/** Shannon entropy in bits per character (the A9 diagnostic, re-implemented). */
export function shannon(s: string): number {
  if (!s) return 0;
  const f = new Map<string, number>();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of f.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const AWS_PREFIX = ['AK', 'IA'].join('');
const STRIPE_PREFIX = ['sk', 'live', ''].join('_');
const PG_SCHEME = ['postgres', '//'].join(':');
const PEM_HEAD = ['-----BEGIN ', 'RSA PRIVATE KEY', '-----'].join('');
const PEM_FOOT = ['-----END ', 'RSA PRIVATE KEY', '-----'].join('');

/** A1: standard prefix + 16 base32 chars; rejection loop on reachable stopwords.
 *  `forceBody` (A11) bypasses the loop so the spec can prove the loop is load-bearing. */
export function genAwsId(seed: string, opts?: { forceBody?: string }): string {
  if (opts?.forceBody) return AWS_PREFIX + opts.forceBody;
  const r = rng(seed);
  for (let i = 0; i < 1000; i++) {
    const v = AWS_PREFIX + pick(r, ALPHA_B32, 16);
    if (!hasReachableStopword(v)) return v;
  }
  throw new Error('genAwsId: rejection loop exhausted');
}
/** A2: 40 base64 chars, filler that makes the INI section look real; registered. */
export function genAwsSecret(seed: string): string {
  const r = rng(seed);
  for (let i = 0; i < 1000; i++) {
    const v = pick(r, ALPHA_B64, 40);
    if (!hasReachableStopword(v)) return v;
  }
  throw new Error('genAwsSecret: rejection loop exhausted');
}
/** A3: live-mode Stripe-style prefix + 24 alphanumerics. */
export function genStripe(seed: string): string {
  const r = rng(seed);
  for (let i = 0; i < 1000; i++) {
    const v = STRIPE_PREFIX + pick(r, ALPHA_ALNUM, 24);
    if (!hasReachableStopword(v)) return v;
  }
  throw new Error('genStripe: rejection loop exhausted');
}

export const DB_USERS = ['app', 'svc', 'reporter'] as const;
export const DB_HOSTS = [
  'db-internal',
  'pg-primary.internal',
  'postgres.svc.cluster.local',
] as const;
export const DB_NAMES = ['app', 'prod', 'main'] as const;
/** A4: the registered value is the 16-char password; `url` is the shape carrier.
 *  The loop rejects on a stopword anywhere in the WHOLE url and on whole-url entropy < 3.0,
 *  because the engine evaluates both over the full regex match (scheme through host). */
export function genDbUrl(seed: string): { password: string; url: string } {
  const r = rng(seed);
  for (let i = 0; i < 1000; i++) {
    const password = pick(r, ALPHA_ALNUM, 16);
    const url =
      PG_SCHEME +
      choose(r, DB_USERS) +
      ':' +
      password +
      '@' +
      choose(r, DB_HOSTS) +
      ':5432/' +
      choose(r, DB_NAMES);
    if (!hasReachableStopword(url) && shannon(url) >= 3.0) return { password, url };
  }
  throw new Error('genDbUrl: rejection loop exhausted');
}
/** A5: PEM-framed random base64; the registered value is the FIRST 64-char body line.
 *  `requireSpecial` (B12) regenerates until that line contains '+' or '/'. */
export function genPem(
  seed: string,
  opts?: { requireSpecial?: boolean }
): { line: string; text: string } {
  const r = rng(seed);
  for (let i = 0; i < 1000; i++) {
    const lines: string[] = [];
    for (let j = 0; j < 24; j++) lines.push(pick(r, ALPHA_B64, 64));
    lines.push(pick(r, ALPHA_B64, 20) + '=');
    const line = lines[0];
    if (opts?.requireSpecial && !/[+/]/.test(line)) continue;
    if (hasReachableStopword(line)) continue;
    return { line, text: [PEM_HEAD, ...lines, PEM_FOOT].join('\n') + '\n' };
  }
  throw new Error('genPem: rejection loop exhausted');
}

export const LABELS = ['backup', 'prod-readonly', 'legacy'] as const;
export const STRIPE_VARS = ['STRIPE_SECRET_KEY', 'STRIPE_API_KEY'] as const;
export const DB_VARS = ['DATABASE_URL', 'PG_URL'] as const;
export const pickLabel = (seed: string): string => choose(rng(seed), LABELS);
export const pickStripeVar = (seed: string): string => choose(rng(seed), STRIPE_VARS);
export const pickDbVar = (seed: string): string => choose(rng(seed), DB_VARS);

export const ROW_COUNTS = { A: 12, B: 42, C: 9, D: 34, E: 18, F: 5 } as const;
