// Production decoy generation. Same SHAPES as the corpus generators
// (packages/policy-engine/src/dlp/canary.fixtures.ts) but from crypto, and
// with the engine itself in the loop: a candidate is accepted only when the
// exact line that will be written trips the named regex pattern at block
// severity (design 4.3 and H18). The oracle is scanArgs, so "shape passes
// regex DLP" is asserted on the real bytes, never assumed. No prefix that
// could complete a credential shape appears contiguously in this source.
import { randomInt } from 'crypto';
import { scanArgs } from '../dlp';

const ALPHA_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALPHA_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const ALPHA_B64 = ALPHA_ALNUM + '+/';

const AWS_PREFIX = ['AK', 'IA'].join('');
const STRIPE_PREFIX = ['sk', 'live', ''].join('_');
const PG_SCHEME = ['postgres', '//'].join(':');
export const PEM_HEAD = ['-----BEGIN ', 'RSA PRIVATE KEY', '-----'].join('');
export const PEM_FOOT = ['-----END ', 'RSA PRIVATE KEY', '-----'].join('');

/** Plausible names only; never anything that says node9 or canary (design 4.3, A6). */
export const LABELS = ['backup', 'prod-readonly', 'legacy'] as const;
export const STRIPE_VARS = ['STRIPE_SECRET_KEY', 'STRIPE_API_KEY'] as const;
export const DB_VARS = ['DATABASE_URL', 'PG_URL'] as const;
const DB_USERS = ['app', 'svc', 'reporter'] as const;
// Host list verified stopword-free: the engine evaluates stopwords and entropy
// over the WHOLE matched URL, so a host containing "here" or "example" would
// silently kill the shape path (H18).
const DB_HOSTS = ['db-internal', 'pg-primary.internal', 'postgres.svc.cluster.local'] as const;
const DB_NAMES = ['app', 'prod', 'main'] as const;

// randomInt, not `randomBytes[i] % alphabet.length`: modulo over 256 favours
// the first (256 % len) characters, which biases every decoy this generates.
// The skew is small, but a decoy's whole value is being unguessable, so it is
// not a place to leave a known bias (CodeQL js/biased-cryptographic-random).
const pick = (alphabet: string, n: number): string => {
  let out = '';
  for (let i = 0; i < n; i++) out += alphabet[randomInt(alphabet.length)];
  return out;
};
const choose = <T>(xs: readonly T[]): T => xs[randomInt(xs.length)];

/** Accept a candidate only when the engine blocks the exact carrier line with the expected pattern. */
/** Exported for its unit row: the loop must be load-bearing, not decorative. */
export function untilBlocked(
  pattern: string,
  make: () => { value: string; carrier: string },
  tries = 200
) {
  for (let i = 0; i < tries; i++) {
    const c = make();
    const m = scanArgs({ content: c.carrier });
    if (m && m.severity === 'block' && m.patternName === pattern) return c;
  }
  throw new Error(`[node9] could not generate a decoy that the ${pattern} detector blocks`);
}

export interface GeneratedValue {
  /** Which secret at the site (INI key or env var name, or a description). */
  field: string;
  value: string;
}
export interface GeneratedSite {
  label: string;
  values: GeneratedValue[];
  /** Full file content to write. */
  text: string;
}

export function generateAwsProfile(): GeneratedSite {
  const label = choose(LABELS);
  const id = untilBlocked('AWS Access Key ID', () => {
    const value = AWS_PREFIX + pick(ALPHA_B32, 16);
    return { value, carrier: `aws_access_key_id = ${value}` };
  });
  const secret = pick(ALPHA_B64, 40);
  const text = `[${label}]\naws_access_key_id = ${id.value}\naws_secret_access_key = ${secret}\n`;
  return {
    label,
    values: [
      { field: 'aws_access_key_id', value: id.value },
      { field: 'aws_secret_access_key', value: secret },
    ],
    text,
  };
}

export function generateEnvFile(): GeneratedSite {
  const stripeVar = choose(STRIPE_VARS);
  const dbVar = choose(DB_VARS);
  const stripe = untilBlocked('Stripe Secret Key', () => {
    const value = STRIPE_PREFIX + pick(ALPHA_ALNUM, 24);
    return { value, carrier: `${stripeVar}=${value}` };
  });
  let password = '';
  const db = untilBlocked('Database Connection String', () => {
    password = pick(ALPHA_ALNUM, 16);
    const url = `${PG_SCHEME}${choose(DB_USERS)}:${password}@${choose(DB_HOSTS)}:5432/${choose(DB_NAMES)}`;
    return { value: url, carrier: `${dbVar}=${url}` };
  });
  const text = `${stripeVar}=${stripe.value}\n${dbVar}=${db.value}\n`;
  // The registered DB value is the PASSWORD, not the URL: an agent forwards the password alone (H5).
  return {
    label: stripeVar,
    values: [
      { field: stripeVar, value: stripe.value },
      { field: dbVar, value: password },
    ],
    text,
  };
}

export function generateSshKey(): GeneratedSite {
  const lines: string[] = [];
  for (let j = 0; j < 24; j++) lines.push(pick(ALPHA_B64, 64));
  lines.push(pick(ALPHA_B64, 20) + '=');
  const text = [PEM_HEAD, ...lines, PEM_FOOT].join('\n') + '\n';
  const m = scanArgs({ content: text });
  if (!m || m.patternName !== 'Private Key (PEM)' || m.severity !== 'block') {
    throw new Error('[node9] generated PEM decoy does not trip the Private Key (PEM) detector');
  }
  // The registered value is the first 64-char body line (H6). The body alone
  // trips no regex; only the header does, and only the canary catches a body
  // pasted without it.
  return { label: 'id_rsa_backup', values: [{ field: 'body-line-1', value: lines[0] }], text };
}
