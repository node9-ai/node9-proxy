// src/apps/catalog.ts
// The apps node9 can find on a machine and the shield that protects each
// (node9Firewall#390, phase 2). A signal is a NAME only: a server label, the
// program a command runs, a package name, an env var name. Values are never
// read.
//
// bash-safe, filesystem and project-jail are not apps: they protect the
// machine itself and are not turned on by finding anything.

export interface AppEntry {
  slug: string;
  label: string;
  /** The built-in shield that protects the app. */
  shield: string;
  /** Substrings of an MCP server label (case-insensitive). */
  servers: readonly string[];
  /** The program a shell command starts with. */
  commands: readonly string[];
  /** Package names in package.json, requirements.txt or pyproject.toml.
   *  A trailing `/` matches a scope (`@aws-sdk/`). */
  packages: readonly string[];
  /** Prefixes of env var names in a project's .env files. */
  envPrefixes: readonly string[];
}

export const APP_CATALOG: readonly AppEntry[] = [
  {
    slug: 'redis',
    label: 'Redis',
    shield: 'redis',
    servers: ['redis', 'valkey'],
    commands: ['redis-cli', 'valkey-cli'],
    packages: ['redis', 'ioredis', 'valkey'],
    envPrefixes: ['REDIS_'],
  },
  {
    slug: 'postgres',
    label: 'PostgreSQL',
    shield: 'postgres',
    servers: ['postgres', 'pgsql'],
    commands: ['psql', 'pg_dump', 'pg_restore', 'pgcli'],
    packages: ['pg', 'postgres', 'psycopg', 'psycopg2', 'psycopg2-binary', 'asyncpg'],
    envPrefixes: ['PGHOST', 'PGDATABASE', 'POSTGRES_'],
  },
  {
    slug: 'mongodb',
    label: 'MongoDB',
    shield: 'mongodb',
    servers: ['mongo'],
    commands: ['mongosh', 'mongo', 'mongodump', 'mongorestore'],
    packages: ['mongodb', 'mongoose', 'pymongo', 'motor'],
    envPrefixes: ['MONGO'],
  },
  {
    slug: 'github',
    label: 'GitHub',
    shield: 'github',
    servers: ['github'],
    commands: ['gh'],
    packages: ['@octokit/', 'octokit', 'pygithub'],
    envPrefixes: ['GITHUB_TOKEN', 'GH_TOKEN'],
  },
  {
    slug: 'aws',
    label: 'AWS',
    shield: 'aws',
    servers: ['aws'],
    commands: ['aws', 'sam', 'cdk'],
    packages: ['aws-sdk', '@aws-sdk/', 'boto3', 'aws-cdk-lib'],
    envPrefixes: ['AWS_ACCESS_KEY_ID', 'AWS_PROFILE'],
  },
  {
    slug: 'k8s',
    label: 'Kubernetes',
    shield: 'k8s',
    servers: ['kubernetes', 'k8s', 'kubectl'],
    commands: ['kubectl', 'helm', 'k9s'],
    packages: ['@kubernetes/client-node', 'kubernetes'],
    envPrefixes: ['KUBECONFIG'],
  },
  {
    slug: 'docker',
    label: 'Docker',
    shield: 'docker',
    servers: ['docker'],
    commands: ['docker', 'docker-compose', 'podman'],
    packages: ['dockerode', 'docker'],
    envPrefixes: ['DOCKER_HOST'],
  },
  {
    slug: 'stripe',
    label: 'Stripe',
    shield: 'stripe',
    servers: ['stripe'],
    commands: ['stripe'],
    packages: ['stripe', '@stripe/'],
    envPrefixes: ['STRIPE_'],
  },
  {
    slug: 'paypal',
    label: 'PayPal',
    shield: 'paypal',
    servers: ['paypal'],
    commands: [],
    packages: ['@paypal/', 'paypalrestsdk', 'paypal-checkout-serversdk', 'paypal-server-sdk'],
    envPrefixes: ['PAYPAL_'],
  },
];

export const APP_BY_SLUG: ReadonlyMap<string, AppEntry> = new Map(
  APP_CATALOG.map((a) => [a.slug, a])
);

/** The app whose shield this is, if any. */
export function appForShield(shield: string): AppEntry | undefined {
  return APP_CATALOG.find((a) => a.shield === shield);
}

/** The action words of the payment apps, and the shield rule each sets
 *  (`node9 apps stripe refunds allow`). */
const PAYMENT_ACTIONS: Readonly<Record<string, string>> = {
  refunds: 'review-refund',
  payouts: 'review-payout',
  transfers: 'review-transfer',
  charges: 'review-charge',
  invoices: 'review-payment-link',
  subscriptions: 'review-subscription',
  disputes: 'review-dispute',
  cards: 'review-card',
  withdrawals: 'review-withdraw',
};
export const ACTIONS_BY_APP: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  stripe: PAYMENT_ACTIONS,
  paypal: PAYMENT_ACTIONS,
};

/** The action word of a shield rule (`stripe`, `review-refund` -> `refunds`). */
export function actionWordOf(shield: string, rule: string): string | undefined {
  const actions = ACTIONS_BY_APP[shield];
  if (!actions) return undefined;
  return Object.entries(actions).find(([, r]) => r === rule)?.[0];
}
