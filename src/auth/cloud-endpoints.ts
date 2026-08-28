// One resolver for cloud API endpoints outside the /intercept namespace.
// Precedence: explicit override → NODE9_API_URL (the intercept base, so a dev
// pointing the daemon at staging reaches the same host) → prod default.
const PROD_BASE = 'https://api.node9.ai/api/v1';

export function resolveCloudEndpoint(pathSuffix: string, override?: string): string {
  if (override) return override;
  const base = process.env.NODE9_API_URL;
  if (base) return base.replace(/\/intercept\/?$/, '') + pathSuffix;
  return PROD_BASE + pathSuffix;
}
