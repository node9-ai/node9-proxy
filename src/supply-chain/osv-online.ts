// src/supply-chain/osv-online.ts
// Online fallback: OSV querybatch, used when the local index is missing or
// stale. Short timeout; the caller fails open on any error.
import type { PackageEcosystem } from '@node9/policy-engine';
import { endpoints, fetchJson } from './net';

export interface OnlineQuery {
  ecosystem: PackageEcosystem;
  name: string;
  version?: string;
}

const TIMEOUT_MS = 2500;

/**
 * MAL- advisory ids per query, in query order, or null when OSV could not be
 * asked (no endpoint, timeout, error). With a version, OSV answers for that
 * version; without one, for any version of the package.
 */
export async function queryOsvMalicious(queries: OnlineQuery[]): Promise<string[][] | null> {
  const base = endpoints().osvApi;
  if (!base || queries.length === 0) return null;
  const body = JSON.stringify({
    queries: queries.map((q) => ({
      package: { name: q.name, ecosystem: q.ecosystem },
      ...(q.version ? { version: q.version } : {}),
    })),
  });
  const res = (await fetchJson(`${base}/v1/querybatch`, {
    timeoutMs: TIMEOUT_MS,
    maxBytes: 1024 * 1024,
    body,
  })) as { results?: Array<{ vulns?: Array<{ id?: unknown }> }> } | null;
  if (!res || !Array.isArray(res.results) || res.results.length !== queries.length) return null;
  return res.results.map((r) =>
    (r.vulns ?? [])
      .map((v) => v.id)
      .filter((id): id is string => typeof id === 'string' && id.startsWith('MAL-'))
  );
}
