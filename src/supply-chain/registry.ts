// src/supply-chain/registry.ts
// Registry signals for a package about to be installed: the version the
// install would resolve to, how recently it was published, and (npm) whether
// it runs an install script. Every function fails soft: a failed lookup
// returns `null` and the caller records a miss.
import type { PackageEcosystem } from '@node9/policy-engine';
import { endpoints, fetchJson } from './net';

export interface RegistryInfo {
  /** The version the install resolves to (the pinned one, else latest). */
  version: string;
  /**
   * Upper bound on when that version was published (epoch ms). npm's
   * abbreviated document carries only the package-level `modified` time, so
   * for npm this is "no later than"; older than the threshold is exact,
   * younger is a signal for review, not proof.
   */
  publishedAtMs?: number;
  hasInstallScript?: boolean;
}

const TIMEOUT_MS = 1500;
const MAX_BYTES = 2 * 1024 * 1024;

async function npmInfo(name: string, version?: string): Promise<RegistryInfo | null> {
  const base = endpoints().npmRegistry;
  if (!base) return null;
  // Every slash, not the first: a valid scoped name has one, and a name with
  // more must not reach another registry path (CodeQL js/incomplete-sanitization).
  const doc = (await fetchJson(`${base}/${name.replaceAll('/', '%2F')}`, {
    timeoutMs: TIMEOUT_MS,
    maxBytes: MAX_BYTES,
    headers: { Accept: 'application/vnd.npm.install-v1+json' },
  })) as {
    modified?: string;
    'dist-tags'?: Record<string, string>;
    versions?: Record<string, { hasInstallScript?: boolean }>;
  } | null;
  if (!doc) return null;
  const latest = doc['dist-tags']?.latest;
  const resolved = version ?? latest;
  if (!resolved) return null;
  const v = doc.versions?.[resolved];
  const modifiedMs = doc.modified ? Date.parse(doc.modified) : NaN;
  return {
    version: resolved,
    // `modified` bounds the publish time of EVERY version from above, but it
    // only approximates the age of the newest one: an older pinned version
    // gets no age (it is at least as old as `latest`, so never "new").
    publishedAtMs: Number.isFinite(modifiedMs) && resolved === latest ? modifiedMs : undefined,
    hasInstallScript: v?.hasInstallScript === true,
  };
}

async function pypiInfo(name: string, version?: string): Promise<RegistryInfo | null> {
  const base = endpoints().pypi;
  if (!base) return null;
  const url = version
    ? `${base}/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`
    : `${base}/pypi/${encodeURIComponent(name)}/json`;
  const doc = (await fetchJson(url, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_BYTES })) as {
    info?: { version?: string };
    urls?: Array<{ upload_time_iso_8601?: string }>;
  } | null;
  if (!doc?.info?.version) return null;
  const times = (doc.urls ?? [])
    .map((u) => (u.upload_time_iso_8601 ? Date.parse(u.upload_time_iso_8601) : NaN))
    .filter((t) => Number.isFinite(t));
  return {
    version: version ?? doc.info.version,
    // The earliest file of the release is when it became installable.
    publishedAtMs: times.length > 0 ? Math.min(...times) : undefined,
  };
}

export async function registryInfo(
  eco: PackageEcosystem,
  name: string,
  version?: string
): Promise<RegistryInfo | null> {
  return eco === 'npm' ? npmInfo(name, version) : pypiInfo(name, version);
}
