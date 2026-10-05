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
  /** Set when the age had to fall back to the package-level `modified` time
   *  because the per-version time could not be read (full document over the
   *  cap, or unavailable). The caller records it as a miss. */
  ageFallback?: string;
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

/**
 * The abbreviated npm document carries one package-level `modified` time and
 * no per-version times, and ANY publish moves it (a `next` or `beta` tag
 * included). So `modified` is only a hint: when it falls inside the window
 * the caller cares about, the full document is read for `time[version]`,
 * capped at MAX_BYTES (react's is 7 MB). Over the cap or unavailable, the
 * hint stands (the conservative side) and `ageFallback` says so.
 */
async function npmInfo(
  name: string,
  version: string | undefined,
  freshWindowMs: number
): Promise<RegistryInfo | null> {
  const base = endpoints().npmRegistry;
  if (!base) return null;
  // Every slash, not the first: a valid scoped name has one, and a name with
  // more must not reach another registry path (CodeQL js/incomplete-sanitization).
  const url = `${base}/${name.replaceAll('/', '%2F')}`;
  const doc = (await fetchJson(url, {
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
  const info: RegistryInfo = {
    version: resolved,
    hasInstallScript: v?.hasInstallScript === true,
  };
  if (!Number.isFinite(modifiedMs)) return info;
  if (Date.now() - modifiedMs >= freshWindowMs) {
    // Nothing about this package changed inside the window, so no version
    // of it is that young. Exact for every version, no second request.
    info.publishedAtMs = resolved === latest ? modifiedMs : undefined;
    return info;
  }
  try {
    const full = (await fetchJson(url, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_BYTES })) as {
      time?: Record<string, string>;
    } | null;
    const t = full?.time?.[resolved];
    const tMs = t ? Date.parse(t) : NaN;
    if (Number.isFinite(tMs)) {
      info.publishedAtMs = tMs;
      return info;
    }
    info.ageFallback = `no publish time for ${resolved} in the full document`;
  } catch (err) {
    info.ageFallback = `full document ${(err as Error).message}`;
  }
  // Fallback: the package-level time, as a bound. For a pinned older version
  // this can only over-estimate youth, which errs toward review.
  info.publishedAtMs = modifiedMs;
  return info;
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
  version: string | undefined,
  /** The age window the caller judges by; inside it npm's per-version time is read. */
  freshWindowMs: number
): Promise<RegistryInfo | null> {
  return eco === 'npm' ? npmInfo(name, version, freshWindowMs) : pypiInfo(name, version);
}
