// src/supply-chain/registry.ts
// Registry signals for a package about to be installed: the version the
// install would resolve to, how recently it was published, and (npm) whether
// it runs an install script. Every function fails soft: a failed lookup
// returns `null` and the caller records a miss.
import { maxSatisfying, satisfies, validRange } from 'semver';
import type { PackageEcosystem } from '@node9/policy-engine';
import { endpoints, fetchJson } from './net';
import { previousRelease } from './provenance';

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
  /** What the registry says about the release before this one; absent when
   *  node9 could not read the version list (a document over the size cap). */
  history?: ReleaseHistory;
  /** PyPI: one file of this release, the key of its provenance record. */
  file?: string;
  /** npm: the package was removed as malicious and a `-security` holding
   *  version is all the registry serves (node9Firewall#385, wave 3). */
  placeholder?: boolean;
  /** When the package's first release was published (epoch ms), where the
   *  document read already says: PyPI's project document, npm's full one. */
  createdAtMs?: number;
}

/** What a package has to its name, for the lookalike check: its age and,
 *  on npm, its downloads last week. A field is absent when unreadable. */
export interface Standing {
  createdAtMs?: number;
  weeklyDownloads?: number;
}

/** `absent`: the registry answered that no package has this name (a 404 on
 *  the package document). `null`: the lookup failed or was ambiguous. */
export type RegistryLookup = RegistryInfo | 'absent' | null;

/** The release before the resolved one (node9Firewall#385). */
export interface ReleaseHistory {
  /** The previous final release; null when this is the first. */
  previous: string | null;
  /** npm: whether the previous release ran an install script. */
  previousHasInstallScript?: boolean;
  /** npm: whether this release and the previous one carry provenance (the
   *  abbreviated document says so per version). PyPI: unknown until asked. */
  provenance?: boolean;
  previousProvenance?: boolean;
  /** PyPI: one file of the previous release. */
  previousFile?: string;
  /** When the previous release was published (epoch ms), where the document
   *  read says: npm's full document, PyPI's project document. */
  previousPublishedAtMs?: number;
}

const TIMEOUT_MS = 2000;
/**
 * The largest registry documents measured on 2026-11-07: nx's abbreviated
 * document 6.2 MB, typescript's 8.8 MB, react's 3.0 MB, boto3's PyPI project
 * document 3.3 MB (its simple-API document is 2.2 MB, so no smaller route
 * exists). Under the old 2 MB cap those lost their version list, so the
 * release history and the age signal did not run for the largest projects
 * (node9Firewall#393). 16 MB reads them all; a document over it still falls
 * back as before. The timeout grew with it: typescript's arrives in about
 * 1.2 s on a good link.
 */
const MAX_BYTES = 16 * 1024 * 1024;
/** A version document (`/<name>/latest`) is one manifest: nx's is about 13 KB. */
const VERSION_DOC_MAX_BYTES = 256 * 1024;
const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall'];

/**
 * The version document of one tag or version, read when the abbreviated
 * document is over MAX_BYTES (rare since fw#393 raised it to 16 MB): it
 * still names the resolved version and its scripts, so the package is not
 * left with no version at all, which read as "has known malicious versions"
 * whenever the record covered any version (fw#372 A10). It carries no publish
 * time, so the age signal is unavailable and recorded as a miss.
 */
async function npmVersionDocument(url: string, selector: string): Promise<RegistryInfo | null> {
  const doc = (await fetchJson(`${url}/${encodeURIComponent(selector)}`, {
    timeoutMs: TIMEOUT_MS,
    maxBytes: VERSION_DOC_MAX_BYTES,
  })) as { version?: string; scripts?: Record<string, unknown> } | null;
  if (!doc?.version) return null;
  const scripts = doc.scripts ?? {};
  return {
    version: doc.version,
    hasInstallScript: INSTALL_SCRIPTS.some(
      (k) => typeof scripts[k] === 'string' && (scripts[k] as string).length > 0
    ),
    ageFallback: `abbreviated document over the size cap; version read from /${selector}, which has no publish time`,
  };
}

/**
 * The abbreviated npm document carries one package-level `modified` time and
 * no per-version times, and ANY publish moves it (a `next` or `beta` tag
 * included). So `modified` is only a hint: when it falls inside the window
 * the caller cares about, the full document is read for `time[version]`,
 * capped at MAX_BYTES (nx's full document is 14 MB). Over the cap or unavailable, the
 * hint stands (the conservative side) and `ageFallback` says so.
 */
async function npmInfo(
  name: string,
  version: string | undefined,
  freshWindowMs: number,
  raw?: string
): Promise<RegistryLookup> {
  const base = endpoints().npmRegistry;
  if (!base) return null;
  // Every slash, not the first: a valid scoped name has one, and a name with
  // more must not reach another registry path (CodeQL js/incomplete-sanitization).
  const url = `${base}/${name.replaceAll('/', '%2F')}`;
  // Preserve the requested tag/range: latest is only the default for a bare name.
  const aliasStart = raw?.indexOf('@npm:') ?? -1;
  const target = aliasStart > 0 ? raw!.slice(aliasStart + 5) : raw?.replace(/^npm:/, '');
  const specStart = target?.indexOf('@', 1) ?? -1;
  const spec = specStart > 0 ? target!.slice(specStart + 1) : '';
  let doc: {
    modified?: string;
    'dist-tags'?: Record<string, string>;
    versions?: Record<
      string,
      { hasInstallScript?: boolean; dist?: { attestations?: { provenance?: unknown } } }
    >;
  } | null;
  try {
    doc = (await fetchJson(url, {
      timeoutMs: TIMEOUT_MS,
      maxBytes: MAX_BYTES,
      headers: { Accept: 'application/vnd.npm.install-v1+json' },
    })) as typeof doc;
  } catch (err) {
    if (!/too large/.test((err as Error).message)) throw err;
    // A pinned version or a dist-tag has its own document. A range cannot be
    // resolved without the version list: `latest` stands in only when it
    // satisfies the range (npm's own preference); otherwise no version is
    // claimed, and the caller treats the install as unpinned.
    const range = !version && spec && validRange(spec) ? spec : null;
    const selector = version ?? (spec && !range ? spec : 'latest');
    const info = await npmVersionDocument(url, selector);
    if (info && range && !satisfies(info.version, range)) return null;
    return info;
  }
  // fetchJson answers a 404 with null: no package has this name.
  if (!doc) return 'absent';
  const latest = doc['dist-tags']?.latest;
  let resolved = version;
  if (!resolved) {
    if (!spec) resolved = latest;
    else if (doc['dist-tags']?.[spec]) resolved = doc['dist-tags'][spec];
    else if (validRange(spec)) {
      // npm prefers the default tag if it satisfies the requested range.
      resolved =
        latest && satisfies(latest, spec)
          ? latest
          : (maxSatisfying(Object.keys(doc.versions ?? {}), spec) ?? undefined);
    }
  }
  if (!resolved) return null;
  const v = doc.versions?.[resolved];
  const modifiedMs = doc.modified ? Date.parse(doc.modified) : NaN;
  const versionKeys = Object.keys(doc.versions ?? {});
  const info: RegistryInfo = {
    version: resolved,
    hasInstallScript: v?.hasInstallScript === true,
  };
  // npm's takeover marker: one version, named `0.0.1-security` (or alike).
  if (versionKeys.length === 1 && /-security$/.test(resolved)) info.placeholder = true;
  const previous = previousRelease('npm', versionKeys, resolved);
  if (v && previous !== undefined) {
    const pv = previous ? doc.versions?.[previous] : undefined;
    info.history = {
      previous,
      previousHasInstallScript: pv ? pv.hasInstallScript === true : undefined,
      provenance: !!v.dist?.attestations?.provenance,
      previousProvenance: pv ? !!pv.dist?.attestations?.provenance : undefined,
    };
  }
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
    const created = full?.time?.created ? Date.parse(full.time.created) : NaN;
    if (Number.isFinite(created)) info.createdAtMs = created;
    const prevT = info.history?.previous ? full?.time?.[info.history.previous] : undefined;
    const prevMs = prevT ? Date.parse(prevT) : NaN;
    if (info.history && Number.isFinite(prevMs)) info.history.previousPublishedAtMs = prevMs;
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

async function pypiInfo(name: string, version?: string): Promise<RegistryLookup> {
  const base = endpoints().pypi;
  if (!base) return null;
  const url = version
    ? `${base}/pypi/${encodeURIComponent(name)}/${encodeURIComponent(version)}/json`
    : `${base}/pypi/${encodeURIComponent(name)}/json`;
  const doc = (await fetchJson(url, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_BYTES })) as PypiDoc;
  // The project document 404s only when no project has the name; a release
  // document 404s for a version the project never had, too, so a pinned
  // install's 404 says nothing about the name.
  if (doc === null) return version ? null : 'absent';
  if (!doc?.info?.version) return null;
  const times = (doc.urls ?? [])
    .map((u) => (u.upload_time_iso_8601 ? Date.parse(u.upload_time_iso_8601) : NaN))
    .filter((t) => Number.isFinite(t));
  const resolved = version ?? doc.info.version;
  const info: RegistryInfo = {
    version: resolved,
    // The earliest file of the release is when it became installable.
    publishedAtMs: times.length > 0 ? Math.min(...times) : undefined,
    file: doc.urls?.find((u) => typeof u.filename === 'string')?.filename,
  };
  // The project document (an unpinned install) lists every release.
  if (doc.releases) {
    info.history = pypiHistoryOf(doc.releases, resolved) ?? undefined;
    info.createdAtMs = pypiCreatedOf(doc.releases);
  }
  return info;
}

/** The earliest upload across every release: when the project first existed. */
function pypiCreatedOf(
  releases: NonNullable<NonNullable<PypiDoc>['releases']>
): number | undefined {
  let min = Infinity;
  for (const files of Object.values(releases)) {
    for (const f of files ?? []) {
      const t = f.upload_time_iso_8601 ? Date.parse(f.upload_time_iso_8601) : NaN;
      if (Number.isFinite(t) && t < min) min = t;
    }
  }
  return Number.isFinite(min) ? min : undefined;
}

/**
 * The standing of a package whose name looks like a popular one
 * (node9Firewall#385, wave 3): npm's full document for `time.created` (small
 * for a package with few versions, which a lookalike is) and its downloads
 * last week; PyPI's project document for the earliest upload. Each part that
 * cannot be read is left out; the caller records the miss.
 */
export async function registryStanding(
  eco: PackageEcosystem,
  name: string,
  /** Which parts to read; a part the caller already has is not fetched again. */
  want: { created: boolean; downloads: boolean } = { created: true, downloads: true }
): Promise<Standing> {
  const out: Standing = {};
  const ep = endpoints();
  if (eco === 'npm' && ep.npmRegistry) {
    const encoded = name.replaceAll('/', '%2F');
    const [full, downloads] = await Promise.all([
      want.created
        ? fetchJson(`${ep.npmRegistry}/${encoded}`, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_BYTES })
            .then((d) => d as { time?: { created?: string } } | null)
            .catch(() => undefined)
        : Promise.resolve(undefined),
      want.downloads && ep.npmDownloads
        ? fetchJson(`${ep.npmDownloads}/downloads/point/last-week/${encoded}`, {
            timeoutMs: TIMEOUT_MS,
            maxBytes: 64 * 1024,
          })
            .then((d) => d as { downloads?: number } | null)
            .catch(() => undefined)
        : Promise.resolve(undefined),
    ]);
    const created = full?.time?.created ? Date.parse(full.time.created) : NaN;
    if (Number.isFinite(created)) out.createdAtMs = created;
    // The downloads API answers 404 with a body for a name it never counted;
    // fetchJson maps that to null, which is "no downloads" too.
    if (downloads === null) out.weeklyDownloads = 0;
    else if (typeof downloads?.downloads === 'number') out.weeklyDownloads = downloads.downloads;
  } else if (eco === 'PyPI' && ep.pypi && want.created) {
    const doc = (await fetchJson(`${ep.pypi}/pypi/${encodeURIComponent(name)}/json`, {
      timeoutMs: TIMEOUT_MS,
      maxBytes: MAX_BYTES,
    }).catch(() => undefined)) as PypiDoc | undefined;
    if (doc?.releases) out.createdAtMs = pypiCreatedOf(doc.releases);
  }
  return out;
}

type PypiDoc = {
  info?: { version?: string };
  urls?: Array<{ upload_time_iso_8601?: string; filename?: string }>;
  releases?: Record<
    string,
    Array<{ filename?: string; yanked?: boolean; upload_time_iso_8601?: string }>
  >;
} | null;

function pypiHistoryOf(
  releases: NonNullable<NonNullable<PypiDoc>['releases']>,
  version: string
): ReleaseHistory | null {
  // A release with no files (all deleted) cannot be installed: not "the one before".
  const versions = Object.keys(releases).filter((v) => (releases[v] ?? []).length > 0);
  const previous = previousRelease('PyPI', versions, version);
  if (previous === undefined) return null;
  const previousPublishedAtMs = previous
    ? pypiCreatedOf({ [previous]: releases[previous] })
    : undefined;
  return {
    previous,
    previousFile: previous
      ? releases[previous]?.find((f) => typeof f.filename === 'string')?.filename
      : undefined,
    previousPublishedAtMs,
  };
}

/**
 * The release history of a pinned PyPI install, read only when a finding is
 * on the table (its project document is the large one: every release). Null
 * when it cannot be read.
 */
export async function pypiHistory(
  name: string,
  version: string
): Promise<{ history: ReleaseHistory; createdAtMs?: number } | null> {
  const base = endpoints().pypi;
  if (!base) return null;
  const doc = (await fetchJson(`${base}/pypi/${encodeURIComponent(name)}/json`, {
    timeoutMs: TIMEOUT_MS,
    maxBytes: MAX_BYTES,
  })) as PypiDoc;
  if (!doc?.releases) return null;
  const history = pypiHistoryOf(doc.releases, version);
  return history ? { history, createdAtMs: pypiCreatedOf(doc.releases) } : null;
}

/**
 * The ecosystems node9 reads registry metadata for (version resolution, publish
 * age, install scripts). The others are checked against OSV only.
 */
export const HAS_REGISTRY_CLIENT: ReadonlySet<PackageEcosystem> = new Set(['npm', 'PyPI']);

export async function registryInfo(
  eco: PackageEcosystem,
  name: string,
  version: string | undefined,
  /** The age window the caller judges by; inside it npm's per-version time is read. */
  freshWindowMs: number,
  raw?: string
): Promise<RegistryLookup> {
  if (eco === 'npm') return npmInfo(name, version, freshWindowMs, raw);
  if (eco === 'PyPI') return pypiInfo(name, version);
  return null;
}
