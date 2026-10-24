// src/supply-chain/provenance.ts
// Where a release was built, read from the registry's provenance record
// (node9Firewall#385). npm publishes SLSA provenance for a package built in CI
// with `--provenance` or trusted publishing; PyPI keeps PEP 740 attestations
// for a release uploaded through a Trusted Publisher. Both registries verify
// the record at upload, so node9 reads the source repository from it and
// compares it with the previous release's.
//
// A new version built from the same repository as the release before it is
// the ordinary shape of a project's own CI publishing; a release with no
// provenance after one that had it is the shape of a stolen token. Every
// lookup fails soft ('unknown') and never throws past the caller.
import { prerelease, rcompare, valid } from 'semver';
import type { PackageEcosystem } from '@node9/policy-engine';
import { endpoints, fetchJson } from './net';

const TIMEOUT_MS = 1500;

/** What a provenance lookup found: the source repository, `none` when the
 *  registry has no provenance for the release, `unknown` when it could not
 *  be read (a failure is never read as an absence). */
export type SourceRepo = string | 'none' | 'unknown';
/** One attestation document: two bundles, about 14 KB for esbuild. */
const MAX_BYTES = 256 * 1024;

/** `https://github.com/Owner/Repo.git` and `owner/repo` -> `github.com/owner/repo`. */
export function normalizeRepo(raw: string, host = 'github.com'): string | null {
  let s = raw.trim().toLowerCase();
  s = s.replace(/^git\+/, '').replace(/^[a-z]+:\/\//, '');
  s = s
    .replace(/@refs\/.*$/, '')
    .replace(/\.git$/, '')
    .replace(/\/+$/, '');
  if (!s.includes('.') || !s.split('/')[0].includes('.')) s = `${host}/${s}`;
  return /^[a-z0-9.-]+\/[\w.-]+\/[\w.-]+/.test(s) ? s : null;
}

/** The source repository named in an npm attestation document, or null. */
export function npmRepoOf(doc: unknown): string | null {
  const list = (doc as { attestations?: unknown[] } | null)?.attestations;
  if (!Array.isArray(list)) return null;
  for (const a of list) {
    const att = a as { predicateType?: string; bundle?: { dsseEnvelope?: { payload?: string } } };
    if (!att.predicateType?.startsWith('https://slsa.dev/provenance/')) continue;
    const payload = att.bundle?.dsseEnvelope?.payload;
    if (typeof payload !== 'string') continue;
    try {
      const statement = JSON.parse(Buffer.from(payload, 'base64').toString('utf8')) as {
        predicate?: {
          buildDefinition?: { externalParameters?: { workflow?: { repository?: string } } };
          invocation?: { configSource?: { uri?: string } };
        };
      };
      const p = statement.predicate;
      // SLSA v1, then v0.2 (npm's first provenance format).
      const repo =
        p?.buildDefinition?.externalParameters?.workflow?.repository ??
        p?.invocation?.configSource?.uri;
      if (typeof repo === 'string') return normalizeRepo(repo);
    } catch {
      /* an unreadable bundle names no repository */
    }
  }
  return null;
}

/**
 * Who uploaded a PyPI file, by its attestations, or null. A GitHub or GitLab
 * Trusted Publisher is named by its repository; Google's by the service
 * account it publishes as (`google:<email>`), the only identity it carries.
 */
export function pypiRepoOf(doc: unknown): string | null {
  const bundles = (doc as { attestation_bundles?: unknown[] } | null)?.attestation_bundles;
  if (!Array.isArray(bundles)) return null;
  for (const b of bundles) {
    const pub = (b as { publisher?: { kind?: string; repository?: string; email?: string } })
      .publisher;
    if (typeof pub?.repository === 'string') {
      const host = /gitlab/i.test(pub.kind ?? '') ? 'gitlab.com' : 'github.com';
      return normalizeRepo(pub.repository, host);
    }
    if (/^google$/i.test(pub?.kind ?? '') && typeof pub?.email === 'string') {
      return `google:${pub.email.trim().toLowerCase()}`;
    }
  }
  return null;
}

/** The repository an npm version was built from, by its provenance. */
export async function npmSourceRepo(name: string, version: string): Promise<SourceRepo> {
  const base = endpoints().npmRegistry;
  if (!base) return 'unknown';
  const url = `${base}/-/npm/v1/attestations/${name.replaceAll('/', '%2F')}@${encodeURIComponent(version)}`;
  return read(url, npmRepoOf);
}

async function read(url: string, repoOf: (doc: unknown) => string | null): Promise<SourceRepo> {
  try {
    const doc = await fetchJson(url, { timeoutMs: TIMEOUT_MS, maxBytes: MAX_BYTES });
    if (doc === null) return 'none';
    return repoOf(doc) ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

/** The repository a PyPI file was uploaded from, by its attestations (PyPI
 *  answers 404 for a file uploaded without them). */
export async function pypiSourceRepo(
  name: string,
  version: string,
  filename: string
): Promise<SourceRepo> {
  const base = endpoints().pypi;
  if (!base) return 'unknown';
  const url = `${base}/integrity/${encodeURIComponent(name)}/${encodeURIComponent(version)}/${encodeURIComponent(filename)}/provenance`;
  return read(url, pypiRepoOf);
}

// A final PyPI release: plain numbers (`2026.10.23`, `3.12`). Pre-, post- and
// dev-releases are not "the release before".
const PYPI_FINAL = /^\d+(?:\.\d+)*$/;

function comparePypi(a: string, b: string): number {
  const x = a.split('.').map(Number);
  const y = b.split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/**
 * The release before `version`: the highest final version below it. Null when
 * there is none (a first release); undefined when `version` cannot be ordered,
 * so the history is unknown.
 */
export function previousRelease(
  eco: PackageEcosystem,
  versions: string[],
  version: string
): string | null | undefined {
  if (eco === 'npm') {
    if (!valid(version)) return undefined;
    const below = versions.filter((v) => valid(v) && !prerelease(v) && rcompare(v, version) > 0);
    return below.sort(rcompare)[0] ?? null;
  }
  if (!PYPI_FINAL.test(version)) return undefined;
  const below = versions.filter((v) => PYPI_FINAL.test(v) && comparePypi(v, version) < 0);
  return below.sort((a, b) => comparePypi(b, a))[0] ?? null;
}
