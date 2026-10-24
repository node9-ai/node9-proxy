// src/supply-chain/check.ts
// The package check on the hook's hot path: for a shell command that installs
// or runs registry packages, decide block / review / allow before it runs.
//
//   known malicious (OSV MAL- record covers the version) → block (or review,
//       per policy.packageCheck.onMalicious), advisory id in the reason
//   a malicious record exists but the version is unknown → review
//   published under maxAgeHours, or an npm install script → review
//   ...unless the release is built from the same repository as the one before
//       it (registry provenance), and an install script the previous release
//       also ran is no signal (node9Firewall#385)
//   a release without the provenance its previous release had → review
//   anything else, and every lookup failure → allow
//
// Contract: never throws, never blocks because a lookup failed. Failures are
// returned as `misses` for the caller to record.
import picomatch from 'picomatch';
import path from 'path';
import {
  extractPackageInstalls,
  isBashTool,
  type PackageEcosystem,
  type PackageInstallRequest,
} from '@node9/policy-engine';
import { lookupIndex, entryCovers, type OsvEntry } from './osv-index';
import { queryOsvMalicious } from './osv-online';
import {
  HAS_REGISTRY_CLIENT,
  pypiHistory,
  registryInfo,
  type RegistryInfo,
  type ReleaseHistory,
} from './registry';
import { npmSourceRepo, pypiSourceRepo, type SourceRepo } from './provenance';
import { resolveInstalled, LOCAL_FIRST_MANAGERS } from './local-resolve';

export interface PackageCheckConfig {
  enabled: boolean;
  onMalicious: 'block' | 'review';
  newPackage: 'review' | 'off';
  maxAgeHours: number;
  installScript: 'review' | 'off';
  onlineFallback: boolean;
  allow: string[];
}

export interface PackageFinding {
  pkg: PackageInstallRequest;
  version?: string;
  /** The finding is about the copy already in node_modules, not a download. */
  installed?: boolean;
  kind: 'malicious' | 'malicious-unpinned' | 'new' | 'install-script' | 'provenance-drop';
  detail: string;
  advisories?: string[];
}

export interface PackageCheckResult {
  verdict: 'allow' | 'review' | 'block';
  reason?: string;
  findings: PackageFinding[];
  misses: string[];
  checked: number;
}

/**
 * At most this many packages per command get NETWORK lookups (registry,
 * OSV online). Every package, however many, is checked against the local
 * index: that costs one small file read, and capping it would let ten benign
 * names in front of a malicious one wave it through.
 */
const MAX_NETWORK_PACKAGES = 10;

const ALLOW: PackageCheckResult = { verdict: 'allow', findings: [], misses: [], checked: 0 };

function commandOf(toolName: string, args: unknown): string | null {
  if (!isBashTool(toolName) || !args || typeof args !== 'object') return null;
  const a = args as Record<string, unknown>;
  return typeof a.command === 'string' ? a.command : typeof a.cmd === 'string' ? a.cmd : null;
}

const KIND: Record<PackageEcosystem, string> = {
  npm: 'npm package',
  PyPI: 'PyPI package',
  RubyGems: 'RubyGems package',
  'crates.io': 'crates.io package',
  Go: 'Go module',
  NuGet: 'NuGet package',
  Maven: 'Maven artifact',
  Packagist: 'Packagist package',
  VSCode: 'VS Code extension',
};

function label(p: PackageInstallRequest, version?: string): string {
  return `${KIND[p.ecosystem]} "${p.name}${version ? `@${version}` : ''}"`;
}

/**
 * The names OSV may file this package under. A Go command names a package
 * path (`host/owner/repo/cmd/tool`) and OSV names the module that contains it,
 * so every prefix of two or more elements is a candidate, longest first
 * (at most six). Every other ecosystem: the name itself.
 */
export function osvNames(p: PackageInstallRequest): string[] {
  if (p.ecosystem !== 'Go') return [p.name];
  const parts = p.name.split('/');
  const out: string[] = [];
  for (let n = parts.length; n >= 2 && out.length < 6; n--) out.push(parts.slice(0, n).join('/'));
  return out;
}

/** Malicious lookup for one package: local index first, OSV online on a gap. */
async function maliciousFor(
  p: PackageInstallRequest,
  version: string | undefined,
  cfg: PackageCheckConfig,
  misses: string[],
  networkCapped: boolean
): Promise<PackageFinding | null> {
  const names = osvNames(p);
  const local = names.map((n) => lookupIndex(p.ecosystem, n));
  const hits = local.flatMap((l) => (l.status === 'hit' ? l.entries : []));
  const entries: OsvEntry[] | null = hits.length > 0 ? hits : null;
  const freshClean = local.every((l) => l.status === 'clean' && l.fresh);
  const status = local.some((l) => l.status === 'unavailable') ? 'unavailable' : local[0].status;

  if (!entries && !freshClean) {
    // No index, or a stale one that has nothing: ask OSV online.
    if (!cfg.onlineFallback || networkCapped) {
      misses.push(
        `${label(p, version)}: local index ${status}, no online lookup (${networkCapped ? 'over the per-command network cap' : 'online fallback off'})`
      );
      return null;
    }
    let perName: string[][] | null = null;
    try {
      perName = await queryOsvMalicious(
        names.map((name) => ({ ecosystem: p.ecosystem, name, version }))
      );
    } catch (err) {
      misses.push(`${label(p, version)}: OSV online ${(err as Error).message}`);
      return null;
    }
    const ids = perName ? [[...new Set(perName.flat())]] : null;
    if (!ids) {
      misses.push(`${label(p, version)}: OSV online unavailable`);
      return null;
    }
    if (ids[0].length === 0) return null;
    // Online with a version answers exactly; without one it means "some version".
    return version
      ? {
          pkg: p,
          version,
          kind: 'malicious',
          advisories: ids[0],
          detail: `${label(p, version)} (${ids[0].join(', ')})`,
        }
      : {
          pkg: p,
          kind: 'malicious-unpinned',
          advisories: ids[0],
          detail: `${label(p)} has known malicious versions (${ids[0].join(', ')}); pin a version that is not affected`,
        };
  }
  if (!entries) return null;

  const covering = entries.filter((e) => entryCovers(e, version) === true).map((e) => e.id);
  if (covering.length > 0) {
    return {
      pkg: p,
      version,
      kind: 'malicious',
      advisories: covering,
      detail: `${label(p, version)} (${covering.join(', ')})`,
    };
  }
  const unknown = entries.filter((e) => entryCovers(e, version) === 'unknown').map((e) => e.id);
  if (unknown.length > 0) {
    return {
      pkg: p,
      kind: 'malicious-unpinned',
      advisories: unknown,
      detail: `${label(p)} has known malicious versions (${unknown.join(', ')}); pin a version that is not affected`,
    };
  }
  return null;
}

/** `npx <pkg>` with a copy in node_modules runs that copy: the install is in
 *  the past, so only the index matters (a hit still blocks, the run is now),
 *  and nothing is asked of the registry or OSV online. */
function checkInstalled(
  p: PackageInstallRequest,
  version: string,
  misses: string[]
): PackageFinding[] {
  const local = lookupIndex(p.ecosystem, p.name);
  if (local.status === 'unavailable') {
    misses.push(`${label(p, version)}: installed copy, local index unavailable`);
    return [];
  }
  if (local.status !== 'hit') return [];
  const covering = local.entries.filter((e) => entryCovers(e, version) === true).map((e) => e.id);
  if (covering.length === 0) return [];
  return [
    {
      pkg: p,
      version,
      installed: true,
      kind: 'malicious',
      advisories: covering,
      detail: `installed ${label(p, version)} (${covering.join(', ')})`,
    },
  ];
}

async function checkOne(
  p: PackageInstallRequest,
  cfg: PackageCheckConfig,
  misses: string[],
  networkCapped: boolean,
  cwd: string | undefined
): Promise<PackageFinding[]> {
  if (
    p.ecosystem === 'npm' &&
    LOCAL_FIRST_MANAGERS.has(p.manager) &&
    p.localCwd !== null &&
    (p.raw === p.name || p.version)
  ) {
    const localCwd =
      cwd && path.isAbsolute(cwd)
        ? (p.localCwd ?? []).reduce((dir, step) => path.resolve(dir, step), cwd)
        : undefined;
    const installed = resolveInstalled(p.name, localCwd);
    if (installed && (!p.version || p.version === installed.version))
      return checkInstalled(p, installed.version, misses);
  }
  const findings: PackageFinding[] = [];
  let info: RegistryInfo | null = null;
  // Registry metadata exists for npm and PyPI only; the other ecosystems are
  // checked against OSV alone, and no request leaves for a registry that
  // would answer for a different ecosystem.
  const wantsRegistry =
    (cfg.newPackage !== 'off' || cfg.installScript !== 'off') &&
    HAS_REGISTRY_CLIENT.has(p.ecosystem);
  if (wantsRegistry && !networkCapped) {
    try {
      // With the age signal off there is no window, so the per-version time
      // (a second, larger request) is never fetched.
      const windowMs = cfg.newPackage === 'off' ? 0 : cfg.maxAgeHours * 3_600_000;
      info = await registryInfo(p.ecosystem, p.name, p.version, windowMs, p.raw);
      if (!info) misses.push(`${label(p, p.version)}: registry metadata unavailable`);
      else if (info.ageFallback)
        misses.push(
          `${label(p, info.version)}: ${
            info.publishedAtMs === undefined
              ? 'publish time unavailable'
              : 'age from the package modified time'
          } (${info.ageFallback})`
        );
    } catch (err) {
      misses.push(`${label(p, p.version)}: registry ${(err as Error).message}`);
    }
  }
  const version = p.version ?? info?.version;

  const mal = await maliciousFor(p, version, cfg, misses, networkCapped);
  if (mal) findings.push(mal);

  if (cfg.newPackage !== 'off' && info?.publishedAtMs !== undefined) {
    const ageH = (Date.now() - info.publishedAtMs) / 3_600_000;
    if (ageH >= 0 && ageH < cfg.maxAgeHours) {
      findings.push({
        pkg: p,
        version,
        kind: 'new',
        detail: info.ageFallback
          ? `${label(p, version)} has package metadata updated ${Math.max(1, Math.round(ageH))}h ago (under ${cfg.maxAgeHours}h); version publish time unavailable`
          : `${label(p, version)} was published ${Math.max(1, Math.round(ageH))}h ago (under ${cfg.maxAgeHours}h)`,
      });
    }
  }
  if (cfg.installScript !== 'off' && info?.hasInstallScript) {
    findings.push({
      pkg: p,
      version,
      kind: 'install-script',
      detail: `${label(p, version)} runs an install script`,
    });
  }
  if (info && version && (cfg.newPackage !== 'off' || cfg.installScript !== 'off')) {
    return byHistory(p, version, info, findings, misses);
  }
  return findings;
}

const SOFT: ReadonlySet<PackageFinding['kind']> = new Set(['new', 'install-script']);

/**
 * Weigh the age and install-script findings against the release before this
 * one (node9Firewall#385):
 *
 *   an install script the previous release also ran is how the package has
 *   always installed (esbuild, bcrypt): no finding. A script that appears in
 *   this release, a first release, or an unknown history keep it.
 *
 *   a release built from the same source repository as the previous one, both
 *   by registry provenance, is the project's own CI publishing: its age and
 *   install-script findings are dropped. A release without the provenance its
 *   previous release had is a finding of its own, whatever its age.
 *
 * Malicious findings are never touched. Every lookup that fails leaves the
 * findings as they were and records a miss.
 */
async function byHistory(
  p: PackageInstallRequest,
  version: string,
  info: RegistryInfo,
  findings: PackageFinding[],
  misses: string[]
): Promise<PackageFinding[]> {
  let out = findings;
  let h: ReleaseHistory | undefined = info.history;
  if (!h && p.ecosystem === 'PyPI' && out.some((f) => SOFT.has(f.kind))) {
    try {
      h = (await pypiHistory(p.name, version)) ?? undefined;
    } catch (err) {
      misses.push(`${label(p, version)}: release history ${(err as Error).message}`);
    }
  }
  if (!h || !h.previous) return out;
  const previous = h.previous;

  if (h.previousHasInstallScript === true) {
    out = out.filter((f) => f.kind !== 'install-script');
  }

  const drop = (): PackageFinding => ({
    pkg: p,
    version,
    kind: 'provenance-drop',
    detail: `${label(p, version)} was published without the provenance its previous release (${previous}) had`,
  });

  if (p.ecosystem === 'npm') {
    // The abbreviated document says per version whether provenance exists, so
    // a drop costs no request and is a finding even outside the age window.
    if (h.previousProvenance && h.provenance === false) return [...out, drop()];
    if (!out.some((f) => SOFT.has(f.kind)) || !h.provenance || !h.previousProvenance) return out;
    const [now, before] = await Promise.all([
      npmSourceRepo(p.name, version),
      npmSourceRepo(p.name, previous),
    ]);
    return vouched(p, version, now, before, out, misses);
  }

  if (p.ecosystem === 'PyPI') {
    if (!out.some((f) => SOFT.has(f.kind)) || !info.file || !h.previousFile) return out;
    const [now, before] = await Promise.all([
      pypiSourceRepo(p.name, version, info.file),
      pypiSourceRepo(p.name, previous, h.previousFile),
    ]);
    if (now === 'none' && before !== 'none' && before !== 'unknown') return [...out, drop()];
    return vouched(p, version, now, before, out, misses);
  }
  return out;
}

function vouched(
  p: PackageInstallRequest,
  version: string,
  now: SourceRepo,
  before: SourceRepo,
  findings: PackageFinding[],
  misses: string[]
): PackageFinding[] {
  if (now === 'unknown' || before === 'unknown') {
    misses.push(`${label(p, version)}: provenance unreadable, findings kept`);
    return findings;
  }
  if (now === 'none' || before === 'none' || now !== before) return findings;
  return findings.filter((f) => !SOFT.has(f.kind));
}

/**
 * Run the package check for one tool call. Fast exit (no I/O) when the call
 * is not a shell command or installs nothing.
 */
export async function runPackageCheck(
  toolName: string,
  args: unknown,
  cfg: PackageCheckConfig,
  /** The hook's validated absolute working directory; where `npx` looks for node_modules. */
  cwd?: string
): Promise<PackageCheckResult> {
  if (!cfg.enabled) return ALLOW;
  try {
    const command = commandOf(toolName, args);
    if (!command) return ALLOW;
    const isAllowed = cfg.allow.length > 0 ? picomatch(cfg.allow) : () => false;
    const requests = extractPackageInstalls(command).filter((p) => !isAllowed(p.name));
    if (requests.length === 0) return ALLOW;

    const misses: string[] = [];
    const checked = requests;
    const settled = await Promise.allSettled(
      checked.map((p, i) => checkOne(p, cfg, misses, i >= MAX_NETWORK_PACKAGES, cwd))
    );
    const findings: PackageFinding[] = [];
    settled.forEach((s, i) => {
      if (s.status === 'fulfilled') findings.push(...s.value);
      else misses.push(`${label(checked[i])}: ${(s.reason as Error)?.message ?? 'check failed'}`);
    });

    const malicious = findings.filter((f) => f.kind === 'malicious');
    if (malicious.length > 0 && cfg.onMalicious === 'block') {
      return {
        verdict: 'block',
        reason: `📦 Known malicious package: ${malicious.map((f) => f.detail).join('; ')}`,
        findings,
        misses,
        checked: checked.length,
      };
    }
    if (findings.length > 0) {
      return {
        verdict: 'review',
        reason: `📦 Package check: ${findings.map((f) => f.detail).join('; ')}`,
        findings,
        misses,
        checked: checked.length,
      };
    }
    return { verdict: 'allow', findings, misses, checked: checked.length };
  } catch (err) {
    // The check itself failed: fail open, and say so.
    return { ...ALLOW, misses: [`package check error: ${(err as Error)?.message ?? err}`] };
  }
}
