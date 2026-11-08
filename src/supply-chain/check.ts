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
//   ...and, with establishedAge off (Standard), a young release of a package
//       over a year old that released within the last 180 days is its normal
//       cadence, not a signal; Strict keeps asking (node9Firewall#385 wave 3)
//   a release without the provenance its previous release had → review
//   no package by that name on npm or PyPI, or npm's security holding package
//       in its place → review (node9Firewall#385 wave 3; policy.packageCheck
//       .lookalike), unless the install can come from a registry the user set up
//   a name one edit (or a separator, a scope, a padding word) away from one of
//       the most downloaded names, when the package is absent, under a year old
//       or (npm) under 1,000 downloads a week → review (same knob)
//   anything else, and every lookup failure → allow
//
// The registry also names the version an unpinned install resolves to, so it
// is asked for that even when both signals are off (node9Firewall#412).
//
// Contract: never throws, never blocks because a lookup failed. Failures are
// returned as `misses` for the caller to record.
import picomatch from 'picomatch';
import path from 'path';
import {
  extractPackageInstalls,
  extractRegistryOverrides,
  isBashTool,
  isPublicRegistryHost,
  type PackageEcosystem,
  type PackageInstallRequest,
} from '@node9/policy-engine';
import { lookupIndex, entryCovers, type OsvEntry } from './osv-index';
import { queryOsvMalicious } from './osv-online';
import {
  HAS_REGISTRY_CLIENT,
  pypiHistory,
  registryInfo,
  registryStanding,
  type RegistryInfo,
  type ReleaseHistory,
} from './registry';
import { npmSourceRepo, pypiSourceRepo, type SourceRepo } from './provenance';
import { resolveInstalled, LOCAL_FIRST_MANAGERS } from './local-resolve';
import { configuredRegistryHosts } from './registries';
import { describeNearMiss, nearMiss } from './lookalike';

export interface PackageCheckConfig {
  enabled: boolean;
  onMalicious: 'block' | 'review';
  newPackage: 'review' | 'off';
  maxAgeHours: number;
  installScript: 'review' | 'off';
  /** A name that looks like a popular one, does not exist on the registry,
   *  or was removed as malicious (node9Firewall#385, wave 3). */
  lookalike: 'review' | 'off';
  /** Whether a young release of an established package (first release over
   *  a year ago, the previous one within 180 days) still asks for its age
   *  alone. Off at Standard, review at Strict (node9Firewall#385, wave 3). */
  establishedAge: 'review' | 'off';
  onlineFallback: boolean;
  allow: string[];
}

/** What the check knows about the command around the package. */
interface CheckContext {
  command: string;
  /** The hook's validated absolute working directory. */
  cwd?: string;
  /** Whether an install in this command can only come from the public
   *  registry; worked out once per command, on the first name that needs it. */
  publicRegistryOnly: () => boolean;
}

export interface PackageFinding {
  pkg: PackageInstallRequest;
  version?: string;
  /** The finding is about the copy already in node_modules, not a download. */
  installed?: boolean;
  kind:
    | 'malicious'
    | 'malicious-unpinned'
    | 'new'
    | 'install-script'
    | 'provenance-drop'
    | 'absent'
    | 'placeholder'
    | 'lookalike';
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

const REGISTRY_NAME: Partial<Record<PackageEcosystem, string>> = { npm: 'npm', PyPI: 'PyPI' };

/** A lookalike younger than this has no standing by age. */
const LOOKALIKE_MAX_AGE_MS = 365 * 24 * 3_600_000;
/** An npm lookalike under this many downloads a week has no standing by use. */
const LOOKALIKE_MIN_WEEKLY_DOWNLOADS = 1000;

/**
 * Whether an install in this command can only come from the public registry:
 * no registry or index named on the command line, and none in the user's
 * package-manager configuration (registries.ts). A 404 from the public
 * registry proves nothing about a name a private registry may serve.
 */
function publicRegistryOnly(command: string, cwd: string | undefined): boolean {
  if (extractRegistryOverrides(command).length > 0) return false;
  for (const host of configuredRegistryHosts(cwd)) {
    if (!isPublicRegistryHost(host)) return false;
  }
  return true;
}

function contextFor(command: string, cwd: string | undefined): CheckContext {
  let publicOnly: boolean | undefined;
  return {
    command,
    cwd,
    publicRegistryOnly: () => (publicOnly ??= publicRegistryOnly(command, cwd)),
  };
}

/**
 * The lookalike finding for a name that resembles a popular one
 * (node9Firewall#385, wave 3), or null when the package has standing of its
 * own: absent from the registry → finding; first published under a year ago
 * → finding; otherwise (npm) its downloads last week decide, under 1,000 →
 * finding. Age and downloads both unreadable is a miss, never a finding.
 */
async function lookalikeFinding(
  p: PackageInstallRequest,
  version: string | undefined,
  info: RegistryInfo | null,
  absent: boolean,
  ctx: CheckContext,
  misses: string[]
): Promise<PackageFinding | null> {
  const near = await nearMiss(p.ecosystem, p.name);
  if (!near) return null;
  const alike = `${label(p)} looks like "${near.popular}" (${describeNearMiss(near)})`;
  if (absent) {
    if (!ctx.publicRegistryOnly()) return null;
    return {
      pkg: p,
      kind: 'lookalike',
      detail: `${alike} and does not exist on ${REGISTRY_NAME[p.ecosystem]}`,
    };
  }
  if (!info) return null;
  // The creation time the document already gave is kept; the downloads are
  // asked whenever the age alone does not make the finding.
  const standing = await registryStanding(p.ecosystem, p.name, {
    created: info.createdAtMs === undefined,
    downloads: p.ecosystem === 'npm',
  });
  const createdAtMs = info.createdAtMs ?? standing.createdAtMs;
  const ageMs = createdAtMs !== undefined ? Date.now() - createdAtMs : NaN;
  if (Number.isFinite(ageMs) && ageMs < LOOKALIKE_MAX_AGE_MS) {
    return {
      pkg: p,
      version,
      kind: 'lookalike',
      detail: `${alike} and was first published ${Math.max(1, Math.round(ageMs / 86_400_000))} days ago`,
    };
  }
  if (
    p.ecosystem === 'npm' &&
    standing.weeklyDownloads !== undefined &&
    standing.weeklyDownloads < LOOKALIKE_MIN_WEEKLY_DOWNLOADS
  ) {
    return {
      pkg: p,
      version,
      kind: 'lookalike',
      detail: `${alike} and had ${standing.weeklyDownloads} downloads last week`,
    };
  }
  if (
    !Number.isFinite(ageMs) &&
    (p.ecosystem !== 'npm' || standing.weeklyDownloads === undefined)
  ) {
    misses.push(`${alike}: its age and downloads could not be read, so it is not a finding`);
  }
  return null;
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
  ctx: CheckContext
): Promise<PackageFinding[]> {
  const { cwd } = ctx;
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
  let absent = false;
  // Registry metadata exists for npm and PyPI only; the other ecosystems are
  // checked against OSV alone, and no request leaves for a registry that
  // would answer for a different ecosystem. With both signals off the
  // registry is still asked for an unpinned install: it names the version the
  // install gets, and without it a record on any old version reads as "has
  // known malicious versions" (node9Firewall#412, the Soft level).
  const wantsRegistry =
    (cfg.newPackage !== 'off' ||
      cfg.installScript !== 'off' ||
      cfg.lookalike !== 'off' ||
      !p.version) &&
    HAS_REGISTRY_CLIENT.has(p.ecosystem);
  if (wantsRegistry && !networkCapped) {
    try {
      // With the age signal off there is no window, so the per-version time
      // (a second, larger request) is never fetched.
      const windowMs = cfg.newPackage === 'off' ? 0 : cfg.maxAgeHours * 3_600_000;
      const looked = await registryInfo(p.ecosystem, p.name, p.version, windowMs, p.raw);
      // An absent name is still asked of OSV below: a removed malicious
      // package keeps its record.
      if (looked === 'absent') absent = true;
      else info = looked;
      if (!absent && !info) misses.push(`${label(p, p.version)}: registry metadata unavailable`);
      else if (info?.ageFallback)
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

  // `absent` is only ever true after a registry answer, so this block never
  // runs over the network cap.
  if (cfg.lookalike !== 'off' && (absent || info)) {
    const alike = await lookalikeFinding(p, version, info, absent, ctx, misses);
    if (alike) findings.push(alike);
    else if (absent && ctx.publicRegistryOnly()) {
      findings.push({
        pkg: p,
        kind: 'absent',
        detail: `${label(p)} does not exist on ${REGISTRY_NAME[p.ecosystem]}; a name an agent invents can be registered by anyone`,
      });
    }
  }
  if (info?.placeholder && cfg.lookalike !== 'off') {
    findings.push({
      pkg: p,
      version,
      kind: 'placeholder',
      detail: `${label(p)} was removed by npm as malicious; what remains is a security holding package`,
    });
  }

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
    return byHistory(p, version, info, findings, misses, cfg);
  }
  return findings;
}

const SOFT: ReadonlySet<PackageFinding['kind']> = new Set(['new', 'install-script']);

/** A package older than this has standing of its own. */
const ESTABLISHED_MS = 365 * 24 * 3_600_000;
/** A previous release older than this makes the young one a revival. */
const DORMANT_MS = 180 * 24 * 3_600_000;

/**
 * Option (b) of node9Firewall#385 wave 3: the age finding on an established
 * package is its normal release cadence, not a signal, when the package's
 * first release is over a year old and the previous release came within the
 * last 180 days. Kept when either time is unknown, when this is the first
 * release, or when the package was dormant (the revival pattern). The other
 * findings on the same release stand on their own.
 */
function establishedCadence(info: RegistryInfo, h: ReleaseHistory): boolean {
  if (info.createdAtMs === undefined || !h.previous || h.previousPublishedAtMs === undefined) {
    return false;
  }
  const now = Date.now();
  return now - info.createdAtMs >= ESTABLISHED_MS && now - h.previousPublishedAtMs < DORMANT_MS;
}

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
  misses: string[],
  cfg: PackageCheckConfig
): Promise<PackageFinding[]> {
  let out = findings;
  let h: ReleaseHistory | undefined = info.history;
  if (!h && p.ecosystem === 'PyPI' && out.some((f) => SOFT.has(f.kind))) {
    try {
      const read = await pypiHistory(p.name, version);
      if (read) {
        h = read.history;
        if (info.createdAtMs === undefined) info.createdAtMs = read.createdAtMs;
      }
    } catch (err) {
      misses.push(`${label(p, version)}: release history ${(err as Error).message}`);
    }
  }
  if (!h || !h.previous) return out;
  const previous = h.previous;

  if (h.previousHasInstallScript === true) {
    out = out.filter((f) => f.kind !== 'install-script');
  }
  if (cfg.establishedAge === 'off' && establishedCadence(info, h)) {
    out = out.filter((f) => f.kind !== 'new');
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
  cwd?: string,
  /** No request leaves the machine: the local OSV index and node_modules only.
   *  A forecast over history runs this way; what the index cannot answer is a
   *  miss, never an allow. */
  opts: { offline?: boolean } = {}
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
    const ctx = contextFor(command, cwd);
    const settled = await Promise.allSettled(
      checked.map((p, i) =>
        checkOne(p, cfg, misses, opts.offline === true || i >= MAX_NETWORK_PACKAGES, ctx)
      )
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
