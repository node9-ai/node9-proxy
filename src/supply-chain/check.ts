// src/supply-chain/check.ts
// The package check on the hook's hot path: for a shell command that installs
// or runs registry packages, decide block / review / allow before it runs.
//
//   known malicious (OSV MAL- record covers the version) → block (or review,
//       per policy.packageCheck.onMalicious), advisory id in the reason
//   a malicious record exists but the version is unknown → review
//   published under maxAgeHours, or an npm install script → review
//   anything else, and every lookup failure → allow
//
// Contract: never throws, never blocks because a lookup failed. Failures are
// returned as `misses` for the caller to record.
import picomatch from 'picomatch';
import {
  extractPackageInstalls,
  isBashTool,
  type PackageInstallRequest,
} from '@node9/policy-engine';
import { lookupIndex, entryCovers, type OsvEntry } from './osv-index';
import { queryOsvMalicious } from './osv-online';
import { registryInfo, type RegistryInfo } from './registry';

export interface PackageCheckConfig {
  enabled: boolean;
  onMalicious: 'block' | 'review';
  registrySignals: boolean;
  maxAgeHours: number;
  onlineFallback: boolean;
  allow: string[];
}

export interface PackageFinding {
  pkg: PackageInstallRequest;
  version?: string;
  kind: 'malicious' | 'malicious-unpinned' | 'new' | 'install-script';
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

function label(p: PackageInstallRequest, version?: string): string {
  return `${p.ecosystem === 'npm' ? 'npm' : 'PyPI'} package "${p.name}${version ? `@${version}` : ''}"`;
}

/** Malicious lookup for one package: local index first, OSV online on a gap. */
async function maliciousFor(
  p: PackageInstallRequest,
  version: string | undefined,
  cfg: PackageCheckConfig,
  misses: string[],
  networkCapped: boolean
): Promise<PackageFinding | null> {
  const local = lookupIndex(p.ecosystem, p.name);
  const entries: OsvEntry[] | null = local.status === 'hit' ? local.entries : null;

  if (!entries && !(local.status === 'clean' && local.fresh)) {
    // No index, or a stale one that has nothing: ask OSV online.
    if (!cfg.onlineFallback || networkCapped) {
      misses.push(
        `${label(p, version)}: local index ${local.status}, no online lookup (${networkCapped ? 'over the per-command network cap' : 'online fallback off'})`
      );
      return null;
    }
    let ids: string[][] | null = null;
    try {
      ids = await queryOsvMalicious([{ ecosystem: p.ecosystem, name: p.name, version }]);
    } catch (err) {
      misses.push(`${label(p, version)}: OSV online ${(err as Error).message}`);
      return null;
    }
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

async function checkOne(
  p: PackageInstallRequest,
  cfg: PackageCheckConfig,
  misses: string[],
  networkCapped: boolean
): Promise<PackageFinding[]> {
  const findings: PackageFinding[] = [];
  let info: RegistryInfo | null = null;
  if (cfg.registrySignals && !networkCapped) {
    try {
      info = await registryInfo(p.ecosystem, p.name, p.version);
      if (!info) misses.push(`${label(p, p.version)}: registry metadata unavailable`);
    } catch (err) {
      misses.push(`${label(p, p.version)}: registry ${(err as Error).message}`);
    }
  }
  const version = p.version ?? info?.version;

  const mal = await maliciousFor(p, version, cfg, misses, networkCapped);
  if (mal) findings.push(mal);

  if (info?.publishedAtMs !== undefined) {
    const ageH = (Date.now() - info.publishedAtMs) / 3_600_000;
    if (ageH >= 0 && ageH < cfg.maxAgeHours) {
      findings.push({
        pkg: p,
        version,
        kind: 'new',
        detail: `${label(p, version)} was published ${Math.max(1, Math.round(ageH))}h ago (under ${cfg.maxAgeHours}h)`,
      });
    }
  }
  if (info?.hasInstallScript) {
    findings.push({
      pkg: p,
      version,
      kind: 'install-script',
      detail: `${label(p, version)} runs an install script`,
    });
  }
  return findings;
}

/**
 * Run the package check for one tool call. Fast exit (no I/O) when the call
 * is not a shell command or installs nothing.
 */
export async function runPackageCheck(
  toolName: string,
  args: unknown,
  cfg: PackageCheckConfig
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
      checked.map((p, i) => checkOne(p, cfg, misses, i >= MAX_NETWORK_PACKAGES))
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
