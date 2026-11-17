// src/ci-check/package-check.ts
// fw#481 A1, part 2 (network): ask npm, PyPI and OSV about the packages scanTree found, and turn
// the answers into findings. Design: scanner-a1-packages-design.md §4.
//
// | Signal                                   | Auto-run | Text   | Rule                    |
// | OSV MAL- covers the version              | critical | high   | CI-3.package-malicious  |
// | OSV MAL- exists, version unknown         | review   | review | CI-3.package-malicious  |
// | name not on the registry (claimable)     | high     | review | CI-3.package-absent     |
// | npm removed it as malicious (holding pkg)| medium   | review | CI-3.package-removed    |
// | look-alike of a popular name             | high     | review | CI-3.package-lookalike  |
//
// Age, install scripts and provenance are left to the gate, which checks them when the agent
// runs the command (§4.3). Never throws; a failed lookup is a note, never a finding or a clean.

import crypto from 'crypto';
import dns from 'dns';
import fs from 'fs';
import net from 'net';
import os from 'os';
import path from 'path';
import type { PackageInstallRequest } from '@node9/policy-engine';
import { checkPackageNames, type NameCheck } from '../supply-chain/check';
import { endpoints, fetchJson } from '../supply-chain/net';
import { binProvidedBy, type PackageRef } from './packages';
import type { DeclaredDep, ManifestSet } from './deps';
import type { CiFinding, Severity } from './types';

export interface PackageSummary {
  /** Distinct packages the scan found. */
  names: number;
  /** How many of them were asked of a registry (live or from the cache). */
  checked: number;
  /** Over the per-scan cap: checked against the local OSV index only. */
  capped: number;
  /** Names whose lookup failed (not graded). */
  failed: number;
}

export interface PackageCheckOptions {
  /** No request leaves the machine (tests, the A/B over local clones). */
  offline?: boolean;
  /** Registry lookups per scan; auto-run surfaces first, then the most named packages. */
  networkCap?: number;
  /** The disk cache directory; null turns it off. Default ~/.node9/cache/packages. */
  cacheDir?: string | null;
  /** Packages the repository declares (root manifests): a doc's `npx X` may run their bin. */
  declared?: ReadonlySet<string>;
  /** Shared between the base and head scans of one run, so a name is asked once. */
  memo?: Map<string, NameCheck>;
}

export const DEFAULT_NETWORK_CAP = 100;
const CACHE_TTL_MS = 12 * 3_600_000;

const keyOf = (r: Pick<PackageRef, 'ecosystem' | 'name' | 'version'>) =>
  `${r.ecosystem}\u0000${r.name}\u0000${r.version ?? ''}`;

function defaultCacheDir(): string {
  return path.join(os.homedir(), '.node9', 'cache', 'packages');
}

function cachePath(dir: string, key: string): string {
  return path.join(dir, `${crypto.createHash('sha1').update(key).digest('hex')}.json`);
}

function readCache<T>(dir: string | null, key: string): T | undefined {
  if (!dir) return undefined;
  try {
    const raw = JSON.parse(fs.readFileSync(cachePath(dir, key), 'utf8')) as {
      at: number;
      key: string;
      value: T;
    };
    if (raw.key !== key || Date.now() - raw.at > CACHE_TTL_MS) return undefined;
    return raw.value;
  } catch {
    return undefined;
  }
}

function writeCache(dir: string | null, key: string, value: unknown): void {
  if (!dir) return;
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(cachePath(dir, key), JSON.stringify({ at: Date.now(), key, value }));
  } catch {
    /* a cache that cannot be written only costs a lookup next time */
  }
}

/** Whether an npm scope already has packages (only its owner can publish under it), or null
 *  when unknown. A scope with none can be claimed by anyone who creates the user or org. */
async function scopeOwned(
  scope: string,
  cacheDir: string | null,
  memo: Map<string, boolean | null>
): Promise<boolean | null> {
  const key = `npm-org\u0000${scope}`;
  if (memo.has(key)) return memo.get(key)!;
  const cached = readCache<boolean>(cacheDir, key);
  if (cached !== undefined) {
    memo.set(key, cached);
    return cached;
  }
  // `/-/org/<scope>/package` answers 200 for an org or a user that exists (even with no
  // public package) and 404 when nobody holds the name. npm search's `scope:` filter returns
  // nothing for every scope (2026-11-17), so it cannot tell the two apart.
  let owned: boolean | null = null;
  const base = endpoints().npmRegistry;
  if (base) {
    try {
      const res = await fetchJson(`${base}/-/org/${encodeURIComponent(scope)}/package`, {
        timeoutMs: 3000,
        maxBytes: 4 * 1024 * 1024,
      });
      owned = res !== null;
    } catch {
      owned = null;
    }
  }
  memo.set(key, owned);
  if (owned !== null) writeCache(cacheDir, key, owned);
  return owned;
}

let reachable: Promise<boolean> | undefined;

/**
 * Can the npm registry's name be resolved at all? Asked once per process through a c-ares
 * resolver that is cancelled after a second: the fetch itself resolves through getaddrinfo,
 * which cannot be cancelled, so with a DNS server that never answers every lookup would hold
 * the process open for its full timeout (the usage ping hit the same, fw#388). A local or IP
 * registry (tests, a mirror) is not probed.
 */
export function registryReachable(): Promise<boolean> {
  if (reachable) return reachable;
  const base = endpoints().npmRegistry;
  let host = '';
  try {
    host = base ? new URL(base).hostname : '';
  } catch {
    host = '';
  }
  if (!host) return (reachable = Promise.resolve(false));
  if (net.isIP(host) || host === 'localhost' || host.endsWith('.test'))
    return (reachable = Promise.resolve(true));
  reachable = new Promise((resolve) => {
    const resolver = new dns.Resolver({ timeout: 1000, tries: 1 });
    const cap = setTimeout(() => {
      resolver.cancel();
      resolve(false);
    }, 1500);
    resolver.resolve4(host, (err, addrs) => {
      clearTimeout(cap);
      resolver.cancel();
      resolve(!err && addrs.length > 0);
    });
  });
  return reachable;
}

/** Tests only: forget the probe answer. */
export function _resetRegistryProbe(): void {
  reachable = undefined;
}

const SURFACE_WORDS: Record<PackageRef['surface'], string> = {
  mcp: 'an MCP server this repository configures, started in every contributor’s agent session',
  hook: 'an agent hook, run by itself in every session',
  task: 'a VS Code task that runs when the folder is opened',
  'hook-script': 'a hook script, run by itself in every session',
  'skill-script': 'a skill script the agent runs',
  doc: 'agent instructions the agent may follow',
};

const NPX_LIKE = new Set(['npx', 'bunx', 'npm exec', 'pnpm dlx', 'yarn dlx']);

const registryOf = (r: PackageRef) => (r.ecosystem === 'npm' ? 'npm' : 'PyPI');

function finding(
  r: PackageRef,
  rule: string,
  severity: Severity,
  title: string,
  signal: string,
  fix: string
): CiFinding {
  return {
    check: 'CI-3',
    rule,
    dimension: r.surface === 'mcp' ? 'mcp' : r.surface === 'doc' ? 'instructions' : 'toolRules',
    severity,
    title,
    file: r.file,
    ...(r.line ? { line: r.line } : {}),
    locator: `${r.ecosystem}:${r.name}`,
    signals: [`\`${r.command.replace(/`/g, "'")}\`: ${SURFACE_WORDS[r.surface]}`, signal],
    fix,
  };
}

/** The findings for one reference, from what the registries said about its package. */
async function findingsFor(
  r: PackageRef,
  check: NameCheck,
  declared: ReadonlySet<string>,
  cacheDir: string | null,
  scopeMemo: Map<string, boolean | null>
): Promise<CiFinding[]> {
  const out: CiFinding[] = [];
  const reg = registryOf(r);
  for (const f of check.findings) {
    switch (f.kind) {
      case 'malicious':
        out.push(
          finding(
            r,
            'CI-3.package-malicious',
            r.autoRun ? 'critical' : 'high',
            `Known malicious package: ${r.name}`,
            `OSV lists ${r.name}${f.version ? `@${f.version}` : ''} as malicious (${(f.advisories ?? []).join(', ')})`,
            'Remove the reference. Treat every machine that ran it as exposed: rotate the tokens on it.'
          )
        );
        break;
      case 'malicious-unpinned':
        // Without a registry answer the version is unknown only because nobody asked (over the
        // cap): a popular package with one compromised release long ago would read as suspect.
        if (!check.registryAsked) break;
        out.push(
          finding(
            r,
            'CI-3.package-malicious',
            'advisory',
            `Package with known malicious versions: ${r.name}`,
            `OSV lists malicious versions of ${r.name} (${(f.advisories ?? []).join(', ')}); the version this reference gets could not be resolved`,
            'Pin a version that is not affected, or remove the reference.'
          )
        );
        break;
      case 'absent': {
        if (r.ecosystem === 'npm' && r.name.startsWith('@')) {
          const owned = await scopeOwned(r.name.slice(1, r.name.indexOf('/')), cacheDir, scopeMemo);
          if (owned !== false) break; // owned, or unknown: only the owner can publish there
        }
        if (!r.autoRun && NPX_LIKE.has(r.manager) && binProvidedBy(r.name, declared)) break;
        out.push(
          finding(
            r,
            'CI-3.package-absent',
            r.autoRun ? 'high' : 'advisory',
            r.autoRun
              ? `Unregistered package started by itself: ${r.name}`
              : `Instructions name a package that is not on ${reg}: ${r.name}`,
            `${r.name} does not exist on ${reg}: anyone can register the name, and the next run fetches their code`,
            `Use the published package name (it may be scoped, or the tool may be installed another way), or publish and pin your own. Until then nobody owns \`${r.name}\`.`
          )
        );
        break;
      }
      case 'placeholder':
        out.push(
          finding(
            r,
            'CI-3.package-removed',
            r.autoRun ? 'medium' : 'advisory',
            `Package removed by npm as malicious: ${r.name}`,
            `npm removed ${r.name} as malicious; the name now serves an empty security holding package, so the command no longer does what this file says`,
            'Replace the command with the package you meant. Check whether anyone ran it before the removal.'
          )
        );
        break;
      case 'lookalike':
        if (!r.autoRun && NPX_LIKE.has(r.manager) && binProvidedBy(r.name, declared)) break;
        out.push(
          finding(
            r,
            'CI-3.package-lookalike',
            r.autoRun ? 'high' : 'advisory',
            `Package name looks like a popular one: ${r.name}`,
            f.detail.replace(/^(npm|PyPI) package /, ''),
            'Check the name letter by letter against the package you meant, and pin it.'
          )
        );
        break;
      default:
        break; // age, install script, provenance: the gate's, at run time (§4.3)
    }
  }
  return out;
}

/**
 * Check every package reference and return the findings, the notes and a summary. One finding
 * per (file, package); the first reference in a file anchors it.
 */
export async function checkPackageRefs(
  refs: PackageRef[],
  opts: PackageCheckOptions = {}
): Promise<{ findings: CiFinding[]; notes: string[]; summary: PackageSummary }> {
  const cacheDir = opts.cacheDir === undefined ? defaultCacheDir() : opts.cacheDir;
  const cap = opts.networkCap ?? DEFAULT_NETWORK_CAP;
  // No network: one note, nothing asked, nothing graded, no wait on timeouts.
  if (!opts.offline && refs.length > 0 && !(await registryReachable())) {
    const names = new Set(refs.map(keyOf)).size;
    return {
      findings: [],
      notes: [
        `packages: npm could not be reached, so the ${names} package name(s) the agent surfaces name were not checked`,
      ],
      summary: { names, checked: 0, capped: 0, failed: names },
    };
  }
  const memo = opts.memo ?? new Map<string, NameCheck>();
  const declared = opts.declared ?? new Set<string>();

  // Distinct packages, auto-run ones first, then by how often they are named.
  const groups = new Map<string, { req: PackageRef; autoRun: boolean; count: number }>();
  for (const r of refs) {
    const k = keyOf(r);
    const g = groups.get(k);
    if (g) {
      g.count++;
      g.autoRun ||= r.autoRun;
    } else groups.set(k, { req: r, autoRun: r.autoRun, count: 1 });
  }
  const order = [...groups.entries()].sort(
    ([, a], [, b]) => Number(b.autoRun) - Number(a.autoRun) || b.count - a.count
  );

  const results = new Map<string, NameCheck>();
  const todo: [string, PackageRef][] = [];
  for (const [k, g] of order) {
    const hit = memo.get(k) ?? readCache<NameCheck>(opts.offline ? null : cacheDir, k);
    if (hit) results.set(k, hit);
    else todo.push([k, g.req]);
  }
  const already = results.size;
  const asked = await checkPackageNames(
    todo.map(([, r]): PackageInstallRequest => ({
      ecosystem: r.ecosystem,
      manager: r.manager,
      name: r.name,
      ...(r.version ? { version: r.version } : {}),
      raw: r.version ? `${r.name}@${r.version}` : r.name,
    })),
    { networkCap: Math.max(0, cap), offline: opts.offline }
  );
  todo.forEach(([k], i) => {
    const c = asked[i];
    results.set(k, c);
    memo.set(k, c);
    if (c.registryAsked && c.misses.length === 0) writeCache(cacheDir, k, c);
  });

  // One finding per (file, package) on auto-run surfaces. On text surfaces one per package: a
  // name repeated across twelve skill docs is one thing to fix, and the other files are named on
  // it. When an auto-run surface has the same package, the docs are named on that finding.
  const scopeMemo = new Map<string, boolean | null>();
  const findings: CiFinding[] = [];
  const byPackage = new Map<string, { anchor: CiFinding[]; files: Set<string> }>();
  const seen = new Set<string>();
  for (const r of refs) {
    const pkg = `${r.ecosystem}:${r.name}`;
    const once = r.autoRun ? `${r.file}\u0000${pkg}` : `text\u0000${pkg}`;
    const entry = byPackage.get(pkg);
    if (!r.autoRun && entry) {
      if (!entry.anchor.some((f) => f.file === r.file)) entry.files.add(r.file);
      continue;
    }
    if (seen.has(once)) continue;
    seen.add(once);
    const check = results.get(keyOf(r));
    if (!check) continue;
    let found = await findingsFor(r, check, declared, opts.offline ? null : cacheDir, scopeMemo);
    if (r.alertsOnly) found = found.filter((f) => f.severity !== 'advisory');
    if (found.length === 0) continue;
    findings.push(...found);
    if (!entry) byPackage.set(pkg, { anchor: found, files: new Set() });
    else if (r.autoRun && entry.anchor.every((f) => f.severity === 'advisory')) {
      // An auto-run finding outranks the doc one: it carries the doc files from now on.
      const docs = entry.anchor.filter((f) => f.severity === 'advisory');
      for (const d of docs) {
        findings.splice(findings.indexOf(d), 1);
        entry.files.add(d.file);
      }
      entry.anchor = found;
    }
  }
  for (const { anchor, files } of byPackage.values()) {
    if (files.size === 0) continue;
    const list = [...files].sort();
    const shown = list
      .slice(0, 5)
      .map((f) => `\`${f}\``)
      .join(', ');
    for (const f of anchor)
      f.signals.push(
        `also named in ${list.length} other file(s): ${shown}${list.length > 5 ? ', …' : ''}`
      );
  }

  const capped = asked.filter((c) => !c.registryAsked).length;
  const failed = [...results.values()].filter((c) => c.registryAsked && c.misses.length > 0).length;
  const summary: PackageSummary = {
    names: groups.size,
    checked: already + asked.filter((c) => c.registryAsked).length,
    capped,
    failed,
  };
  const notes: string[] = [];
  if (groups.size > 0 && !opts.offline && capped > 0)
    notes.push(
      `packages: ${capped} of ${groups.size} package names were over the per-scan limit of ${cap} registry lookups; they were not asked of npm or PyPI (only a local malicious-package index, where one exists)`
    );
  if (failed > 0)
    notes.push(
      `packages: the registry lookup failed for ${failed} package name(s); those are not graded`
    );
  return { findings, notes, summary };
}

const NEW_PACKAGE_MS = 7 * 24 * 3_600_000;

/**
 * PR mode (§4.5): findings for the dependencies a change adds. Every one is introduced by the
 * change, so the PR comment shows it as new. A private registry or index the repository sets up
 * excuses a public 404 (the package may live there), never a malicious record.
 */
export async function checkAddedDeps(
  added: DeclaredDep[],
  head: Pick<ManifestSet, 'privateNpm' | 'privatePy'>,
  opts: Pick<PackageCheckOptions, 'offline' | 'cacheDir' | 'networkCap'> = {}
): Promise<{ findings: CiFinding[]; notes: string[] }> {
  if (added.length === 0) return { findings: [], notes: [] };
  if (!opts.offline && !(await registryReachable()))
    return {
      findings: [],
      notes: [
        `dependencies: npm could not be reached, so the ${added.length} added dependency name(s) were not checked`,
      ],
    };
  const cacheDir = opts.offline
    ? null
    : opts.cacheDir === undefined
      ? defaultCacheDir()
      : opts.cacheDir;
  const checks = await checkPackageNames(
    added.map((d): PackageInstallRequest => ({
      ecosystem: d.ecosystem,
      manager: d.ecosystem === 'npm' ? 'npm' : 'pip',
      name: d.name,
      ...(d.version ? { version: d.version } : {}),
      raw: d.version ? `${d.name}@${d.version}` : d.name,
    })),
    { networkCap: opts.networkCap ?? DEFAULT_NETWORK_CAP, offline: opts.offline, created: true }
  );
  const scopeMemo = new Map<string, boolean | null>();
  const findings: CiFinding[] = [];
  let failed = 0;
  for (let i = 0; i < added.length; i++) {
    const d = added[i];
    const c = checks[i];
    if (c.registryAsked && c.misses.length > 0) failed++;
    const reg = d.ecosystem === 'npm' ? 'npm' : 'PyPI';
    const priv = d.ecosystem === 'npm' ? head.privateNpm : head.privatePy;
    const make = (kind: string, severity: Severity, title: string, signal: string, fix: string) => {
      findings.push({
        check: 'CI-3',
        rule: `CI-3.dependency-added-${kind}`,
        dimension: 'files',
        severity,
        title,
        file: d.file,
        ...(d.line ? { line: d.line } : {}),
        locator: `${d.ecosystem}:${d.name}`,
        signals: [`this change adds \`${d.spec.replace(/`/g, "'")}\``, signal],
        fix,
      });
    };
    for (const f of c.findings) {
      if (f.kind === 'malicious')
        make(
          'malicious',
          'critical',
          `Added dependency is known malicious: ${d.name}`,
          `OSV lists ${d.name}${f.version ? `@${f.version}` : ''} as malicious (${(f.advisories ?? []).join(', ')})`,
          'Remove the dependency before merging. Treat any machine or CI run that installed it as exposed.'
        );
      else if (f.kind === 'malicious-unpinned')
        make(
          'malicious',
          'advisory',
          `Added dependency has known malicious versions: ${d.name}`,
          `OSV lists malicious versions of ${d.name} (${(f.advisories ?? []).join(', ')})`,
          'Pin a version that is not affected.'
        );
      else if (f.kind === 'absent') {
        if (priv) continue;
        if (d.ecosystem === 'npm' && d.name.startsWith('@')) {
          const owned = await scopeOwned(d.name.slice(1, d.name.indexOf('/')), cacheDir, scopeMemo);
          if (owned !== false) continue;
        }
        make(
          'absent',
          'high',
          `Added dependency does not exist on ${reg}: ${d.name}`,
          `${d.name} is not on ${reg}: the install fails today, and anyone can register the name before this merges (a package name an AI model invented is the usual source)`,
          'Find the real package name before merging; do not register the name yourself to make the install pass.'
        );
      } else if (f.kind === 'placeholder')
        make(
          'removed',
          'high',
          `Added dependency was removed by npm as malicious: ${d.name}`,
          `npm removed ${d.name} as malicious; only a security holding package remains`,
          'Replace it with the package you meant.'
        );
      else if (f.kind === 'lookalike') {
        if (priv && /does not exist/.test(f.detail)) continue;
        make(
          'lookalike',
          'high',
          `Added dependency looks like a popular package: ${d.name}`,
          f.detail.replace(/^(npm|PyPI) package /, ''),
          'Check the name letter by letter against the package you meant.'
        );
      }
    }
    if (
      c.createdAtMs !== undefined &&
      Date.now() - c.createdAtMs < NEW_PACKAGE_MS &&
      !c.findings.some((f) => f.kind === 'malicious' || f.kind === 'lookalike')
    )
      make(
        'new',
        'advisory',
        `Added dependency was first published days ago: ${d.name}`,
        `${d.name} was first published ${Math.max(1, Math.round((Date.now() - c.createdAtMs) / 86_400_000))} day(s) ago`,
        'Make sure this is the package you meant and that its owner is who you expect.'
      );
  }
  const notes =
    failed > 0
      ? [
          `dependencies: the registry lookup failed for ${failed} added dependency name(s); those are not graded`,
        ]
      : [];
  return { findings, notes };
}
