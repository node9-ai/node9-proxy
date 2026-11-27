// src/addons/package-standing.ts
// The package check for the MCP servers on this machine (node9Firewall#376
// item 6, phase 4, check D): is the package a server runs on the malicious
// list, a near miss of a popular name, absent from the registry, or days old.
// Same lookups as the install gate (supply-chain/check.ts). Runs in the daemon
// and from `node9 policy push`, never on a hook's path: it asks registries.
//
// Contract: never throws; a lookup that fails leaves no finding and marks the
// entry as not checked by the registry, so the dashboard never reads silence
// as "clean".

import os from 'os';
import { normalizePyPiName, type PackageInstallRequest } from '@node9/policy-engine';
import { checkPackageNames, type NameCheck } from '../supply-chain/check';
import type { McpPackage } from './identity';
import {
  MALICIOUS_RULE,
  readStanding,
  writeStanding,
  type StandingEntry,
  type StandingFinding,
  type StandingFile,
} from './standing-file';

/** A result is reused for this long: the malicious index itself syncs every 6 hours. */
const FRESH_MS = 6 * 60 * 60 * 1000;
/** A registry that did not answer is asked again sooner. */
const RETRY_MS = 30 * 60 * 1000;
/** First published under this long ago is worth a look (the scan's rule). */
const NEW_PACKAGE_MS = 7 * 24 * 60 * 60 * 1000;
const NETWORK_CAP = 30;

export interface StandingTarget {
  identity: string;
  pkg: McpPackage;
}

function request(pkg: McpPackage): PackageInstallRequest {
  const name = pkg.ecosystem === 'PyPI' ? normalizePyPiName(pkg.name) : pkg.name;
  return {
    ecosystem: pkg.ecosystem,
    manager: pkg.ecosystem === 'npm' ? 'npx' : 'uvx',
    name,
    ...(pkg.version ? { version: pkg.version } : {}),
    raw: pkg.version ? `${name}@${pkg.version}` : name,
  };
}

/** One check result as the findings the dashboard row and the gate read. */
export function standingFindings(check: NameCheck, now: number): StandingFinding[] {
  const out = new Map<string, StandingFinding>();
  const add = (f: StandingFinding) => {
    if (!out.has(f.rule)) out.set(f.rule, f);
  };
  for (const f of check.findings) {
    const advisories = (f.advisories ?? []).slice(0, 5);
    const adv = advisories.length ? { advisories } : {};
    if (f.kind === 'malicious') add({ rule: MALICIOUS_RULE, severity: 'critical', ...adv });
    // A record exists, but not for a version node9 can tell is the one in use.
    else if (f.kind === 'malicious-unpinned')
      add({ rule: 'mcp.package-malicious-record', severity: 'high', ...adv });
    else if (f.kind === 'lookalike') add({ rule: 'mcp.package-lookalike', severity: 'high' });
    else if (f.kind === 'absent') add({ rule: 'mcp.package-absent', severity: 'high' });
    else if (f.kind === 'placeholder') add({ rule: 'mcp.package-removed', severity: 'high' });
  }
  if (check.createdAtMs !== undefined && now - check.createdAtMs < NEW_PACKAGE_MS && out.size === 0)
    add({ rule: 'mcp.package-new', severity: 'medium' });
  return [...out.values()];
}

function isFresh(e: StandingEntry | undefined, pkg: McpPackage, now: number): boolean {
  if (!e || (e.version ?? '') !== (pkg.version ?? '')) return false;
  const age = now - Date.parse(e.checkedAt);
  return age >= 0 && age < (e.registry ? FRESH_MS : RETRY_MS);
}

/**
 * Check the servers whose stored result is missing or old, and write the file.
 * Entries of servers no longer configured are dropped. Returns the file as
 * written.
 */
export async function refreshPackageStanding(
  targets: StandingTarget[],
  home: string = os.homedir(),
  opts: { check?: typeof checkPackageNames; now?: number; offline?: boolean } = {}
): Promise<StandingFile> {
  const now = opts.now ?? Date.now();
  const prev = readStanding(home);
  const next: StandingFile = { v: 1, entries: {} };
  const byIdentity = new Map<string, McpPackage>();
  // One identity, one check: a pinned copy wins over an unpinned one, so the
  // verdict is about a version the check could name.
  for (const t of targets)
    if (!byIdentity.has(t.identity) || (t.pkg.version && !byIdentity.get(t.identity)!.version))
      byIdentity.set(t.identity, t.pkg);

  const stale: Array<[string, McpPackage]> = [];
  for (const [identity, pkg] of byIdentity) {
    const e = prev.entries[identity];
    if (isFresh(e, pkg, now)) next.entries[identity] = e;
    else stale.push([identity, pkg]);
  }
  if (stale.length > 0) {
    let checks: NameCheck[] = [];
    try {
      checks = await (opts.check ?? checkPackageNames)(
        stale.map(([, pkg]) => request(pkg)),
        { networkCap: NETWORK_CAP, created: true, ...(opts.offline ? { offline: true } : {}) }
      );
    } catch {
      /* the check failed as a whole: nothing new is known */
    }
    stale.forEach(([identity, pkg], i) => {
      const c = checks[i];
      if (!c) {
        // Keep what was known rather than forget a malicious verdict.
        if (prev.entries[identity]) next.entries[identity] = prev.entries[identity];
        return;
      }
      next.entries[identity] = {
        findings: standingFindings(c, now),
        registry: c.registryAsked && c.misses.length === 0,
        ...(pkg.version ? { version: pkg.version } : {}),
        checkedAt: new Date(now).toISOString(),
      };
    });
  }
  writeStanding(next, home);
  return next;
}
