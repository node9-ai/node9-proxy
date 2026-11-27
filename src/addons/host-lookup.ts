// src/addons/host-lookup.ts
// Asks DNS whether the domains a skill names exist (node9Firewall#376 item 6,
// phase 4, check B). For the daemon and `node9 policy push`, never a hook: it
// uses the network. Answers are kept in ~/.node9/addons-hosts.json.
//
// A finding needs three things to be true, because "this domain is
// unregistered" is a strong thing to tell an admin:
//   1. the resolver works: a domain that certainly exists resolves, in this
//      very round (a captive portal or a dead resolver answers nothing);
//   2. the top-level domain exists (`default.svc`, `collector.monitoring` and
//      `attacker.evil` are not public names; nobody can register them);
//   3. the registry says NXDOMAIN for the registrable domain itself.
// Anything else (a timeout, SERVFAIL, an empty answer) is "not known", which
// is never a finding.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { promises as dns } from 'dns';
import { atomicWriteSync } from '../utils/atomic-write';

/** true = exists, false = no such domain, null = not known. */
export type DomainAnswer = boolean | null;

interface CacheEntry {
  exists: boolean;
  checkedAt: string;
}
interface HostCache {
  v: 1;
  domains: Record<string, CacheEntry>;
  tlds: Record<string, CacheEntry>;
}

const FRESH_MS = 24 * 60 * 60 * 1000;
const TLD_FRESH_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_CACHED = 2000;
const MAX_PER_ROUND = 150;
const CONCURRENCY = 8;
const ROUND_BUDGET_MS = 15_000;
/** IANA keeps this one for documentation: it always exists. */
const CONTROL_DOMAIN = 'example.com';

export function hostCachePath(home: string = os.homedir()): string {
  return path.join(home, '.node9', 'addons-hosts.json');
}

function readCache(home: string): HostCache {
  const empty: HostCache = { v: 1, domains: {}, tlds: {} };
  try {
    const raw = JSON.parse(fs.readFileSync(hostCachePath(home), 'utf8')) as Partial<HostCache>;
    const part = (v: unknown): Record<string, CacheEntry> => {
      const out: Record<string, CacheEntry> = {};
      if (!v || typeof v !== 'object' || Array.isArray(v)) return out;
      for (const [k, e] of Object.entries(v).slice(0, MAX_CACHED)) {
        const c = e as Partial<CacheEntry> | null;
        if (c && typeof c.exists === 'boolean' && typeof c.checkedAt === 'string')
          out[k] = { exists: c.exists, checkedAt: c.checkedAt };
      }
      return out;
    };
    return { v: 1, domains: part(raw.domains), tlds: part(raw.tlds) };
  } catch {
    return empty;
  }
}

function fresh(e: CacheEntry | undefined, now: number, ttl: number): e is CacheEntry {
  if (!e) return false;
  const age = now - Date.parse(e.checkedAt);
  return age >= 0 && age < ttl;
}

/** How one name is asked. Injected in tests. */
export type NsQuery = (name: string) => Promise<unknown>;

/** exists / no such domain / not known, from one NS query. */
async function ask(query: NsQuery, name: string): Promise<DomainAnswer> {
  try {
    await query(name);
    return true;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    if (code === 'ENOTFOUND') return false; // NXDOMAIN
    // The name exists but has no NS record of its own (a hosted subdomain).
    if (code === 'ENODATA') return true;
    return null;
  }
}

function defaultQuery(): NsQuery {
  const resolver = new dns.Resolver({ timeout: 3000, tries: 1 });
  return (name) => resolver.resolveNs(name);
}

/**
 * Whether each domain exists. Cached answers are reused for a day; at most
 * MAX_PER_ROUND names are asked per call, the rest come back as not known.
 * Never throws.
 */
export async function lookupDomains(
  domains: string[],
  home: string = os.homedir(),
  opts: { query?: NsQuery; now?: number } = {}
): Promise<Map<string, DomainAnswer>> {
  return (await lookupDomainsRound(domains, home, opts)).answers;
}

/** The answers, and whether the round could be trusted at all: false when
 *  the resolver did not answer for a domain that must exist, so the caller
 *  can tell "checked, nothing found" from "could not check". */
export async function lookupDomainsRound(
  domains: string[],
  home: string = os.homedir(),
  opts: { query?: NsQuery; now?: number } = {}
): Promise<{ answers: Map<string, DomainAnswer>; ok: boolean }> {
  const now = opts.now ?? Date.now();
  const out = new Map<string, DomainAnswer>();
  let ok = false;
  const unique = [...new Set(domains)];
  try {
    const cache = readCache(home);
    const stale: string[] = [];
    for (const d of unique) {
      const e = cache.domains[d];
      if (fresh(e, now, FRESH_MS)) out.set(d, e.exists);
      else stale.push(d);
    }
    if (stale.length === 0) return { answers: out, ok: true };
    for (const d of stale) out.set(d, null);

    const query = opts.query ?? defaultQuery();
    // 1. Does the resolver work at all, right now?
    if ((await ask(query, CONTROL_DOMAIN)) !== true) return { answers: out, ok: false };
    ok = true;

    const deadline = Date.now() + ROUND_BUDGET_MS;
    const stamp = new Date(now).toISOString();
    const tldOf = (d: string) => d.slice(d.lastIndexOf('.') + 1);
    const tldAnswer = async (tld: string): Promise<DomainAnswer> => {
      const e = cache.tlds[tld];
      if (fresh(e, now, TLD_FRESH_MS)) return e.exists;
      const a = await ask(query, tld);
      if (a !== null) cache.tlds[tld] = { exists: a, checkedAt: stamp };
      return a;
    };
    const todo = stale.slice(0, MAX_PER_ROUND);
    let next = 0;
    const worker = async (): Promise<void> => {
      while (next < todo.length && Date.now() < deadline) {
        const d = todo[next++];
        const a = await ask(query, d);
        if (a === true) {
          out.set(d, true);
          cache.domains[d] = { exists: true, checkedAt: stamp };
          continue;
        }
        if (a === null) continue;
        // 2. NXDOMAIN: only a name under a real top-level domain can be
        // registered by someone else.
        const tld = await tldAnswer(tldOf(d));
        if (tld === null) continue; // not known: say nothing
        if (tld === false) {
          // Not a public name. Remembered as "exists" in the sense that
          // matters here: nobody can register it.
          out.set(d, true);
          cache.domains[d] = { exists: true, checkedAt: stamp };
          continue;
        }
        out.set(d, false);
        cache.domains[d] = { exists: false, checkedAt: stamp };
      }
    };
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, todo.length) }, worker));

    // Keep the newest answers when the file grows past its cap.
    const keep = Object.entries(cache.domains)
      .sort((a, b) => b[1].checkedAt.localeCompare(a[1].checkedAt))
      .slice(0, MAX_CACHED);
    atomicWriteSync(
      hostCachePath(home),
      JSON.stringify({ v: 1, domains: Object.fromEntries(keep), tlds: cache.tlds }),
      { mode: 0o600 }
    );
  } catch {
    /* what was answered so far stands; the rest is not known */
  }
  return { answers: out, ok };
}
