// src/auth/trusted-hosts.ts
// Persistent trusted-host allowlist. Hosts added here downgrade pipe-chain
// exfiltration decisions: 'block' (critical) → 'review', 'review' (high) → 'allow'.
// Only the CLI can add entries — AI tool calls cannot modify this list.
import fs from 'fs';
import path from 'path';
import os from 'os';

export interface TrustedHostEntry {
  host: string;
  addedAt: number;
  addedBy: 'user';
}

interface TrustedHostsFile {
  hosts: TrustedHostEntry[];
}

export function getTrustedHostsPath(): string {
  return path.join(os.homedir(), '.node9', 'trusted-hosts.json');
}

export function readTrustedHosts(): TrustedHostEntry[] {
  try {
    const raw = fs.readFileSync(getTrustedHostsPath(), 'utf8');
    const parsed = JSON.parse(raw) as TrustedHostsFile;
    return Array.isArray(parsed.hosts) ? parsed.hosts : [];
  } catch {
    return [];
  }
}

// Module-level TTL cache — avoids a sync disk read on every policy evaluation.
// Cross-process invalidation: we store the file mtime alongside the cached hosts.
// If another process (e.g. `node9 trust remove`) writes the file, the mtime changes
// and the next call re-reads immediately — no need to wait for TTL expiry.
// Invalidated by _resetTrustedHostsCache() (used in tests) and after each write.
//
// Mtime granularity caveat: on Linux ext4 the mtime has 1-second resolution.
// If a `node9 trust remove` write and the very next daemon `isTrustedHost()` call
// land within the same clock second, the mtime appears unchanged and the stale
// cache is served until TTL expiry (≤ 5 s). This is an accepted, bounded risk:
// the maximum window is max(mtime_granularity, CACHE_TTL_MS) ≈ 5 seconds.
let _cache: { hosts: TrustedHostEntry[]; expiry: number; mtime: number } | null = null;
const CACHE_TTL_MS = 5_000;

export function _resetTrustedHostsCache(): void {
  _cache = null;
}

function getFileMtime(): number {
  try {
    return fs.statSync(getTrustedHostsPath()).mtimeMs;
  } catch {
    return 0;
  }
}

function getCachedHosts(): TrustedHostEntry[] {
  const now = Date.now();
  if (_cache && now < _cache.expiry) {
    // Fast path: TTL not expired — but still check mtime for cross-process writes.
    // getFileMtime() returns 0 if the file doesn't exist (stat throws ENOENT).
    // If the file was deleted after the cache was populated, _cache.mtime is a
    // real nonzero value and mtime (0) won't match it — cache miss triggers a
    // re-read, which returns [] (fail-safe, no stale trust). If the file never
    // existed, both mtime and _cache.mtime are 0 — cache hit correctly returns [].
    const mtime = getFileMtime();
    if (mtime === _cache.mtime) return _cache.hosts;
  }
  const hosts = readTrustedHosts();
  _cache = { hosts, expiry: now + CACHE_TTL_MS, mtime: getFileMtime() };
  return hosts;
}

function writeTrustedHosts(hosts: TrustedHostEntry[]): void {
  const filePath = getTrustedHostsPath();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = filePath + '.node9-tmp';
  fs.writeFileSync(tmp, JSON.stringify({ hosts }, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, filePath);
  // Update cache with new content and fresh mtime — no stale window after our own writes
  _cache = { hosts, expiry: Date.now() + CACHE_TTL_MS, mtime: getFileMtime() };
}

/** Add a host to the trusted list. Normalizes input before storing. No-op if already present.
 *  Throws if the pattern is a single-label wildcard (e.g. *.com, *.io) — these are too broad
 *  and would bypass exfiltration detection for virtually any destination. */
export function addTrustedHost(host: string): void {
  const normalized = normalizeHost(host);
  if (normalized.startsWith('*.')) {
    const base = normalized.slice(2); // everything after "*."
    if (!base.includes('.')) {
      throw new Error(
        `Wildcard pattern '${normalized}' is too broad — the base domain must have at least one dot (e.g. '*.mycompany.com', not '*.com').`
      );
    }
  }
  const hosts = readTrustedHosts();
  if (hosts.some((h) => h.host === normalized)) return;
  hosts.push({ host: normalized, addedAt: Date.now(), addedBy: 'user' });
  writeTrustedHosts(hosts);
}

/** Remove a host from the trusted list. Returns true if removed, false if not found. */
export function removeTrustedHost(host: string): boolean {
  const hosts = readTrustedHosts();
  const filtered = hosts.filter((h) => h.host !== host);
  if (filtered.length === hosts.length) return false;
  writeTrustedHosts(filtered);
  return true;
}

/**
 * Normalizes a raw URL or hostname to a comparable FQDN.
 * Examples:
 *   "https://api.mycompany.com/collect" → "api.mycompany.com"
 *   "api.mycompany.com:443"             → "api.mycompany.com"
 *   "api.mycompany.com:8443"            → "api.mycompany.com"  (non-standard port, same result)
 *   "user@host.com"                     → "host.com"
 *
 * Port stripping is intentional and port-agnostic: trusting a hostname means trusting
 * all ports on that host (api.company.com:443 and api.company.com:8443 map to the same
 * trusted entry). Users who need per-port granularity should not use the trusted-host
 * allowlist for that endpoint.
 */
export function normalizeHost(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/^https?:\/\//, '') // strip protocol
    .replace(/\/.*$/, '') // strip path
    .replace(/^[^@]+@/, '') // strip user@
    .replace(/:\d+$/, ''); // strip :port
}

/**
 * Returns true if `host` is trusted.
 * - Exact match: "api.mycompany.com" matches entry "api.mycompany.com"
 * - Wildcard: entry "*.mycompany.com" matches "api.mycompany.com" and "sub.api.mycompany.com"
 *   but does NOT match bare "mycompany.com" — a wildcard requires at least one subdomain label.
 * - Protocol/path/port are stripped before comparison.
 * - "api.mycompany.com" does NOT match a bare "mycompany.com" entry.
 */
export function isTrustedHost(host: string): boolean {
  const normalized = normalizeHost(host);
  return getCachedHosts().some((entry) => {
    const entryHost = entry.host.toLowerCase();
    if (entryHost.startsWith('*.')) {
      const domain = entryHost.slice(2);
      // Must be a proper subdomain: "foo.domain" matches, bare "domain" does not.
      return normalized.endsWith('.' + domain);
    }
    return normalized === entryHost;
  });
}
