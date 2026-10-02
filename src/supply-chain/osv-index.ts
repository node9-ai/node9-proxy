// src/supply-chain/osv-index.ts
// Local index of OSV malicious-package records (MAL- ids, OpenSSF
// malicious-packages feed). Read on the hook's hot path, written by the
// daemon's sync (osv-sync.ts).
//
// Layout under ~/.node9/osv/<ecosystem>/:
//   meta.json          { syncedAt, lastModifiedMs, records, mode }
//   shards/<xx>.json   { [packageName]: OsvEntry[] }
// The shard is the first two hex characters of sha1(name), so a lookup reads
// one small file (about 1/256 of the index), never the whole thing.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';
import { normalizePyPiName, type PackageEcosystem } from '@node9/policy-engine';
import { atomicWriteSync } from '../utils/atomic-write';

export interface OsvRange {
  introduced: string;
  fixed?: string;
  lastAffected?: string;
}

export interface OsvEntry {
  id: string;
  /** Every version of the package is malicious. */
  all?: true;
  versions?: string[];
  ranges?: OsvRange[];
}

export interface OsvIndexMeta {
  syncedAt: string;
  /** Newest `modified` timestamp applied, epoch ms. */
  lastModifiedMs: number;
  records: number;
  mode: 'full' | 'incremental';
}

export type IndexLookup =
  | { status: 'unavailable' }
  | { status: 'clean'; fresh: boolean }
  | { status: 'hit'; fresh: boolean; entries: OsvEntry[] };

/** An index older than this still counts for HITS, but a miss is re-checked online. */
export const INDEX_FRESH_MS = 72 * 60 * 60 * 1000;

export function osvRoot(): string {
  return path.join(os.homedir(), '.node9', 'osv');
}

function ecoDir(eco: PackageEcosystem): string {
  return path.join(osvRoot(), eco);
}

export function indexKey(eco: PackageEcosystem, name: string): string {
  return eco === 'PyPI' ? normalizePyPiName(name) : name.toLowerCase();
}

export function shardOf(key: string): string {
  return createHash('sha1').update(key).digest('hex').slice(0, 2);
}

function shardPath(eco: PackageEcosystem, shard: string): string {
  return path.join(ecoDir(eco), 'shards', `${shard}.json`);
}

export function readMeta(eco: PackageEcosystem): OsvIndexMeta | null {
  try {
    const m = JSON.parse(fs.readFileSync(path.join(ecoDir(eco), 'meta.json'), 'utf8'));
    if (typeof m?.syncedAt !== 'string' || typeof m?.lastModifiedMs !== 'number') return null;
    return m as OsvIndexMeta;
  } catch {
    return null;
  }
}

export function writeMeta(eco: PackageEcosystem, meta: OsvIndexMeta): void {
  atomicWriteSync(path.join(ecoDir(eco), 'meta.json'), JSON.stringify(meta));
}

export type Shard = Record<string, OsvEntry[]>;

export function readShard(eco: PackageEcosystem, shard: string): Shard {
  try {
    const s = JSON.parse(fs.readFileSync(shardPath(eco, shard), 'utf8'));
    return s && typeof s === 'object' && !Array.isArray(s) ? (s as Shard) : {};
  } catch {
    return {};
  }
}

export function writeShard(eco: PackageEcosystem, shard: string, data: Shard): void {
  atomicWriteSync(shardPath(eco, shard), JSON.stringify(data));
}

/** Look a package up in the local index. Never throws. */
export function lookupIndex(eco: PackageEcosystem, name: string): IndexLookup {
  const meta = readMeta(eco);
  if (!meta) return { status: 'unavailable' };
  const fresh = Date.now() - Date.parse(meta.syncedAt) < INDEX_FRESH_MS;
  const key = indexKey(eco, name);
  const entries = readShard(eco, shardOf(key))[key];
  if (!entries || entries.length === 0) return { status: 'clean', fresh };
  return { status: 'hit', fresh, entries };
}

// ── OSV record → index entries ──────────────────────────────────────────────

interface OsvRecord {
  id?: unknown;
  modified?: unknown;
  withdrawn?: unknown;
  affected?: Array<{
    package?: { name?: unknown; ecosystem?: unknown };
    versions?: unknown;
    ranges?: Array<{ type?: unknown; events?: Array<Record<string, unknown>> }>;
  }>;
}

/** The index rows one OSV record contributes, keyed by index key. */
export function entriesFromRecord(
  eco: PackageEcosystem,
  record: unknown
): { id: string; modifiedMs: number; withdrawn: boolean; rows: Map<string, OsvEntry> } | null {
  const r = record as OsvRecord;
  if (typeof r?.id !== 'string' || !r.id.startsWith('MAL-')) return null;
  const modifiedMs = typeof r.modified === 'string' ? Date.parse(r.modified) || 0 : 0;
  const rows = new Map<string, OsvEntry>();
  for (const a of r.affected ?? []) {
    if (a?.package?.ecosystem !== eco || typeof a.package.name !== 'string') continue;
    const key = indexKey(eco, a.package.name);
    const entry: OsvEntry = rows.get(key) ?? { id: r.id };
    if (Array.isArray(a.versions)) {
      const vs = a.versions.filter((v): v is string => typeof v === 'string');
      if (vs.length > 0) entry.versions = [...(entry.versions ?? []), ...vs];
    }
    for (const range of a.ranges ?? []) {
      let introduced: string | undefined;
      for (const ev of range?.events ?? []) {
        if (typeof ev.introduced === 'string') introduced = ev.introduced;
        const fixed = typeof ev.fixed === 'string' ? ev.fixed : undefined;
        const lastAffected = typeof ev.last_affected === 'string' ? ev.last_affected : undefined;
        if (introduced !== undefined && (fixed || lastAffected)) {
          (entry.ranges ??= []).push({ introduced, fixed, lastAffected });
          introduced = undefined;
        }
      }
      // An open range (introduced with no end) covers every later version.
      if (introduced !== undefined) {
        if (introduced === '0') entry.all = true;
        else (entry.ranges ??= []).push({ introduced });
      }
    }
    // A record that names a package and no versions at all means the package.
    if (!entry.all && !entry.versions && !entry.ranges) entry.all = true;
    rows.set(key, entry);
  }
  return { id: r.id, modifiedMs, withdrawn: !!r.withdrawn, rows };
}

/** Apply one record to an in-memory shard set (replace by id; drop when withdrawn). */
export function applyRecordToShards(
  shards: Map<string, Shard>,
  parsed: NonNullable<ReturnType<typeof entriesFromRecord>>,
  load: (shard: string) => Shard
): void {
  for (const [key, entry] of parsed.rows) {
    const sid = shardOf(key);
    let shard = shards.get(sid);
    if (!shard) {
      shard = load(sid);
      shards.set(sid, shard);
    }
    const kept = (shard[key] ?? []).filter((e) => e.id !== parsed.id);
    if (!parsed.withdrawn) kept.push(entry);
    if (kept.length > 0) shard[key] = kept;
    else delete shard[key];
  }
}

// ── Version matching ────────────────────────────────────────────────────────

/**
 * Generic version comparison: numeric dot segments compare numerically, a
 * pre-release tail (`1.0.0-beta`, `1.0rc1`) sorts before the release. Good
 * enough for range bounds in MAL records, which are rare (most records list
 * exact versions or cover every version).
 */
export function compareVersions(a: string, b: string): number {
  const split = (v: string) => {
    const m = /^v?(\d+(?:\.\d+)*)(.*)$/.exec(v.trim());
    return m
      ? { nums: m[1].split('.').map(Number), tail: m[2].replace(/^[-+.]/, '') }
      : { nums: [], tail: v };
  };
  const x = split(a);
  const y = split(b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  if (x.tail === y.tail) return 0;
  if (!x.tail) return 1;
  if (!y.tail) return -1;
  return x.tail < y.tail ? -1 : 1;
}

function inRange(v: string, r: OsvRange): boolean {
  if (r.introduced !== '0' && compareVersions(v, r.introduced) < 0) return false;
  if (r.fixed !== undefined) return compareVersions(v, r.fixed) < 0;
  if (r.lastAffected !== undefined) return compareVersions(v, r.lastAffected) <= 0;
  return true;
}

/** Does this entry cover `version`? `undefined` version means "unknown". */
export function entryCovers(entry: OsvEntry, version: string | undefined): boolean | 'unknown' {
  if (entry.all) return true;
  if (version === undefined) return 'unknown';
  if (entry.versions?.includes(version)) return true;
  return (entry.ranges ?? []).some((r) => inRange(version, r));
}
