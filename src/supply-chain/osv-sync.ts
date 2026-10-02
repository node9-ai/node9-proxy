// src/supply-chain/osv-sync.ts
// Builds and refreshes the local OSV malicious-package index (osv-index.ts).
// Runs in the daemon on an unref'd timer and from `node9 package-index sync`;
// never on a hook's hot path.
//
//   full:        download <bucket>/<ECOSYSTEM>/all.zip to disk, read only the
//                MAL-*.json entries, rebuild every shard. Used on first run, when
//                the index is older than FULL_REBUILD_MS, or when the backlog
//                of changed records is too large to fetch one by one.
//   incremental: read <bucket>/<ECOSYSTEM>/modified_id.csv (newest first),
//                fetch each MAL- record modified since the last sync, and
//                apply it (replace by id, drop when withdrawn).
//
// A record whose package list SHRINKS keeps its old rows until the next full
// rebuild (an incremental apply only knows the record's current names). That
// errs toward blocking, and the weekly rebuild clears it.
import fs from 'fs';
import path from 'path';
import { Readable } from 'stream';
import { pipeline } from 'stream/promises';
import type { ReadableStream as WebReadableStream } from 'stream/web';
import type { PackageEcosystem } from '@node9/policy-engine';
import { appendToLog, HOOK_DEBUG_LOG } from '../audit';
import { getConfig } from '../config';
import { readZipEntries, readZipEntry } from './zip';
import {
  osvRoot,
  readMeta,
  writeMeta,
  readShard,
  writeShard,
  entriesFromRecord,
  applyRecordToShards,
  type Shard,
} from './osv-index';
import { endpoints } from './net';

export const ECOSYSTEMS: PackageEcosystem[] = ['npm', 'PyPI'];

const SYNC_INTERVAL_MS = 6 * 60 * 60 * 1000;
const FIRST_SYNC_DELAY_MS = 2 * 60 * 1000;
const FULL_REBUILD_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_INCREMENTAL = 5000;
const MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024;
const ARCHIVE_TIMEOUT_MS = 15 * 60 * 1000;
const CSV_MAX_BYTES = 64 * 1024 * 1024;

export interface SyncResult {
  ecosystem: PackageEcosystem;
  mode: 'full' | 'incremental' | 'skipped';
  records: number;
  error?: string;
}

function log(event: string, detail: Record<string, unknown>): void {
  appendToLog(HOOK_DEBUG_LOG, { ts: new Date().toISOString(), event, ...detail });
}

async function download(url: string, dest: string): Promise<void> {
  const res = await fetch(url, { signal: AbortSignal.timeout(ARCHIVE_TIMEOUT_MS) });
  if (!res.ok || !res.body) throw new Error(`download ${res.status}`);
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > MAX_ARCHIVE_BYTES) throw new Error('archive too large');
  let total = 0;
  const body = Readable.fromWeb(res.body as unknown as WebReadableStream);
  body.on('data', (chunk: Buffer) => {
    total += chunk.length;
    if (total > MAX_ARCHIVE_BYTES) body.destroy(new Error('archive too large'));
  });
  await pipeline(body, fs.createWriteStream(dest, { mode: 0o600 }));
}

/** Rebuild one ecosystem's index from its all.zip. */
export async function fullSync(eco: PackageEcosystem, bucket: string): Promise<number> {
  const dir = path.join(osvRoot(), eco);
  fs.mkdirSync(dir, { recursive: true });
  const zipPath = path.join(dir, `all.${process.pid}.zip.tmp`);
  try {
    await download(`${bucket}/${eco}/all.zip`, zipPath);
    const fd = fs.openSync(zipPath, 'r');
    const shards = new Map<string, Shard>();
    let records = 0;
    let lastModifiedMs = 0;
    try {
      const entries = readZipEntries(fd, fs.fstatSync(fd).size);
      for (const e of entries) {
        if (!e.name.startsWith('MAL-') || !e.name.endsWith('.json')) continue;
        let parsed;
        try {
          parsed = entriesFromRecord(eco, JSON.parse(readZipEntry(fd, e).toString('utf8')));
        } catch {
          continue; // one corrupt record must not sink the whole index
        }
        if (!parsed) continue;
        applyRecordToShards(shards, parsed, () => ({}));
        records++;
        if (parsed.modifiedMs > lastModifiedMs) lastModifiedMs = parsed.modifiedMs;
      }
    } finally {
      fs.closeSync(fd);
    }
    if (records === 0) throw new Error('archive held no MAL- records');
    // Replace the shard set: write the new shards, then drop shards that no
    // longer exist, then the meta (the meta is what makes the index live).
    const shardDir = path.join(dir, 'shards');
    fs.mkdirSync(shardDir, { recursive: true });
    for (const [sid, data] of shards) writeShard(eco, sid, data);
    for (const f of fs.readdirSync(shardDir)) {
      if (f.endsWith('.json') && !shards.has(f.slice(0, -5))) fs.rmSync(path.join(shardDir, f));
    }
    writeMeta(eco, {
      syncedAt: new Date().toISOString(),
      lastModifiedMs,
      records,
      mode: 'full',
    });
    return records;
  } finally {
    fs.rmSync(zipPath, { force: true });
  }
}

/** Parse modified_id.csv rows newer than `sinceMs` (the file is newest first). */
export function changedIds(csv: string, sinceMs: number): { ids: string[]; complete: boolean } {
  const ids: string[] = [];
  for (const line of csv.split('\n')) {
    const comma = line.indexOf(',');
    if (comma < 0) continue;
    const ts = Date.parse(line.slice(0, comma));
    // A one-second overlap re-applies the boundary records; applying is idempotent.
    if (!Number.isFinite(ts) || ts < sinceMs - 1000) return { ids, complete: true };
    const id = line.slice(comma + 1).trim();
    if (id.startsWith('MAL-')) ids.push(id);
    if (ids.length > MAX_INCREMENTAL) return { ids, complete: false };
  }
  return { ids, complete: true };
}

async function fetchText(url: string, maxBytes: number): Promise<string> {
  const res = await fetch(url, { signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > maxBytes) throw new Error('response too large');
  return text;
}

/** Apply records modified since the last sync. Returns null when a full rebuild is needed. */
export async function incrementalSync(
  eco: PackageEcosystem,
  bucket: string,
  sinceMs: number
): Promise<number | null> {
  const csv = await fetchText(`${bucket}/${eco}/modified_id.csv`, CSV_MAX_BYTES);
  const { ids, complete } = changedIds(csv, sinceMs);
  if (!complete) return null;
  const shards = new Map<string, Shard>();
  let lastModifiedMs = sinceMs;
  let applied = 0;
  const queue = [...ids];
  const worker = async () => {
    for (let id = queue.shift(); id !== undefined; id = queue.shift()) {
      const res = await fetch(`${bucket}/${eco}/${id}.json`, {
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error(`record ${id}: HTTP ${res.status}`);
      const parsed = entriesFromRecord(eco, await res.json());
      if (!parsed) continue;
      applyRecordToShards(shards, parsed, (sid) => readShard(eco, sid));
      applied++;
      if (parsed.modifiedMs > lastModifiedMs) lastModifiedMs = parsed.modifiedMs;
    }
  };
  // All-or-nothing: a failed fetch throws before anything is written, so the
  // next run retries the same window.
  await Promise.all(Array.from({ length: 8 }, worker));
  for (const [sid, data] of shards) writeShard(eco, sid, data);
  const prev = readMeta(eco);
  writeMeta(eco, {
    syncedAt: new Date().toISOString(),
    lastModifiedMs,
    records: (prev?.records ?? 0) + applied,
    mode: 'incremental',
  });
  return applied;
}

/** Sync one ecosystem: incremental when possible, otherwise a full rebuild. */
export async function syncEcosystem(
  eco: PackageEcosystem,
  opts: { forceFull?: boolean } = {}
): Promise<SyncResult> {
  const bucket = endpoints().osvBucket;
  if (!bucket) return { ecosystem: eco, mode: 'skipped', records: 0, error: 'no endpoint' };
  try {
    const meta = readMeta(eco);
    const stale = !meta || Date.now() - Date.parse(meta.syncedAt) > FULL_REBUILD_MS;
    if (!opts.forceFull && meta && !stale) {
      const n = await incrementalSync(eco, bucket, meta.lastModifiedMs);
      if (n !== null) return { ecosystem: eco, mode: 'incremental', records: n };
    }
    const n = await fullSync(eco, bucket);
    return { ecosystem: eco, mode: 'full', records: n };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    log('package-index-sync-failed', { ecosystem: eco, error });
    return { ecosystem: eco, mode: 'skipped', records: 0, error };
  }
}

let running = false;

/** Sync every ecosystem once, sequentially (one archive in flight at a time). */
export async function syncOsvIndex(opts: { forceFull?: boolean } = {}): Promise<SyncResult[]> {
  if (running) return [];
  running = true;
  try {
    const out: SyncResult[] = [];
    for (const eco of ECOSYSTEMS) out.push(await syncEcosystem(eco, opts));
    return out;
  } finally {
    running = false;
  }
}

/** Daemon entry point: first sync shortly after start, then every 6 hours. */
export function startOsvSync(): void {
  const tick = () => {
    let enabled = false;
    try {
      enabled = getConfig().policy.packageCheck.enabled;
    } catch (err) {
      log('package-index-sync-config-error', { error: (err as Error).message });
    }
    if (enabled) syncOsvIndex().catch(() => {});
  };
  setTimeout(tick, FIRST_SYNC_DELAY_MS).unref();
  setInterval(tick, SYNC_INTERVAL_MS).unref();
}
