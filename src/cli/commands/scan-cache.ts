// The incremental history scan (fw#400).
//
// `node9 scan` re-read and re-judged every transcript on every run: 9.5 minutes
// for 30 days on one machine, and the 90-day run did not finish. The judging
// moved into the live gate's forecast (fw#399), so a per-file result is a pure
// function of (file bytes, window start, the configuration the judge used,
// the engine version). This cache keeps that result under
// `~/.node9/scan-cache/` and hands it back when the file has not changed.
//
// Granularity: one transcript file, which is one session for every agent the
// scan reads. A grown file is re-read whole, not from an offset: loop
// analytics and the early-secrets metric look at the whole session, and the
// growing files are the few live sessions. The whole cache is dropped when the
// configuration hash, the engine version or the cache version changes: a
// changed setting must change every row.
//
// Nothing here changes `--json`: the merged result is the same object a cold
// run builds, which the snapshot test proves.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';
import { CANONICAL_EXTRACTOR_VERSION } from '@node9/policy-engine';
import type { Config } from '../../config';
import type { ScanResult } from './scan';

/** Bump when the per-file result shape or the parsers' semantics change. */
export const SCAN_CACHE_VERSION = 1;

interface IndexEntry {
  size: number;
  mtimeMs: number;
  /** The window the result was computed for (`all` or an ISO date). */
  window: string;
  agent: string;
  /** Cached result file, relative to the cache root. */
  result: string;
}

interface IndexFile {
  cacheVersion: number;
  engineVersion: string;
  configHash: string;
  files: Record<string, IndexEntry>;
}

export interface FileStamp {
  size: number;
  mtimeMs: number;
}

export function scanCacheRoot(): string {
  return path.join(os.homedir(), '.node9', 'scan-cache');
}

/** A hash of everything the judge reads that can change a verdict. */
export function configHashOf(config: Config): string {
  const h = createHash('sha256');
  h.update(JSON.stringify(config.settings.mode ?? ''));
  h.update(JSON.stringify(config.policySource));
  h.update(JSON.stringify(config.policy));
  return h.digest('hex').slice(0, 16);
}

export function fileStamp(filePath: string): FileStamp | null {
  try {
    const st = fs.statSync(filePath);
    return { size: st.size, mtimeMs: st.mtimeMs };
  } catch {
    return null;
  }
}

export class ScanCache {
  private readonly root: string;
  private index: IndexFile;
  private dirty = false;
  readonly enabled: boolean;
  /** Counters for the run, so a caller can say what was reused. */
  hits = 0;
  misses = 0;

  constructor(opts: { configHash: string; enabled?: boolean; root?: string }) {
    this.root = opts.root ?? scanCacheRoot();
    this.enabled = opts.enabled ?? process.env.NODE9_SCAN_CACHE !== '0';
    this.index = this.load(opts.configHash);
  }

  private load(configHash: string): IndexFile {
    const fresh: IndexFile = {
      cacheVersion: SCAN_CACHE_VERSION,
      engineVersion: CANONICAL_EXTRACTOR_VERSION,
      configHash,
      files: {},
    };
    if (!this.enabled) return fresh;
    try {
      const raw = JSON.parse(
        fs.readFileSync(path.join(this.root, 'index.json'), 'utf8')
      ) as IndexFile;
      if (
        raw.cacheVersion !== SCAN_CACHE_VERSION ||
        raw.engineVersion !== CANONICAL_EXTRACTOR_VERSION ||
        raw.configHash !== configHash ||
        typeof raw.files !== 'object'
      ) {
        // A different world: every cached row is stale.
        this.dropAll();
        return fresh;
      }
      return raw;
    } catch {
      return fresh;
    }
  }

  private dropAll(): void {
    try {
      fs.rmSync(this.root, { recursive: true, force: true });
    } catch {
      /* a cache that cannot be removed is simply not read */
    }
  }

  /** The cached result for an unchanged file in this window, or null. */
  get(filePath: string, stamp: FileStamp, window: string): ScanResult | null {
    if (!this.enabled) return null;
    const e = this.index.files[filePath];
    if (!e || e.size !== stamp.size || e.mtimeMs !== stamp.mtimeMs || e.window !== window) {
      this.misses++;
      return null;
    }
    try {
      const r = JSON.parse(fs.readFileSync(path.join(this.root, e.result), 'utf8')) as ScanResult;
      this.hits++;
      return r;
    } catch {
      this.misses++;
      return null;
    }
  }

  put(filePath: string, stamp: FileStamp, window: string, agent: string, result: ScanResult): void {
    if (!this.enabled) return;
    const name = createHash('sha1').update(`${agent}|${filePath}|${window}`).digest('hex');
    const rel = path.join('files', name.slice(0, 2), `${name}.json`);
    try {
      const abs = path.join(this.root, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true, mode: 0o700 });
      fs.writeFileSync(abs, JSON.stringify(result), { mode: 0o600 });
      this.index.files[filePath] = { ...stamp, window, agent, result: rel };
      this.dirty = true;
    } catch {
      /* best effort: a cache write failure costs the next run time, not truth */
    }
  }

  /** Write the index once per run. */
  flush(): void {
    if (!this.enabled || !this.dirty) return;
    try {
      fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
      const tmp = path.join(this.root, `index.${process.pid}.tmp`);
      fs.writeFileSync(tmp, JSON.stringify(this.index), { mode: 0o600 });
      fs.renameSync(tmp, path.join(this.root, 'index.json'));
      this.dirty = false;
    } catch {
      /* same: best effort */
    }
  }
}

/** The window key: the start date at day precision, or `all`. */
export function windowKey(startDate: Date | null): string {
  return startDate ? startDate.toISOString().slice(0, 10) : 'all';
}
