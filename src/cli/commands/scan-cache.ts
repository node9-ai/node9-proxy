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
// scan reads, judged from the window start less a state lookback (or whole)
// and stored with its activity split by day; the window is applied when the
// file is merged. An entry records where judging started: any window starting
// at or after it is served from the entry, so a daily run whose window moves
// forward stays warm, and only a wider window re-judges (fw#406). A grown file is re-read whole,
// not from an offset: loop analytics and the early-secrets metric look at the
// whole session, and the growing files are the few live sessions. The whole
// cache is dropped when the configuration hash, the engine version, the proxy
// version or the cache version changes: a changed setting must change every
// row. The index is flushed every few files and on an interrupt, so a run
// stopped with Ctrl-C keeps what it judged.
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
import { PROXY_VERSION } from '../../version';

/** Bump when the per-file result shape or the parsers' semantics change. */
export const SCAN_CACHE_VERSION = 3;

/** Flush the index after this many new entries, or after this long. */
const FLUSH_EVERY_FILES = 25;
const FLUSH_EVERY_MS = 10_000;

/** Every cache opened in this process, so an interrupt can flush them all. */
const activeCaches = new Set<ScanCache>();
export function flushScanCaches(): void {
  for (const c of activeCaches) c.flush();
}

interface IndexEntry {
  size: number;
  mtimeMs: number;
  agent: string;
  /** Cached result file, relative to the cache root. */
  result: string;
  /** Hash of the configuration of every working directory the file's calls
   *  were judged under; a project file that changed misses the cache. */
  configHashes?: Record<string, string>;
  /** When the entry was written. */
  at: number;
  /** ISO instant judging started from; absent = the whole file. */
  judgedFrom?: string;
}

interface IndexFile {
  cacheVersion: number;
  engineVersion: string;
  proxyVersion: string;
  configHash: string;
  /** Keyed by the transcript's absolute path. */
  files: Record<string, IndexEntry>;
}

/** What the cache needs from the judge: the hash of a directory's configuration. */
export interface ConfigHasher {
  configHashFor(cwd: string | undefined): string;
}

export interface FileStamp {
  size: number;
  mtimeMs: number;
}

export function scanCacheRoot(): string {
  return path.join(os.homedir(), '.node9', 'scan-cache');
}

/** Files beside config.json that the gate reads on every call and that are
 *  not part of the resolved configuration object: the decoy registry, the
 *  shield state, jail paths, standing decisions, trusted hosts and
 *  recipients, the workspace policy cache and the OSV index metadata. */
const SIDECAR_FILES = [
  'canaries.json',
  'shields.json',
  'jail-paths.json',
  'decisions.json',
  'trusted-hosts.json',
  'trusted-recipients.json',
  'rules-cache.json',
  path.join('osv', 'npm', 'meta.json'),
  path.join('osv', 'PyPI', 'meta.json'),
];

/** A hash of everything the judge reads that can change a verdict: the
 *  resolved configuration and the size and mtime of every sidecar file. */
export function configHashOf(config: Config): string {
  const h = createHash('sha256');
  h.update(JSON.stringify(config.settings.mode ?? ''));
  h.update(JSON.stringify(config.policySource));
  h.update(JSON.stringify(config.policy));
  for (const name of SIDECAR_FILES) {
    const st = fileStamp(path.join(os.homedir(), '.node9', name));
    h.update(`|${name}:${st ? `${st.size}:${st.mtimeMs}` : 'absent'}`);
  }
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
  private pendingPuts = 0;
  private lastFlush = Date.now();

  constructor(opts: { configHash: string; enabled?: boolean; root?: string }) {
    this.root = opts.root ?? scanCacheRoot();
    this.enabled = opts.enabled ?? process.env.NODE9_SCAN_CACHE !== '0';
    this.index = this.load(opts.configHash);
    activeCaches.add(this);
  }

  private load(configHash: string): IndexFile {
    const fresh: IndexFile = {
      cacheVersion: SCAN_CACHE_VERSION,
      engineVersion: CANONICAL_EXTRACTOR_VERSION,
      proxyVersion: PROXY_VERSION,
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
        raw.proxyVersion !== PROXY_VERSION ||
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

  /** The cached whole-file result for an unchanged file, judged under
   *  configurations that have not changed either, or null. */
  get(
    filePath: string,
    stamp: FileStamp,
    hasher?: ConfigHasher,
    judgeFrom: Date | null = null
  ): ScanResult | null {
    if (!this.enabled) return null;
    const e = this.index.files[filePath];
    if (!e || e.size !== stamp.size || e.mtimeMs !== stamp.mtimeMs) {
      this.misses++;
      return null;
    }
    // The entry must cover the span this window judges: a whole-file entry
    // covers every window, a partial one only windows starting at or after it.
    if (e.judgedFrom && (!judgeFrom || judgeFrom.getTime() < Date.parse(e.judgedFrom))) {
      this.misses++;
      return null;
    }
    for (const [cwd, hash] of Object.entries(e.configHashes ?? {})) {
      if (hasher && hasher.configHashFor(cwd) !== hash) {
        this.misses++;
        return null;
      }
    }
    try {
      // The file carries where its judging started: two processes with
      // different windows writing the same transcript must not pair one's
      // index entry with the other's content (fw#406 review).
      const stored = JSON.parse(fs.readFileSync(path.join(this.root, e.result), 'utf8')) as {
        judgedFrom: string | null;
        result: ScanResult;
      };
      if ((stored.judgedFrom ?? null) !== (e.judgedFrom ?? null) || !stored.result) {
        this.misses++;
        return null;
      }
      this.hits++;
      return stored.result;
    } catch {
      this.misses++;
      return null;
    }
  }

  put(
    filePath: string,
    stamp: FileStamp,
    agent: string,
    result: ScanResult,
    hasher?: ConfigHasher,
    judgeFrom: Date | null = null
  ): void {
    if (!this.enabled) return;
    const name = createHash('sha256').update(`${agent}|${filePath}`).digest('hex').slice(0, 40);
    const rel = path.join('files', name.slice(0, 2), `${name}.json`);
    const configHashes: Record<string, string> = {};
    if (hasher)
      for (const cwd of result.configCwds ?? []) configHashes[cwd] = hasher.configHashFor(cwd);
    try {
      const abs = path.join(this.root, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true, mode: 0o700 });
      fs.writeFileSync(
        abs,
        JSON.stringify({ judgedFrom: judgeFrom ? judgeFrom.toISOString() : null, result }),
        { mode: 0o600 }
      );
      this.index.files[filePath] = {
        ...stamp,
        agent,
        result: rel,
        configHashes,
        at: Date.now(),
        ...(judgeFrom && { judgedFrom: judgeFrom.toISOString() }),
      };
      this.dirty = true;
      this.pendingPuts++;
      if (this.pendingPuts >= FLUSH_EVERY_FILES || Date.now() - this.lastFlush > FLUSH_EVERY_MS)
        this.flush();
    } catch {
      /* best effort: a cache write failure costs the next run time, not truth */
    }
  }

  /** Drop the entries of transcripts that no longer exist, and their files. */
  private prune(): void {
    for (const [key, e] of Object.entries(this.index.files)) {
      if (fs.existsSync(key)) continue;
      try {
        fs.rmSync(path.join(this.root, e.result), { force: true });
      } catch {
        /* the index entry goes either way */
      }
      delete this.index.files[key];
      this.dirty = true;
    }
  }

  /** The final flush of a run: the cache leaves the interrupt registry, so a
   *  long-lived daemon does not keep every index it ever opened. */
  close(): void {
    this.flush();
    activeCaches.delete(this);
  }

  /** Write the index: every few files, on an interrupt, and at the end. */
  flush(): void {
    if (!this.enabled) return;
    if (this.pendingPuts === 0) this.prune();
    this.pendingPuts = 0;
    this.lastFlush = Date.now();
    if (!this.dirty) return;
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
