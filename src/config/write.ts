// src/config/write.ts
// The one writer for a node9 config file.
//
// Nine places used to read-modify-write ~/.node9/config.json on their own,
// each without a lock, without validation, and each in whatever shape it
// assumed. With the v2 file that is untenable: a writer that does not know the
// file's format silently writes the old one, and a later reader ignores it.
//
// Callers mutate the LEGACY file shape (settings / policy / environments),
// the shape every writer already thinks in; this module persists in the
// format the file is in (a v2 file stays v2, a legacy or missing file stays
// legacy until `node9 config migrate` or `node9 init` writes v2). The write
// is serialised across processes by a lock file and lands atomically.

import fs from 'fs';
import path from 'path';
import os from 'os';
import { atomicWriteSync } from '../utils/atomic-write';
import { isV2File, v2ToLegacy, legacyToV2, type LegacyFile } from './v2';
import type { Verdict } from '@node9/policy-engine';
import { _resetConfigCache } from './index';

/** Computed per call: tests move HOME, and a load-time constant would not follow. */
export function globalConfigPath(): string {
  return path.join(os.homedir(), '.node9', 'config.json');
}

export type ConfigFileFormat = 'v2' | 'legacy' | 'missing';

export interface ConfigFileView {
  format: ConfigFileFormat;
  /** The file's content as the legacy shape, whatever its format on disk. */
  legacy: LegacyFile;
  /** A v2 file's explicit `checks`, kept so a write round-trips the ones the
   *  legacy shape cannot carry (`commands.sudo` has no legacy knob). */
  checks: Record<string, Verdict>;
}

/**
 * Read a config file as the legacy shape. A missing file is an empty one; a
 * file that exists but is not JSON throws, because a writer must never
 * overwrite a config it could not read.
 */
export function readConfigFileView(filePath: string): ConfigFileView {
  let text: string;
  try {
    text = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT')
      return { format: 'missing', legacy: {}, checks: {} };
    throw err;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error(
      `${filePath} is not valid JSON; fix it before changing settings (refusing to overwrite).`
    );
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error(`${filePath} is not a JSON object; fix it before changing settings.`);
  if (isV2File(raw)) {
    const { legacy, stated } = v2ToLegacy(raw);
    return { format: 'v2', legacy, checks: stated };
  }
  return { format: 'legacy', legacy: raw as LegacyFile, checks: {} };
}

/** The legacy-shaped view of a file, for readers that need the raw file
 *  rather than the merged config (an approver toggle, the egress block). */
export function readConfigFileLegacy(filePath: string = globalConfigPath()): LegacyFile {
  return readConfigFileView(filePath).legacy;
}

// ── Lock ─────────────────────────────────────────────────────────────────────

const LOCK_WAIT_MS = 2000;
const LOCK_STALE_MS = 10_000;

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Take `<file>.lock` (O_EXCL), waiting up to two seconds; a lock older than
 *  ten seconds belongs to a process that died and is taken over. */
function withLock<T>(filePath: string, fn: () => T): T {
  const lockPath = `${filePath}.lock`;
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx');
      fs.closeSync(fd);
      break;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      try {
        if (Date.now() - fs.statSync(lockPath).mtimeMs > LOCK_STALE_MS) {
          fs.unlinkSync(lockPath);
          continue;
        }
      } catch {
        continue; // the holder released it between our two calls
      }
      if (Date.now() > deadline)
        throw new Error(`${filePath} is locked by another node9 process; try again.`);
      sleepSync(20);
    }
  }
  try {
    return fn();
  } finally {
    try {
      fs.unlinkSync(lockPath);
    } catch {
      /* best effort */
    }
  }
}

// ── Write ────────────────────────────────────────────────────────────────────

export interface WriteConfigOptions {
  /** Persist as v2 even when the file was legacy or missing. Migration uses
   *  it; everything else keeps the file's own format. */
  format?: 'v2';
}

/**
 * Read, mutate, write, under the lock. `mutate` receives the legacy shape and
 * changes it in place (or returns a replacement). Returns the format written.
 */
export function writeConfigFile(
  filePath: string,
  mutate: (file: LegacyFile) => LegacyFile | void,
  options: WriteConfigOptions = {}
): ConfigFileFormat {
  return withLock(filePath, () => {
    const view = readConfigFileView(filePath);
    const next = mutate(view.legacy) ?? view.legacy;
    // A file keeps its format. A missing file is created in the legacy shape:
    // only `node9 init` (a new machine) and `node9 config migrate` create v2.
    const format: ConfigFileFormat =
      options.format === 'v2' || view.format === 'v2' ? 'v2' : 'legacy';
    // A legacy file is written back as it was read, nothing added.
    const body = format === 'v2' ? legacyToV2(next, view.checks) : next;
    atomicWriteSync(filePath, JSON.stringify(body, null, 2) + '\n', { mode: 0o600 });
    _resetConfigCache();
    return format;
  });
}

export type RewriteOutcome =
  | { status: 'rewritten'; backup: string; written: Record<string, unknown> }
  | { status: 'already-v2' }
  | { status: 'no-file' };

/**
 * Move one file to the v2 shape, backup included, entirely under the lock:
 * read, check, copy, write. Two processes migrating at once (several
 * `mcp-gateway`s at agent start) produce one backup and one rewrite; the
 * second finds the file already v2.
 */
export function rewriteAsV2(filePath: string, backupPath: string): RewriteOutcome {
  return withLock(filePath, () => {
    const view = readConfigFileView(filePath);
    if (view.format === 'missing') return { status: 'no-file' };
    if (view.format === 'v2') return { status: 'already-v2' };
    fs.copyFileSync(filePath, backupPath);
    const body = legacyToV2(view.legacy) as unknown as Record<string, unknown>;
    atomicWriteSync(filePath, JSON.stringify(body, null, 2) + '\n', { mode: 0o600 });
    _resetConfigCache();
    return { status: 'rewritten', backup: backupPath, written: body };
  });
}

/** The global file, ~/.node9/config.json. */
export function writeLocalConfig(
  mutate: (file: LegacyFile) => LegacyFile | void,
  options: WriteConfigOptions = {}
): ConfigFileFormat {
  return writeConfigFile(globalConfigPath(), mutate, options);
}

/** Set one key under `settings` in the global file. */
export function writeLocalSetting(key: string, value: unknown): void {
  writeLocalConfig((file) => {
    file.settings = { ...(file.settings ?? {}), [key]: value } as LegacyFile['settings'];
  });
}
