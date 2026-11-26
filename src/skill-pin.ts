// src/skill-pin.ts
// Skill pinning — supply chain & update drift defense (AST 02 + AST 07).
// Records SHA-256 hashes of agent skill files/directories on first session use.
// On subsequent sessions, compares hashes; if any skill root changed, the
// session is quarantined and all tool calls are blocked until a human reviews
// the change via `node9 skill pin update <rootKey>`.
//
// Storage: ~/.node9/skill-pins.json (atomic writes, mode 0o600).
// Pattern: mirrors src/mcp-pin.ts; adds file-tree hashing for directory roots.

import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { readCapped } from './utils/read-capped';
import { installedPlugins } from './addons/installed-plugins';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HashResult {
  /** Whether the root path existed at hash time */
  exists: boolean;
  /** SHA-256 hex of canonicalized tree (empty string when !exists) */
  contentHash: string;
  /** 1 for single-file roots, N for directory roots, 0 when !exists */
  fileCount: number;
}

export interface SkillPinEntry {
  rootPath: string;
  exists: boolean;
  contentHash: string;
  fileCount: number;
  pinnedAt: string;
}

export interface SkillPinsFile {
  roots: Record<string, SkillPinEntry>;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

function getPinsFilePath(home: string = os.homedir()): string {
  return path.join(home, '.node9', 'skill-pins.json');
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

const MAX_FILES = 5000;
const MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50 MB safety cap

function sha256Bytes(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/** Walk a directory and return sorted `relpath\0hash` tuples (symlink-safe, capped). */
function walkDir(root: string): string[] {
  const out: Array<{ rel: string; hash: string }> = [];
  let totalBytes = 0;

  const visit = (dir: string, relDir: string): void => {
    if (out.length >= MAX_FILES) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (out.length >= MAX_FILES) return;
      const full = path.join(dir, entry.name);
      const rel = relDir ? path.posix.join(relDir, entry.name) : entry.name;
      let lst: fs.Stats;
      try {
        lst = fs.lstatSync(full);
      } catch {
        continue;
      }
      if (lst.isSymbolicLink()) continue;
      if (lst.isDirectory()) {
        visit(full, rel);
        continue;
      }
      if (!lst.isFile()) continue;
      // Budget enforced by the read rather than by lst.size: the cap is
      // cumulative, and a file swapped after the lstat would blow it.
      // `truncated` reproduces the old skip-the-file behaviour exactly, and
      // readCapped returns raw bytes because these are hashed.
      const remaining = MAX_TOTAL_BYTES - totalBytes;
      if (remaining <= 0) continue;
      const capped = readCapped(full, remaining);
      if (!capped || capped.truncated) continue;
      totalBytes += capped.bytes.length;
      out.push({ rel, hash: sha256Bytes(capped.bytes) });
    }
  };

  visit(root, '');
  out.sort((a, b) => a.rel.localeCompare(b.rel));
  return out.map((e) => `${e.rel}\0${e.hash}`);
}

/** Hash a skill root (file or directory). Missing paths return `!exists`. */
export function hashSkillRoot(absPath: string): HashResult {
  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(absPath);
  } catch {
    return { exists: false, contentHash: '', fileCount: 0 };
  }
  if (lst.isSymbolicLink()) return { exists: false, contentHash: '', fileCount: 0 };
  if (lst.isFile()) {
    try {
      return { exists: true, contentHash: sha256Bytes(fs.readFileSync(absPath)), fileCount: 1 };
    } catch {
      return { exists: false, contentHash: '', fileCount: 0 };
    }
  }
  if (lst.isDirectory()) {
    const entries = walkDir(absPath);
    const contentHash = crypto.createHash('sha256').update(entries.join('\n')).digest('hex');
    return { exists: true, contentHash, fileCount: entries.length };
  }
  return { exists: false, contentHash: '', fileCount: 0 };
}

/** First 16 hex chars of sha256(absolutePath) — stable short identifier. */
export function getRootKey(absPath: string): string {
  return crypto.createHash('sha256').update(absPath).digest('hex').slice(0, 16);
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

export type SkillPinsReadResult =
  | { ok: true; pins: SkillPinsFile }
  | { ok: false; reason: 'missing' }
  | { ok: false; reason: 'corrupt'; detail: string };

export function readSkillPinsSafe(home?: string): SkillPinsReadResult {
  const filePath = getPinsFilePath(home);
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    if (!raw.trim()) return { ok: false, reason: 'corrupt', detail: 'empty file' };
    const parsed = JSON.parse(raw) as Partial<SkillPinsFile>;
    if (!parsed.roots || typeof parsed.roots !== 'object' || Array.isArray(parsed.roots)) {
      return { ok: false, reason: 'corrupt', detail: 'invalid structure: missing roots object' };
    }
    return { ok: true, pins: { roots: parsed.roots } };
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { ok: false, reason: 'missing' };
    return { ok: false, reason: 'corrupt', detail: String(err) };
  }
}

export function readSkillPins(): SkillPinsFile {
  const result = readSkillPinsSafe();
  if (result.ok) return result.pins;
  if (result.reason === 'missing') return { roots: {} };
  throw new Error(`[node9] skill pin file is corrupt: ${result.detail}`);
}

function writeSkillPins(data: SkillPinsFile): void {
  const filePath = getPinsFilePath();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

// ---------------------------------------------------------------------------
// Pin operations
// ---------------------------------------------------------------------------

export function checkPin(
  rootKey: string,
  currentHash: string,
  currentExists: boolean
): 'match' | 'mismatch' | 'new' | 'corrupt' {
  const result = readSkillPinsSafe();
  if (!result.ok) return result.reason === 'missing' ? 'new' : 'corrupt';
  const entry = result.pins.roots[rootKey];
  if (!entry) return 'new';
  if (entry.exists !== currentExists) return 'mismatch';
  return entry.contentHash === currentHash ? 'match' : 'mismatch';
}

export function updatePin(
  rootKey: string,
  rootPath: string,
  contentHash: string,
  exists: boolean,
  fileCount: number
): void {
  const pins = readSkillPins();
  pins.roots[rootKey] = {
    rootPath,
    exists,
    contentHash,
    fileCount,
    pinnedAt: new Date().toISOString(),
  };
  writeSkillPins(pins);
}

export function removePin(rootKey: string): void {
  const pins = readSkillPins();
  delete pins.roots[rootKey];
  writeSkillPins(pins);
}

export function clearAllPins(): void {
  writeSkillPins({ roots: {} });
}

// ---------------------------------------------------------------------------
// Batched verification (used by the check hook)
// ---------------------------------------------------------------------------

export type VerifyResult =
  | { kind: 'verified' }
  | { kind: 'corrupt'; detail: string }
  | { kind: 'drift'; changedRootKey: string; changedRootPath: string; summary: string };

/**
 * Verify a set of skill roots against the pin registry in one pass.
 * First drift short-circuits and returns `drift`. New roots are pinned in a
 * single batched write.
 */
export function verifyAndPinRoots(
  roots: Array<string | SkillRoot>,
  /** A change someone already approved elsewhere (the workspace's approved
   *  list of add-ons, node9Firewall#376): re-pinned silently, not drift. */
  acknowledged?: (root: SkillRoot, contentHash: string) => boolean
): VerifyResult {
  const pinsRead = readSkillPinsSafe();
  if (!pinsRead.ok && pinsRead.reason === 'corrupt') {
    return { kind: 'corrupt', detail: pinsRead.detail };
  }
  const pins: SkillPinsFile = pinsRead.ok ? pinsRead.pins : { roots: {} };
  let mutated = false;

  const seen = new Set<string>();
  for (const [key, entry] of Object.entries(pins.roots))
    if (entry && typeof entry.rootPath === 'string' && isLegacyCatalogPin(entry.rootPath)) {
      delete pins.roots[key];
      mutated = true;
    }
  for (const root of roots) {
    const entry: SkillRoot = typeof root === 'string' ? pathRoot(root) : root;
    const { path: rootPath, key: rootKey } = entry;
    if (seen.has(rootKey)) continue;
    seen.add(rootKey);
    const current = hashSkillRoot(rootPath);
    const existing = pins.roots[rootKey];
    if (!existing) {
      pins.roots[rootKey] = {
        rootPath,
        exists: current.exists,
        contentHash: current.contentHash,
        fileCount: current.fileCount,
        pinnedAt: new Date().toISOString(),
      };
      mutated = true;
      continue;
    }
    if (
      current.exists &&
      (existing.exists !== current.exists || existing.contentHash !== current.contentHash) &&
      acknowledged?.(entry, current.contentHash)
    ) {
      pins.roots[rootKey] = {
        rootPath,
        exists: true,
        contentHash: current.contentHash,
        fileCount: current.fileCount,
        pinnedAt: new Date().toISOString(),
      };
      mutated = true;
      continue;
    }
    if (existing.exists !== current.exists || existing.contentHash !== current.contentHash) {
      let summary: string;
      if (existing.exists && !current.exists) summary = `vanished: ${rootPath}`;
      else if (!existing.exists && current.exists) summary = `appeared: ${rootPath}`;
      else summary = `changed: ${rootPath}`;
      return { kind: 'drift', changedRootKey: rootKey, changedRootPath: rootPath, summary };
    }
  }
  if (mutated) writeSkillPins(pins);
  return { kind: 'verified' };
}

// ---------------------------------------------------------------------------
// Root resolution (used by the check hook)
// ---------------------------------------------------------------------------

/** A bound against a corrupt installed list, far above any real install. */
const MAX_PINNED_PLUGINS = 5000;

/** Pins written by earlier versions keyed marketplace catalog folders; they are
 *  never checked again, so they are dropped instead of lingering in
 *  `node9 skill pin list`. */
function isLegacyCatalogPin(rootPath: string): boolean {
  const marker = `${path.sep}.claude${path.sep}plugins${path.sep}marketplaces${path.sep}`;
  return rootPath.includes(marker);
}

/** A root to pin and the key its pin is filed under. */
export interface SkillRoot {
  path: string;
  key: string;
  /** For an installed plugin: `name@marketplace`, the key the workspace's
   *  approved list of add-ons files it under. */
  plugin?: string;
}

/** A root keyed by its path: a folder the user named in `policy.skillPinning.roots`. */
export function pathRoot(absPath: string): SkillRoot {
  return { path: absPath, key: getRootKey(absPath) };
}

/**
 * The installed Claude Code plugins, one pin root each.
 *
 * Installed only: `~/.claude/plugins/installed_plugins.json`. The marketplace
 * folders (`~/.claude/plugins/marketplaces/<registry>/plugins/*`) hold the
 * whole catalog, installed or not, and Claude Code refreshes them on its own,
 * so pinning them quarantined sessions over plugins that never run.
 *
 * Keyed by the plugin (`name@marketplace`), not its path: each version is
 * installed in a folder of its own, so a path key would take every update for
 * a new plugin and trust it silently. Under this key an update is a change to
 * the pinned plugin, which is what the pin exists to catch; `node9 skill pin
 * update <key>` drops the pin and the next session pins the new folder.
 *
 * A new plugin creates its pin silently, the way a new MCP server does. User
 * files (CLAUDE.md, .cursor/rules/) are not included; extend with
 * `config.policy.skillPinning.roots`.
 */
export function defaultSkillRootEntries(home: string = os.homedir()): SkillRoot[] {
  // No report-size cap here: every installed plugin gets its pin.
  return installedPlugins(home, MAX_PINNED_PLUGINS)
    .filter((p): p is typeof p & { installPath: string } => !!p.installPath)
    .map((p) => ({ path: p.installPath, key: getRootKey(`plugin:${p.key}`), plugin: p.key }));
}

/** The installed plugins' folders (for reports that list them). */
export function defaultSkillRoots(_cwd: string | undefined, home: string = os.homedir()): string[] {
  return defaultSkillRootEntries(home).map((r) => r.path);
}

/** Resolve a user-supplied entry: absolute, `~/`-prefixed, or cwd-relative. */
export function resolveUserSkillRoot(entry: string, cwd: string | undefined): string | null {
  if (!entry) return null;
  if (entry.startsWith('~/') || entry === '~') return path.join(os.homedir(), entry.slice(1));
  if (path.isAbsolute(entry)) return entry;
  if (!cwd || !path.isAbsolute(cwd)) return null;
  return path.join(cwd, entry);
}
