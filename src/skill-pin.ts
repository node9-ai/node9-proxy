// src/skill-pin.ts
// Skill pinning — supply chain & update drift defense (AST 02 + AST 07).
// Records SHA-256 hashes of agent skill files/directories on first session use.
// On subsequent sessions, compares hashes; if any skill root changed, the
// session is quarantined and all tool calls are blocked until a human reviews
// the change via `node9 skill pin update <rootKey>`.
//
// Storage: ~/.node9/skill-pins.json (atomic writes, mode 0o600).
// Pattern: mirrors src/mcp-pin.ts one-for-one; file-tree hashing below adds
// the one piece the MCP variant didn't need.

import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FileManifestEntry {
  /** Relative path from the root (for single-file roots, this is the basename) */
  relPath: string;
  /** SHA-256 of the file's bytes */
  fileHash: string;
}

export interface HashResult {
  /** Whether the root path existed at hash time */
  exists: boolean;
  /** SHA-256 hex of canonicalized tree (empty string when !exists) */
  contentHash: string;
  /** 1 for single-file roots, N for directory roots, 0 when !exists */
  fileCount: number;
  /** Per-file manifest (only for directory roots, used by the diff helper) */
  fileManifest?: FileManifestEntry[];
}

export interface SkillPinEntry {
  /** Absolute path that was pinned (for display) */
  rootPath: string;
  /** Whether the root existed at pin time */
  exists: boolean;
  /** SHA-256 of canonicalized tree (empty when !exists) */
  contentHash: string;
  /** 1 for single-file roots, N for directory roots, 0 when !exists */
  fileCount: number;
  /** ISO 8601 timestamp */
  pinnedAt: string;
  /** Optional per-file manifest (written for directory roots to enable diffs) */
  fileManifest?: FileManifestEntry[];
}

export interface SkillPinsFile {
  roots: Record<string, SkillPinEntry>;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

function getPinsFilePath(): string {
  return path.join(os.homedir(), '.node9', 'skill-pins.json');
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/** Safety caps so a pathological root can't hang the hook. */
const MAX_FILES = 5000;
const MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50 MB

function sha256Bytes(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Walk a directory and return a sorted array of {relPath, fileHash} entries.
 * - Skips symlinks (never follows them into arbitrary filesystem locations).
 * - Skips any entries whose combined size would exceed MAX_TOTAL_BYTES.
 * - Caps the number of files at MAX_FILES.
 */
function walkDir(root: string): FileManifestEntry[] {
  const out: FileManifestEntry[] = [];
  let totalBytes = 0;

  const visit = (dir: string, relDir: string): void => {
    if (out.length >= MAX_FILES) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    // Sort entries deterministically for stable traversal (also helps
    // guarantee order-invariance even though we re-sort the final manifest).
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (out.length >= MAX_FILES) return;
      const full = path.join(dir, entry.name);
      const rel = relDir ? path.posix.join(relDir, entry.name) : entry.name;
      // Guard against symlinks — lstat is authoritative for link-ness.
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
      if (totalBytes + lst.size > MAX_TOTAL_BYTES) continue;
      try {
        const buf = fs.readFileSync(full);
        totalBytes += buf.length;
        out.push({ relPath: rel, fileHash: sha256Bytes(buf) });
      } catch {
        // Permission / race — skip this entry rather than failing the whole hash.
      }
    }
  };

  visit(root, '');
  out.sort((a, b) => a.relPath.localeCompare(b.relPath));
  return out;
}

/**
 * Hash a skill root (file or directory). Missing paths return a well-defined
 * `!exists` result; the caller's `checkPin` treats exists-flip as drift.
 */
export function hashSkillRoot(absPath: string): HashResult {
  let lst: fs.Stats;
  try {
    lst = fs.lstatSync(absPath);
  } catch {
    return { exists: false, contentHash: '', fileCount: 0 };
  }
  // Never follow a symlinked root — treat as missing to avoid escapes.
  if (lst.isSymbolicLink()) {
    return { exists: false, contentHash: '', fileCount: 0 };
  }
  if (lst.isFile()) {
    try {
      const buf = fs.readFileSync(absPath);
      const fileHash = sha256Bytes(buf);
      return {
        exists: true,
        contentHash: fileHash,
        fileCount: 1,
      };
    } catch {
      return { exists: false, contentHash: '', fileCount: 0 };
    }
  }
  if (lst.isDirectory()) {
    const manifest = walkDir(absPath);
    const canonical = JSON.stringify(manifest);
    const contentHash = crypto.createHash('sha256').update(canonical).digest('hex');
    return {
      exists: true,
      contentHash,
      fileCount: manifest.length,
      fileManifest: manifest,
    };
  }
  // Special file (socket, block device, etc.) — treat as missing.
  return { exists: false, contentHash: '', fileCount: 0 };
}

/** Derive a short root key from the absolute path. First 16 hex chars of sha256. */
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

/**
 * Read the pin registry from disk with explicit error reporting.
 * - File missing (ENOENT): `{ ok: false, reason: 'missing' }`
 * - File corrupt / unreadable: `{ ok: false, reason: 'corrupt' }`
 * - File valid: `{ ok: true, pins }`
 */
export function readSkillPinsSafe(): SkillPinsReadResult {
  const filePath = getPinsFilePath();
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    if (!raw.trim()) {
      return { ok: false, reason: 'corrupt', detail: 'empty file' };
    }
    const parsed = JSON.parse(raw) as Partial<SkillPinsFile>;
    if (!parsed.roots || typeof parsed.roots !== 'object' || Array.isArray(parsed.roots)) {
      return { ok: false, reason: 'corrupt', detail: 'invalid structure: missing roots object' };
    }
    return { ok: true, pins: { roots: parsed.roots } };
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { ok: false, reason: 'missing' };
    }
    return { ok: false, reason: 'corrupt', detail: String(err) };
  }
}

/** Read the pin registry; returns empty roots on missing; throws on corrupt. */
export function readSkillPins(): SkillPinsFile {
  const result = readSkillPinsSafe();
  if (result.ok) return result.pins;
  if (result.reason === 'missing') return { roots: {} };
  throw new Error(`[node9] skill pin file is corrupt: ${result.detail}`);
}

/** Atomic write of the pin registry to disk. Exported for batched updates. */
export function writeSkillPins(data: SkillPinsFile): void {
  const filePath = getPinsFilePath();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, filePath);
}

// ---------------------------------------------------------------------------
// Pin operations
// ---------------------------------------------------------------------------

/**
 * Check whether a skill root's current state matches the pinned state.
 * Returns:
 *   'new'      — no pin exists for this root
 *   'match'    — content hash AND exists flag both match
 *   'mismatch' — hash differs OR exists flipped (possible drift)
 *   'corrupt'  — pin file exists but is unreadable/malformed (fail closed)
 */
export function checkPin(
  rootKey: string,
  currentHash: string,
  currentExists: boolean
): 'match' | 'mismatch' | 'new' | 'corrupt' {
  const result = readSkillPinsSafe();
  if (!result.ok) {
    if (result.reason === 'missing') return 'new';
    return 'corrupt';
  }
  const entry = result.pins.roots[rootKey];
  if (!entry) return 'new';
  if (entry.exists !== currentExists) return 'mismatch';
  return entry.contentHash === currentHash ? 'match' : 'mismatch';
}

/** Save or overwrite a pin for a skill root. */
export function updatePin(
  rootKey: string,
  rootPath: string,
  contentHash: string,
  exists: boolean,
  fileCount: number,
  fileManifest?: FileManifestEntry[]
): void {
  const pins = readSkillPins();
  pins.roots[rootKey] = {
    rootPath,
    exists,
    contentHash,
    fileCount,
    pinnedAt: new Date().toISOString(),
    ...(fileManifest ? { fileManifest } : {}),
  };
  writeSkillPins(pins);
}

/** Remove a single root's pin. */
export function removePin(rootKey: string): void {
  const pins = readSkillPins();
  delete pins.roots[rootKey];
  writeSkillPins(pins);
}

/** Clear all pins (fresh start). */
export function clearAllPins(): void {
  writeSkillPins({ roots: {} });
}

// ---------------------------------------------------------------------------
// Diff (used by `node9 skill pin update` to explain what changed)
// ---------------------------------------------------------------------------

export type PinDiff =
  | { kind: 'unchanged' }
  | { kind: 'appeared'; rootPath: string }
  | { kind: 'vanished'; rootPath: string }
  | {
      kind: 'changed';
      rootPath: string;
      added: string[];
      removed: string[];
      modified: string[];
    };

/**
 * Compute a human-readable diff between a pin entry and the current state of
 * the root path. Used by the CLI `pin update` flow.
 */
export function computePinDiff(pin: SkillPinEntry, currentPath: string): PinDiff {
  const current = hashSkillRoot(currentPath);
  if (pin.exists && !current.exists) {
    return { kind: 'vanished', rootPath: pin.rootPath };
  }
  if (!pin.exists && current.exists) {
    return { kind: 'appeared', rootPath: pin.rootPath };
  }
  if (!pin.exists && !current.exists) {
    return { kind: 'unchanged' };
  }
  if (pin.contentHash === current.contentHash) {
    return { kind: 'unchanged' };
  }
  // Both exist, hashes differ — build per-file diff if we have a manifest.
  const oldManifest = pin.fileManifest ?? [];
  const newManifest = current.fileManifest ?? [];
  const oldMap = new Map(oldManifest.map((e) => [e.relPath, e.fileHash]));
  const newMap = new Map(newManifest.map((e) => [e.relPath, e.fileHash]));
  const added: string[] = [];
  const removed: string[] = [];
  const modified: string[] = [];
  for (const [rel, hash] of newMap) {
    const prev = oldMap.get(rel);
    if (prev === undefined) added.push(rel);
    else if (prev !== hash) modified.push(rel);
  }
  for (const rel of oldMap.keys()) {
    if (!newMap.has(rel)) removed.push(rel);
  }
  added.sort();
  removed.sort();
  modified.sort();
  return { kind: 'changed', rootPath: pin.rootPath, added, removed, modified };
}

// ---------------------------------------------------------------------------
// Default skill roots (used by the check hook)
// ---------------------------------------------------------------------------

/**
 * Resolve the default set of skill roots Node9 protects. Global roots are
 * absolute paths; project roots are only returned when `cwd` is an absolute
 * path (per CLAUDE.md: validate external path inputs before filesystem use).
 */
export function defaultSkillRoots(cwd: string | undefined): string[] {
  const home = os.homedir();
  const global = [
    path.join(home, '.claude', 'skills'),
    path.join(home, '.claude', 'CLAUDE.md'),
    path.join(home, '.claude', 'rules'),
  ];
  if (!cwd || !path.isAbsolute(cwd)) return global;
  return [
    ...global,
    path.join(cwd, '.claude', 'CLAUDE.md'),
    path.join(cwd, '.claude', 'CLAUDE.local.md'),
    path.join(cwd, '.claude', 'rules'),
    path.join(cwd, '.cursor', 'rules'),
    path.join(cwd, 'AGENTS.md'),
    path.join(cwd, 'CLAUDE.md'),
  ];
}

/**
 * Verify a set of skill roots against the pin registry in one pass.
 * - First root that drifts returns `drift` (session should be quarantined).
 * - Corrupt pin file returns `corrupt` (session should be quarantined).
 * - Roots with no prior pin are pinned in a single batched write; result is `verified`.
 * - Roots whose content/existence matches the pin pass silently; result is `verified`.
 *
 * De-duplicates roots by path. Callers typically pass
 * `[...defaultSkillRoots(cwd), ...userProvided]`.
 */
export type VerifyResult =
  | { kind: 'verified' }
  | { kind: 'corrupt'; detail: string }
  | { kind: 'drift'; changedRootKey: string; changedRootPath: string; summary: string };

export function verifyAndPinRoots(roots: string[]): VerifyResult {
  const pinsRead = readSkillPinsSafe();
  if (!pinsRead.ok && pinsRead.reason === 'corrupt') {
    return { kind: 'corrupt', detail: pinsRead.detail };
  }
  const pins: SkillPinsFile = pinsRead.ok ? pinsRead.pins : { roots: {} };

  // De-dup (different callers can construct the same path twice).
  const unique = Array.from(new Set(roots));
  let mutated = false;

  for (const rootPath of unique) {
    const rootKey = getRootKey(rootPath);
    const current = hashSkillRoot(rootPath);
    const existing = pins.roots[rootKey];
    if (!existing) {
      // First pin for this root — record it.
      pins.roots[rootKey] = {
        rootPath,
        exists: current.exists,
        contentHash: current.contentHash,
        fileCount: current.fileCount,
        pinnedAt: new Date().toISOString(),
        ...(current.fileManifest ? { fileManifest: current.fileManifest } : {}),
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
    // Matches — no action.
  }

  if (mutated) {
    writeSkillPins(pins);
  }
  return { kind: 'verified' };
}

/**
 * Resolve a user-supplied skill root. Absolute paths pass through; paths
 * starting with `~/` are expanded against the home directory; relative paths
 * are joined onto `cwd` if it is absolute, otherwise ignored (returns null).
 */
export function resolveUserSkillRoot(entry: string, cwd: string | undefined): string | null {
  if (!entry) return null;
  if (entry.startsWith('~/') || entry === '~') {
    return path.join(os.homedir(), entry.slice(1));
  }
  if (path.isAbsolute(entry)) return entry;
  if (!cwd || !path.isAbsolute(cwd)) return null;
  return path.join(cwd, entry);
}
