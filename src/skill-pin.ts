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

function getPinsFilePath(): string {
  return path.join(os.homedir(), '.node9', 'skill-pins.json');
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
      if (totalBytes + lst.size > MAX_TOTAL_BYTES) continue;
      try {
        const buf = fs.readFileSync(full);
        totalBytes += buf.length;
        out.push({ rel, hash: sha256Bytes(buf) });
      } catch {
        /* permission/race — skip */
      }
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

export function readSkillPinsSafe(): SkillPinsReadResult {
  const filePath = getPinsFilePath();
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
export function verifyAndPinRoots(roots: string[]): VerifyResult {
  const pinsRead = readSkillPinsSafe();
  if (!pinsRead.ok && pinsRead.reason === 'corrupt') {
    return { kind: 'corrupt', detail: pinsRead.detail };
  }
  const pins: SkillPinsFile = pinsRead.ok ? pinsRead.pins : { roots: {} };
  let mutated = false;

  for (const rootPath of new Set(roots)) {
    const rootKey = getRootKey(rootPath);
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

/** Built-in skill roots. Project-scoped roots are only included when cwd is absolute. */
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

/** Resolve a user-supplied entry: absolute, `~/`-prefixed, or cwd-relative. */
export function resolveUserSkillRoot(entry: string, cwd: string | undefined): string | null {
  if (!entry) return null;
  if (entry.startsWith('~/') || entry === '~') return path.join(os.homedir(), entry.slice(1));
  if (path.isAbsolute(entry)) return entry;
  if (!cwd || !path.isAbsolute(cwd)) return null;
  return path.join(cwd, entry);
}
