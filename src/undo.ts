// src/undo.ts
// Snapshot engine: creates lightweight git snapshots before AI file edits,
// enabling single-command undo with full diff preview.
//
// Uses an isolated shadow bare repo at ~/.node9/snapshots/<hash16>/
// so the user's .git is never touched.
import { spawnSync, spawn } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';

const SNAPSHOT_STACK_PATH = path.join(os.homedir(), '.node9', 'snapshots.json');
// Keep backward compat — still write this so existing code reading it doesn't break
const UNDO_LATEST_PATH = path.join(os.homedir(), '.node9', 'undo_latest.txt');

const MAX_SNAPSHOTS = 10;
const GIT_TIMEOUT = 15_000; // 15s cap on any single git operation

export interface SnapshotEntry {
  hash: string;
  tool: string;
  argsSummary: string;
  cwd: string;
  timestamp: number;
}

function readStack(): SnapshotEntry[] {
  try {
    if (fs.existsSync(SNAPSHOT_STACK_PATH))
      return JSON.parse(fs.readFileSync(SNAPSHOT_STACK_PATH, 'utf-8')) as SnapshotEntry[];
  } catch {}
  return [];
}

function writeStack(stack: SnapshotEntry[]): void {
  const dir = path.dirname(SNAPSHOT_STACK_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(SNAPSHOT_STACK_PATH, JSON.stringify(stack, null, 2));
}

function buildArgsSummary(tool: string, args: unknown): string {
  if (!args || typeof args !== 'object') return '';
  const a = args as Record<string, unknown>;
  const filePath = a.file_path ?? a.path ?? a.filename;
  if (typeof filePath === 'string') return filePath;
  const cmd = a.command ?? a.cmd;
  if (typeof cmd === 'string') return cmd.slice(0, 80);
  const sql = a.sql ?? a.query;
  if (typeof sql === 'string') return sql.slice(0, 80);
  return tool;
}

// ── Shadow Repo Helpers ───────────────────────────────────────────────────────

/**
 * Normalizes a path for hashing: resolves symlinks, converts to forward slashes,
 * lowercases on Windows for drive-letter consistency.
 */
function normalizeCwdForHash(cwd: string): string {
  let normalized: string;
  try {
    normalized = fs.realpathSync(cwd);
  } catch {
    normalized = cwd;
  }
  normalized = normalized.replace(/\\/g, '/');
  if (process.platform === 'win32') normalized = normalized.toLowerCase();
  return normalized;
}

/**
 * Returns the path to the isolated shadow bare repo for a given project directory.
 * Uses the first 16 hex chars of SHA-256(normalized_cwd) — 64 bits of entropy.
 */
export function getShadowRepoDir(cwd: string): string {
  const hash = crypto
    .createHash('sha256')
    .update(normalizeCwdForHash(cwd))
    .digest('hex')
    .slice(0, 16);
  return path.join(os.homedir(), '.node9', 'snapshots', hash);
}

/**
 * Deletes per-invocation index files older than 60s left behind by hard-killed processes.
 */
function cleanOrphanedIndexFiles(shadowDir: string): void {
  try {
    const cutoff = Date.now() - 60_000;
    for (const f of fs.readdirSync(shadowDir)) {
      if (f.startsWith('index_')) {
        const fp = path.join(shadowDir, f);
        try {
          if (fs.statSync(fp).mtimeMs < cutoff) fs.unlinkSync(fp);
        } catch {}
      }
    }
  } catch {
    /* non-fatal — shadow dir may not exist yet */
  }
}

/**
 * Writes gitignore-style exclusions into the shadow repo's info/exclude.
 * Always excludes .git and .node9 to prevent snapshotting internal git state
 * (inception) or node9's own data directory.
 */
function writeShadowExcludes(shadowDir: string, ignorePaths: string[]): void {
  const hardcoded = ['.git', '.node9'];
  const lines = [...hardcoded, ...ignorePaths].join('\n');
  try {
    fs.writeFileSync(path.join(shadowDir, 'info', 'exclude'), lines + '\n', 'utf8');
  } catch {}
}

/**
 * Ensures the shadow bare repo exists and is healthy.
 * - Validates with `git rev-parse --git-dir` (reliable check)
 * - Detects hash collisions and directory renames via project-path.txt
 * - Auto-recovers from corruption by deleting and reinitializing
 * - Sets performance config (untrackedCache, fsmonitor) on first init
 * Returns false if git is unavailable or init fails.
 */
function ensureShadowRepo(shadowDir: string, cwd: string): boolean {
  cleanOrphanedIndexFiles(shadowDir);

  const normalizedCwd = normalizeCwdForHash(cwd);
  const shadowEnvBase = { ...process.env, GIT_DIR: shadowDir, GIT_WORK_TREE: cwd };

  // Validate existing repo
  const check = spawnSync('git', ['rev-parse', '--git-dir'], {
    env: shadowEnvBase,
    timeout: 3_000,
  });

  if (check.status === 0) {
    const ptPath = path.join(shadowDir, 'project-path.txt');
    try {
      const stored = fs.readFileSync(ptPath, 'utf8').trim();
      if (stored === normalizedCwd) return true; // healthy
      // Mismatch — hash collision or directory renamed
      if (process.env.NODE9_DEBUG === '1')
        console.error(
          `[Node9] Shadow repo path mismatch: stored="${stored}" expected="${normalizedCwd}" — reinitializing`
        );
      fs.rmSync(shadowDir, { recursive: true, force: true });
    } catch {
      // project-path.txt missing (pre-migration shadow repo) — write it and continue
      try {
        fs.writeFileSync(ptPath, normalizedCwd, 'utf8');
      } catch {}
      return true;
    }
  }

  // Initialize new or re-initialize corrupted/mismatched shadow repo
  try {
    fs.mkdirSync(shadowDir, { recursive: true });
  } catch {}

  const init = spawnSync('git', ['init', '--bare', shadowDir], { timeout: 5_000 });
  if (init.status !== 0) {
    if (process.env.NODE9_DEBUG === '1')
      console.error('[Node9] git init --bare failed:', init.stderr?.toString());
    return false;
  }

  // Performance config
  const configFile = path.join(shadowDir, 'config');
  spawnSync('git', ['config', '--file', configFile, 'core.untrackedCache', 'true'], {
    timeout: 3_000,
  });
  spawnSync('git', ['config', '--file', configFile, 'core.fsmonitor', 'true'], {
    timeout: 3_000,
  });

  // Write project-path.txt for auditability and collision detection
  try {
    fs.writeFileSync(path.join(shadowDir, 'project-path.txt'), normalizedCwd, 'utf8');
  } catch {}

  return true;
}

/**
 * Returns the git env to use for diff/undo operations on a given cwd.
 * Prefers the shadow repo; falls back to ambient git (user's .git) for old
 * hashes created before the shadow repo migration.
 */
function buildGitEnv(cwd: string): NodeJS.ProcessEnv {
  const shadowDir = getShadowRepoDir(cwd);
  const check = spawnSync('git', ['rev-parse', '--git-dir'], {
    env: { ...process.env, GIT_DIR: shadowDir, GIT_WORK_TREE: cwd },
    timeout: 2_000,
  });
  if (check.status === 0) {
    return { ...process.env, GIT_DIR: shadowDir, GIT_WORK_TREE: cwd };
  }
  // Legacy fallback: use ambient git context (user's .git or none)
  return { ...process.env };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Creates a shadow snapshot and pushes metadata onto the stack.
 * Works in any directory — no .git required in the project.
 */
export async function createShadowSnapshot(
  tool = 'unknown',
  args: unknown = {},
  ignorePaths: string[] = []
): Promise<string | null> {
  let indexFile: string | null = null;
  try {
    const cwd = process.cwd();
    const shadowDir = getShadowRepoDir(cwd);

    if (!ensureShadowRepo(shadowDir, cwd)) return null;
    writeShadowExcludes(shadowDir, ignorePaths);

    // Per-invocation index file in shadow dir (not user's .git) for concurrent-session safety
    indexFile = path.join(shadowDir, `index_${process.pid}_${Date.now()}`);
    const shadowEnv = {
      ...process.env,
      GIT_DIR: shadowDir,
      GIT_WORK_TREE: cwd,
      GIT_INDEX_FILE: indexFile,
    };

    spawnSync('git', ['add', '-A'], { env: shadowEnv, timeout: GIT_TIMEOUT });

    const treeRes = spawnSync('git', ['write-tree'], { env: shadowEnv, timeout: GIT_TIMEOUT });
    const treeHash = treeRes.stdout?.toString().trim();
    if (!treeHash || treeRes.status !== 0) return null;

    const commitRes = spawnSync(
      'git',
      ['commit-tree', treeHash, '-m', `Node9 AI Snapshot: ${new Date().toISOString()}`],
      { env: shadowEnv, timeout: GIT_TIMEOUT }
    );
    const commitHash = commitRes.stdout?.toString().trim();
    if (!commitHash || commitRes.status !== 0) return null;

    const stack = readStack();
    stack.push({
      hash: commitHash,
      tool,
      argsSummary: buildArgsSummary(tool, args),
      cwd,
      timestamp: Date.now(),
    });
    // Check GC BEFORE splice so total-snapshots-ever is used, not capped length.
    // After splice, stack.length ≤ MAX_SNAPSHOTS (10), so % 20 would never fire.
    const shouldGc = stack.length % 5 === 0;
    if (stack.length > MAX_SNAPSHOTS) stack.splice(0, stack.length - MAX_SNAPSHOTS);
    writeStack(stack);

    // Backward compat: keep undo_latest.txt
    fs.writeFileSync(UNDO_LATEST_PATH, commitHash);

    // Periodic GC — fire-and-forget, non-blocking, keeps shadow dir tidy
    if (shouldGc) {
      spawn('git', ['gc', '--auto'], { env: shadowEnv, detached: true, stdio: 'ignore' }).unref();
    }

    return commitHash;
  } catch (err) {
    if (process.env.NODE9_DEBUG === '1') console.error('[Node9 Undo Engine Error]:', err);
    return null;
  } finally {
    // Always clean up the per-invocation index file
    if (indexFile) {
      try {
        fs.unlinkSync(indexFile);
      } catch {}
    }
  }
}

/**
 * Returns the most recent snapshot entry, or null if none.
 */
export function getLatestSnapshot(): SnapshotEntry | null {
  const stack = readStack();
  return stack.length > 0 ? stack[stack.length - 1] : null;
}

/**
 * Backward-compat shim used by existing code.
 */
export function getLatestSnapshotHash(): string | null {
  return getLatestSnapshot()?.hash ?? null;
}

/**
 * Returns the full snapshot history (newest last).
 */
export function getSnapshotHistory(): SnapshotEntry[] {
  return readStack();
}

/**
 * Computes a unified diff between the snapshot and the current working tree.
 * Uses the shadow repo if available; falls back to user's .git for old hashes.
 */
export function computeUndoDiff(hash: string, cwd: string): string | null {
  try {
    const env = buildGitEnv(cwd);
    const statRes = spawnSync('git', ['diff', hash, '--stat', '--', '.'], {
      cwd,
      env,
      timeout: GIT_TIMEOUT,
    });
    const stat = statRes.stdout?.toString().trim();
    if (!stat || statRes.status !== 0) return null;

    const diffRes = spawnSync('git', ['diff', hash, '--', '.'], {
      cwd,
      env,
      timeout: GIT_TIMEOUT,
    });
    const raw = diffRes.stdout?.toString();
    if (!raw || diffRes.status !== 0) return null;

    const lines = raw
      .split('\n')
      .filter(
        (l) => !l.startsWith('diff --git') && !l.startsWith('index ') && !l.startsWith('Binary')
      );
    return lines.join('\n') || null;
  } catch {
    return null;
  }
}

/**
 * Reverts the current directory to a specific snapshot hash.
 * Uses the shadow repo if available; falls back to user's .git for old hashes.
 */
export function applyUndo(hash: string, cwd?: string): boolean {
  try {
    const dir = cwd ?? process.cwd();
    const env = buildGitEnv(dir);

    const restore = spawnSync('git', ['restore', '--source', hash, '--staged', '--worktree', '.'], {
      cwd: dir,
      env,
      timeout: GIT_TIMEOUT,
    });
    if (restore.status !== 0) return false;

    const lsTree = spawnSync('git', ['ls-tree', '-r', '--name-only', hash], {
      cwd: dir,
      env,
      timeout: GIT_TIMEOUT,
    });
    // Guard: if ls-tree fails, snapshotFiles would be empty and every file
    // in the working tree would be deleted. Abort instead.
    if (lsTree.status !== 0) {
      // Always warn — this is an unexpected git failure, not normal flow.
      // A silent false return is impossible to diagnose in production.
      process.stderr.write(`[Node9] applyUndo: git ls-tree failed for hash ${hash}\n`);
      return false;
    }
    const snapshotFiles = new Set(
      lsTree.stdout?.toString().trim().split('\n').filter(Boolean) ?? []
    );
    // Guard: an empty snapshot set means ls-tree produced no output despite exit 0 —
    // proceeding would delete every file in the working tree. Abort instead.
    // A legitimately empty project snapshot cannot occur in normal node9 usage.
    if (snapshotFiles.size === 0) {
      process.stderr.write(`[Node9] applyUndo: ls-tree returned no files for hash ${hash}\n`);
      return false;
    }

    const tracked =
      spawnSync('git', ['ls-files'], { cwd: dir, env, timeout: GIT_TIMEOUT })
        .stdout?.toString()
        .trim()
        .split('\n')
        .filter(Boolean) ?? [];

    const untracked =
      spawnSync('git', ['ls-files', '--others', '--exclude-standard'], {
        cwd: dir,
        env,
        timeout: GIT_TIMEOUT,
      })
        .stdout?.toString()
        .trim()
        .split('\n')
        .filter(Boolean) ?? [];

    for (const file of [...tracked, ...untracked]) {
      const fullPath = path.join(dir, file);
      if (!snapshotFiles.has(file) && fs.existsSync(fullPath)) {
        fs.unlinkSync(fullPath);
      }
    }

    return true;
  } catch {
    return false;
  }
}
