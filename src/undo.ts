// src/undo.ts
import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';

const UNDO_LATEST_PATH = path.join(os.homedir(), '.node9', 'undo_latest.txt');

/**
 * Creates a "Shadow Snapshot" of the current repository state.
 * Uses a temporary Git index to ensure we don't interfere with the
 * user's own staged changes.
 */
export async function createShadowSnapshot(): Promise<string | null> {
  try {
    const cwd = process.cwd();
    if (!fs.existsSync(path.join(cwd, '.git'))) return null;

    // Use a unique temp index file so we don't touch the user's staging area
    const tempIndex = path.join(cwd, '.git', `node9_index_${Date.now()}`);
    const env = { ...process.env, GIT_INDEX_FILE: tempIndex };

    // 1. Stage all changes into the TEMP index
    spawnSync('git', ['add', '-A'], { env });

    // 2. Create a tree object from the TEMP index
    const treeRes = spawnSync('git', ['write-tree'], { env });
    const treeHash = treeRes.stdout.toString().trim();

    // Clean up the temp index file immediately
    if (fs.existsSync(tempIndex)) fs.unlinkSync(tempIndex);

    if (!treeHash || treeRes.status !== 0) return null;

    // 3. Create a dangling commit (not attached to any branch)
    const commitRes = spawnSync('git', [
      'commit-tree',
      treeHash,
      '-m',
      `Node9 AI Snapshot: ${new Date().toISOString()}`,
    ]);
    const commitHash = commitRes.stdout.toString().trim();

    if (commitHash && commitRes.status === 0) {
      const dir = path.dirname(UNDO_LATEST_PATH);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(UNDO_LATEST_PATH, commitHash);
      return commitHash;
    }
  } catch (err) {
    if (process.env.NODE9_DEBUG === '1') {
      console.error('[Node9 Undo Engine Error]:', err);
    }
  }
  return null;
}

/**
 * Reverts the current directory to a specific Git commit hash.
 * Also removes files that were created after the snapshot (git restore
 * alone does not delete files that aren't in the source tree).
 */
export function applyUndo(hash: string): boolean {
  try {
    // 1. Restore all tracked files to snapshot state
    const restore = spawnSync('git', ['restore', '--source', hash, '--staged', '--worktree', '.']);
    if (restore.status !== 0) return false;

    // 2. Find files in the snapshot tree
    const lsTree = spawnSync('git', ['ls-tree', '-r', '--name-only', hash]);
    const snapshotFiles = new Set(lsTree.stdout.toString().trim().split('\n').filter(Boolean));

    // 3. Delete files that weren't in the snapshot.
    //    Must cover both tracked files (git ls-files) AND untracked non-ignored
    //    files (git ls-files --others --exclude-standard), since `git add -A`
    //    captures both and `git restore` doesn't remove either category.
    const tracked = spawnSync('git', ['ls-files'])
      .stdout.toString()
      .trim()
      .split('\n')
      .filter(Boolean);
    const untracked = spawnSync('git', ['ls-files', '--others', '--exclude-standard'])
      .stdout.toString()
      .trim()
      .split('\n')
      .filter(Boolean);
    for (const file of [...tracked, ...untracked]) {
      if (!snapshotFiles.has(file) && fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    }

    return true;
  } catch {
    return false;
  }
}

export function getLatestSnapshotHash(): string | null {
  if (!fs.existsSync(UNDO_LATEST_PATH)) return null;
  return fs.readFileSync(UNDO_LATEST_PATH, 'utf-8').trim();
}
