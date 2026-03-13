// src/undo.ts
// Snapshot engine: creates lightweight git snapshots before AI file edits,
// enabling single-command undo with full diff preview.
import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import os from 'os';

const SNAPSHOT_STACK_PATH = path.join(os.homedir(), '.node9', 'snapshots.json');
// Keep backward compat — still write this so existing code reading it doesn't break
const UNDO_LATEST_PATH = path.join(os.homedir(), '.node9', 'undo_latest.txt');

const MAX_SNAPSHOTS = 10;

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
  // Show the most useful single arg depending on tool type
  const filePath = a.file_path ?? a.path ?? a.filename;
  if (typeof filePath === 'string') return filePath;
  const cmd = a.command ?? a.cmd;
  if (typeof cmd === 'string') return cmd.slice(0, 80);
  const sql = a.sql ?? a.query;
  if (typeof sql === 'string') return sql.slice(0, 80);
  return tool;
}

/**
 * Creates a shadow snapshot and pushes metadata onto the stack.
 */
export async function createShadowSnapshot(
  tool = 'unknown',
  args: unknown = {}
): Promise<string | null> {
  try {
    const cwd = process.cwd();
    if (!fs.existsSync(path.join(cwd, '.git'))) return null;

    const tempIndex = path.join(cwd, '.git', `node9_index_${Date.now()}`);
    const env = { ...process.env, GIT_INDEX_FILE: tempIndex };

    spawnSync('git', ['add', '-A'], { env });
    const treeRes = spawnSync('git', ['write-tree'], { env });
    const treeHash = treeRes.stdout.toString().trim();

    if (fs.existsSync(tempIndex)) fs.unlinkSync(tempIndex);
    if (!treeHash || treeRes.status !== 0) return null;

    const commitRes = spawnSync('git', [
      'commit-tree',
      treeHash,
      '-m',
      `Node9 AI Snapshot: ${new Date().toISOString()}`,
    ]);
    const commitHash = commitRes.stdout.toString().trim();

    if (!commitHash || commitRes.status !== 0) return null;

    // Push to stack
    const stack = readStack();
    const entry: SnapshotEntry = {
      hash: commitHash,
      tool,
      argsSummary: buildArgsSummary(tool, args),
      cwd,
      timestamp: Date.now(),
    };
    stack.push(entry);
    if (stack.length > MAX_SNAPSHOTS) stack.splice(0, stack.length - MAX_SNAPSHOTS);
    writeStack(stack);

    // Backward compat: keep undo_latest.txt
    fs.writeFileSync(UNDO_LATEST_PATH, commitHash);

    return commitHash;
  } catch (err) {
    if (process.env.NODE9_DEBUG === '1') console.error('[Node9 Undo Engine Error]:', err);
  }
  return null;
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
 * Returns the diff string, or null if the repo is clean / no diff available.
 */
export function computeUndoDiff(hash: string, cwd: string): string | null {
  try {
    const result = spawnSync('git', ['diff', hash, '--stat', '--', '.'], { cwd });
    const stat = result.stdout.toString().trim();
    if (!stat) return null;

    const diff = spawnSync('git', ['diff', hash, '--', '.'], { cwd });
    const raw = diff.stdout.toString();
    if (!raw) return null;
    // Strip git header lines, keep only file names + hunks
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
 * Reverts the current directory to a specific Git commit hash.
 */
export function applyUndo(hash: string, cwd?: string): boolean {
  try {
    const dir = cwd ?? process.cwd();

    const restore = spawnSync('git', ['restore', '--source', hash, '--staged', '--worktree', '.'], {
      cwd: dir,
    });
    if (restore.status !== 0) return false;

    const lsTree = spawnSync('git', ['ls-tree', '-r', '--name-only', hash], { cwd: dir });
    const snapshotFiles = new Set(lsTree.stdout.toString().trim().split('\n').filter(Boolean));

    const tracked = spawnSync('git', ['ls-files'], { cwd: dir })
      .stdout.toString()
      .trim()
      .split('\n')
      .filter(Boolean);
    const untracked = spawnSync('git', ['ls-files', '--others', '--exclude-standard'], { cwd: dir })
      .stdout.toString()
      .trim()
      .split('\n')
      .filter(Boolean);

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
