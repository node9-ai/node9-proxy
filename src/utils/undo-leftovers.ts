// What the removed undo feature left on disk, and how to remove it.
//
// The undo/snapshot feature was removed: the store had no size ceiling and took
// a machine to 378 GB at a measured ~19 MB per minute of agent work. Upgrading
// does not delete anything — `npm install -g` runs unattended in CI and Docker,
// and the store holds copies of the user's own code. Instead the user is told
// there are leftovers and given `node9 undo --purge`.
//
// Three artifacts, because the store was never one directory:
//   ~/.node9/snapshots/<hash>/   the shadow git repos — the bulk
//   ~/.node9/snapshots.json      the stack index — 720 KB observed in the wild
//   ~/.node9/undo_latest.txt     a backward-compat pointer
// A cleanup that names only the first leaves a stale index and a pointer to a
// store that no longer exists.
//
// ⭐ This module answers "what is still there", NOT "how big is it". An earlier
// version walked the tree to print a size and a pasteable `rm -rf` line. It
// summed apparent size rather than allocated blocks and under-reported a git
// object store by ~69x, quoted shell paths with JSON.stringify so a `$` in a
// home directory retargeted the command, and emitted a command Windows does not
// have. None of that is needed once node9 does the deleting: the user needs a
// command, not a number to weigh.
import fs from 'fs';
import os from 'os';
import path from 'path';

function candidates(homeDir: string): string[] {
  const node9Dir = path.join(homeDir, '.node9');
  return [
    path.join(node9Dir, 'snapshots'),
    path.join(node9Dir, 'snapshots.json'),
    path.join(node9Dir, 'undo_latest.txt'),
  ];
}

/**
 * Absolute paths of undo artifacts still on disk, store first. Empty means
 * there is nothing left and every surface stays silent — the common case.
 *
 * Uses `lstat`, not `existsSync`: `existsSync` returns false on a permission
 * error as well as on absence, so an unreadable ~/.node9 would read as "nothing
 * left" on exactly the machine that has the most to remove. Anything other than
 * ENOENT means the artifact is there and we simply cannot see into it; it is
 * reported, and `purgeUndoLeftovers` surfaces the real error.
 *
 * An artifact is not required to be non-empty. An empty `snapshots/` directory
 * is still ours to clean up, and `--purge` removes it in one step.
 */
export function undoLeftoverPaths(homeDir: string = os.homedir()): string[] {
  const found: string[] = [];
  for (const p of candidates(homeDir)) {
    try {
      fs.lstatSync(p);
      found.push(p);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') found.push(p);
    }
  }
  return found;
}

export interface PurgeOutcome {
  deleted: string[];
  /** Deliberately not removed, with the reason shown to the user. */
  skipped: { path: string; reason: string }[];
  /** Removal was attempted and the path is still there. */
  failed: { path: string; reason: string }[];
}

/**
 * Delete the artifacts listed by `undoLeftoverPaths`, and nothing else.
 *
 * Guards, in the order they matter:
 *   - Every path is rebuilt here from `homeDir`. No flag, env var, config value
 *     or cloud payload chooses what gets deleted; there is no input to abuse.
 *   - A symlinked artifact is SKIPPED. Following one would turn a cleanup into
 *     a delete of whatever it points at.
 *   - ~/.node9 itself is never removed — the config, audit log and credentials
 *     live there. `node9 uninstall --purge` owns that decision.
 *   - Every removal is verified afterwards. `force: true` suppresses errors,
 *     so without the second look a permission failure prints as success. The
 *     uninstall path does the same, for the same reason (cli.ts).
 */
export function purgeUndoLeftovers(homeDir: string = os.homedir()): PurgeOutcome {
  const out: PurgeOutcome = { deleted: [], skipped: [], failed: [] };

  for (const p of undoLeftoverPaths(homeDir)) {
    try {
      if (fs.lstatSync(p).isSymbolicLink()) {
        out.skipped.push({
          path: p,
          reason: 'is a symlink — remove it yourself so nothing else is followed',
        });
        continue;
      }
    } catch (err) {
      out.failed.push({ path: p, reason: (err as Error).message });
      continue;
    }

    // ⭐ ONE decision point: whether the path is still there afterwards. A throw
    // is only a reason string, never the verdict. Two arbiters — "rmSync threw"
    // and "the file is gone" — can disagree, and then the order of the checks
    // decides the answer instead of the filesystem. Concretely: `force: true`
    // suppresses errors, so a removal that silently did nothing would report
    // success; and a throw AFTER the unlink succeeded would report a failure
    // for a file that is gone.
    let reason: string | null = null;
    try {
      fs.rmSync(p, { recursive: true, force: true });
    } catch (err) {
      reason = (err as Error).message;
    }

    if (fs.existsSync(p)) {
      out.failed.push({ path: p, reason: reason ?? 'still present after removal' });
    } else {
      out.deleted.push(p);
    }
  }

  return out;
}
