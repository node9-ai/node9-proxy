// What the removed undo feature left behind on disk.
//
// The undo/snapshot feature was removed: the store had no size ceiling and took
// a machine to 378 GB, at a measured ~19 MB per minute of active agent work. We
// do NOT delete a user's data on upgrade — `npm install -g` runs unattended in
// CI and Docker, and the store holds copies of the user's own code. So instead
// every surface tells them what is there and lets them decide.
//
// Three artifacts, because the store was never just one directory:
//   ~/.node9/snapshots/<hash>/   the shadow git repos — the bulk
//   ~/.node9/snapshots.json      the stack index — 720 KB observed in the wild
//   ~/.node9/undo_latest.txt     a backward-compat pointer
// A cleanup command that names only the first leaves a stale index and a
// pointer to a store that no longer exists.
//
// Two rules this module exists to enforce, both of them about not lying:
//   - A subtree we cannot read is COUNTED as unreadable and never folded in as
//     zero bytes. Telling the user with 378 GB that they have "0 MB" and then
//     advising `rm -rf` would be worse than saying nothing at all.
//   - An empty leftover directory reports nothing. The condition is "there are
//     files", not "the directory exists" — otherwise every user who already
//     cleaned up gets a permanent 0 MB nag.
import fs from 'fs';
import os from 'os';
import path from 'path';

export interface UndoLeftovers {
  /** Bytes we could actually stat. Never includes a guess for an unreadable subtree. */
  bytes: number;
  files: number;
  /** Directories that could not be read. When > 0, render the size as "≥ N". */
  unreadable: number;
  /** Only the artifacts that exist, absolute. Drives the cleanup command we print. */
  paths: string[];
  /** The walk hit its time budget, so `bytes` is a floor. Render as "≥ N" too. */
  truncated: boolean;
}

/** Walking a store with hundreds of thousands of files must not hang a CLI command. */
const WALK_BUDGET_MS = 2000;

/**
 * Report what the removed undo feature left behind, or `null` when there is
 * nothing to report. `null` is the common case — a machine that never enabled
 * the feature has no artifacts, and every caller stays silent.
 *
 * Cost: measured at 325 ms for 18k files / 236 MB, against a ~220 ms `node9
 * status` baseline. Not a hot path — the Claude Code statusLine spawns
 * `node9 hud`, not `status` — so the time budget is sufficient and no cache is
 * warranted.
 */
export function findUndoLeftovers(homeDir?: string): UndoLeftovers | null {
  const home = homeDir ?? os.homedir();
  const node9Dir = path.join(home, '.node9');

  const snapshotsDir = path.join(node9Dir, 'snapshots');
  const stackFile = path.join(node9Dir, 'snapshots.json');
  const latestFile = path.join(node9Dir, 'undo_latest.txt');

  let bytes = 0;
  let files = 0;
  let unreadable = 0;
  let truncated = false;
  const paths: string[] = [];

  // ── the two flat files ────────────────────────────────────────────────────
  for (const file of [stackFile, latestFile]) {
    try {
      const stat = fs.statSync(file);
      if (stat.isFile()) {
        bytes += stat.size;
        files += 1;
        paths.push(file);
      }
    } catch {
      // Absent is the common case and not worth reporting. A file that exists
      // but cannot be stat'd is counted as unreadable rather than as nothing.
      if (fs.existsSync(file)) unreadable += 1;
    }
  }

  // ── the store ─────────────────────────────────────────────────────────────
  if (fs.existsSync(snapshotsDir)) {
    const started = Date.now();
    let sawEntry = false;
    const stack: string[] = [snapshotsDir];

    while (stack.length > 0) {
      if (Date.now() - started > WALK_BUDGET_MS) {
        truncated = true;
        break;
      }
      const dir = stack.pop() as string;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        // EACCES / EPERM — a subtree we cannot see. Counted, never zeroed.
        unreadable += 1;
        continue;
      }
      for (const entry of entries) {
        sawEntry = true;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          stack.push(full);
          continue;
        }
        try {
          bytes += fs.statSync(full).size;
          files += 1;
        } catch {
          unreadable += 1;
        }
      }
    }

    // An empty directory is not a leftover — see the header. It only counts as
    // an artifact once we know something is actually inside it.
    if (sawEntry || truncated) paths.push(snapshotsDir);
  }

  // Nothing readable AND nothing hidden behind a permission error → stay quiet.
  if (files === 0 && unreadable === 0) return null;

  return { bytes, files, unreadable, paths, truncated };
}

/** Human size. Rendered as a floor whenever we know the number is incomplete. */
export function formatLeftovers(left: UndoLeftovers): string {
  const mb = left.bytes / (1024 * 1024);
  const size = mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb.toFixed(1)} MB`;
  const floor = left.unreadable > 0 || left.truncated ? '≥ ' : '';
  const caveat =
    left.unreadable > 0
      ? ` (${left.unreadable} ${left.unreadable === 1 ? 'subtree' : 'subtrees'} unreadable)`
      : left.truncated
        ? ' (scan stopped early)'
        : '';
  return `${floor}${size}${caveat}`;
}

/** The exact command to remove everything the feature left. Names all three artifacts. */
export function cleanupCommand(left: UndoLeftovers): string {
  return `rm -rf ${left.paths.map((p) => JSON.stringify(p)).join(' ')}`;
}
