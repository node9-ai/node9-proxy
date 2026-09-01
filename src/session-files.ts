// Finding session transcripts, and counting each usage row once.
//
// Every cost and scan path used to do a flat `fs.readdirSync(projectDir)`,
// which sees only the top level. Claude Code has not stored everything there
// for a while: sub-agent transcripts live in `<session>/subagents/*.jsonl` and
// workflow runs in `<session>/wf_*/*.jsonl`. Measured on the founder's machine,
// 30-day window:
//
//   depth 1      28 files   $14,001   <- all that was ever scanned
//   subagents/  309 files    $1,418
//   wf_*/       206 files      $507
//
// 13.8% of real spend, invisible to every report. ccusage has never had this
// problem because it globs `**/*.jsonl`; we walked one level and stopped.
import * as fs from 'fs';
import * as path from 'path';

/**
 * Every `.jsonl` transcript under a project directory, at any depth.
 *
 * NOTE the missing `!f.startsWith('agent-')` filter that three of the callers
 * used to have. It was written for a layout where agent transcripts sat beside
 * session files at depth 1; measured today there are ZERO such files at depth 1
 * and 458 nested. Kept, it would exclude precisely the files this function
 * exists to find. Double counting is prevented by `usageKey` below — by
 * identity, not by filename.
 *
 * `maxDepth` is a loop guard, not a policy: real nesting is 2 levels.
 */
export function listSessionFiles(dir: string, maxDepth = 6): string[] {
  const out: string[] = [];
  const walk = (d: string, rel: string, depth: number): void => {
    if (depth > maxDepth) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return; // unreadable directory is not a reason to lose the rest
    }
    for (const e of entries) {
      const childRel = rel ? path.join(rel, e.name) : e.name;
      if (e.isDirectory()) walk(path.join(d, e.name), childRel, depth + 1);
      else if (e.name.endsWith('.jsonl')) out.push(childRel);
    }
  };
  walk(dir, '', 0);
  return out;
}

/**
 * The session id a transcript belongs to: its filename, without directories.
 *
 * Callers used to derive this as `file.replace(/\.jsonl$/, '')` when `file`
 * was always a bare name. Now that paths can be nested, that expression would
 * produce `subagents/agent-x` — a session id with a separator in it, shipped to
 * the cloud and used to group loops.
 */
export function sessionIdOf(relPath: string): string {
  return path.basename(relPath).replace(/\.jsonl$/, '');
}

/**
 * Identity of a usage row, for de-duplication.
 *
 * `${message.id}:${requestId}` — the pair ccusage settled on. Measured across
 * 52,870 rows on this machine: zero collisions between depth-1, `subagents/`
 * and `wf_*`, so recursion adds spend rather than repeating it. The key is the
 * guard that keeps that true if the layout changes again.
 *
 * Returns null when either half is missing (32 of 52,870 rows). Callers should
 * COUNT those rather than drop them: losing real spend is worse than a
 * theoretical double count at 0.06%, and it is the choice codeburn makes.
 * ccusage skips them instead — a defensible opposite, but this product's
 * failure mode all week has been under-reporting, not over-reporting.
 */
export function usageKey(row: { message?: { id?: unknown }; requestId?: unknown }): string | null {
  const id = row.message?.id;
  const req = row.requestId;
  if (typeof id !== 'string' || !id) return null;
  if (typeof req !== 'string' || !req) return null;
  return `${id}:${req}`;
}
