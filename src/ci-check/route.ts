// src/ci-check/route.ts
// ONE answer to "which check reads this path". A file's meaning comes from the path the agent
// opens it by: `.claude/settings.json` is agent settings wherever its bytes live. scanTree
// dispatches on this, and the readers use it to drop a duplicate only when the SAME bytes would
// go to the SAME check (K.3) — never merely because the bytes were already read under another
// name.

import { isAppDoc, isHookScript, isInstructionFile, isSkillScript } from './instructions';
import { SUPPRESSIONS_FILE } from './suppress';

export type Route =
  | 'suppressions'
  | 'workflow'
  | 'agent-config'
  | 'hook-script'
  | 'skill-script'
  | 'mcp'
  | 'codex'
  | 'instruction'
  /** An application's own doc under an app-root skill: graded only if the SKILL.md names it. */
  | 'app-doc';

/** The check a path is routed to, in scanTree's order; null when no check reads it. */
export function routeOf(
  path: string,
  skillDirs: ReadonlySet<string>,
  appDirs: ReadonlySet<string> = new Set()
): Route | null {
  if (path === SUPPRESSIONS_FILE) return 'suppressions';
  if (/\.github\/workflows\/.+\.ya?ml$/.test(path)) return 'workflow';
  if (/\.claude\/settings(\.local)?\.json$/.test(path)) return 'agent-config';
  if (isHookScript(path)) return 'hook-script';
  if (isSkillScript(path, skillDirs)) return 'skill-script';
  if (/\.mcp\.json$|\.cursor\/mcp\.json$/.test(path)) return 'mcp';
  if (/(^|\/)\.codex\/config\.toml$/.test(path)) return 'codex';
  if (isInstructionFile(path, skillDirs, appDirs)) return 'instruction';
  if (isAppDoc(path, skillDirs, appDirs)) return 'app-doc';
  return null;
}
