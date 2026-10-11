// src/ci-check/route.ts
// ONE answer to "which check reads this path". A file's meaning comes from the path the agent
// opens it by: `.claude/settings.json` is agent settings wherever its bytes live. scanTree
// dispatches on this, and the readers use it to drop a duplicate only when the SAME bytes would
// go to the SAME check (K.3) — never merely because the bytes were already read under another
// name.

import { isAppDoc, isHookScript, isInstructionFile, isSkillScript } from './instructions';
import { SUPPRESSIONS_FILE } from './suppress';

/** T.3: every committed MCP server config the scanner reads (Claude, Cursor, VS Code, Kiro,
 *  Gemini CLI, opencode), at any depth. */
export const MCP_CONFIG_RE =
  /\.mcp\.json$|\.cursor\/mcp\.json$|(^|\/)\.vscode\/mcp\.json$|(^|\/)\.kiro\/settings\/mcp\.json$|(^|\/)\.gemini\/settings\.json$|(^|\/)opencode\.json$|(^|\/)\.opencode\/config\.json$/;

/** A root issue form or issue template (GitHub reads only the root `.github/ISSUE_TEMPLATE`). */
export const ISSUE_FORM_RE = /^\.github\/ISSUE_TEMPLATE\/[^/]+\.(ya?ml|md)$/i;

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
  | 'app-doc'
  /** T.6.9: a root issue form; read only for the labels it applies, never graded. */
  | 'issue-form'
  /** T.3: the root package manifest; read only for the package name it publishes. */
  | 'manifest';

/** The check a path is routed to, in scanTree's order; null when no check reads it. */
export function routeOf(
  path: string,
  skillDirs: ReadonlySet<string>,
  appDirs: ReadonlySet<string> = new Set()
): Route | null {
  if (path === SUPPRESSIONS_FILE) return 'suppressions';
  if (/\.github\/workflows\/.+\.ya?ml$/.test(path)) return 'workflow';
  if (ISSUE_FORM_RE.test(path)) return 'issue-form';
  if (path === 'package.json' || path === 'pyproject.toml') return 'manifest';
  if (/\.claude\/settings(\.local)?\.json$/.test(path)) return 'agent-config';
  if (isHookScript(path)) return 'hook-script';
  if (isSkillScript(path, skillDirs)) return 'skill-script';
  if (MCP_CONFIG_RE.test(path)) return 'mcp';
  if (/(^|\/)\.codex\/config\.toml$/.test(path)) return 'codex';
  if (isInstructionFile(path, skillDirs, appDirs)) return 'instruction';
  if (isAppDoc(path, skillDirs, appDirs)) return 'app-doc';
  return null;
}
