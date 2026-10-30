// packages/policy-engine/src/files/git-hooks.ts
// A hook file disarmed through a file operation (node9Firewall#413, part 2,
// `commands.git-hooks-bypass`). The shell half of the check (`--no-verify`,
// `core.hooksPath`, `HUSKY=0`, `chmod -x`) lives in shell/git.ts; this half
// reads the file accesses the collectors already produce, from a file tool
// or from the shell, so a hook removed, moved away, truncated or overwritten
// with nothing is seen whichever way it is written.
//
// A hook written with real content is work, not a bypass: only text that
// runs nothing (empty, comments, a shebang, `exit 0`, `true`, `:`) counts for
// a file tool, and an Edit that puts `exit` or `true` on a line of its own.
// A shell write whose content cannot be seen counts; an append does not.

import { checkValue, type CatalogSettings } from '../catalog';
import type { PolicyVerdict } from '../policy';
import { isHookPath } from '../shell/git';
import type { FileAccess, FileAccessContext } from './paths';
import { normalizeFilePath } from './paths';
import { writtenTexts } from './written-texts';

const CHECK_ID = 'commands.git-hooks-bypass';
const RULE_NAME = 'review-git-hooks-bypass';

export type GitHooksFileVerdict = PolicyVerdict & {
  path: string;
  operation: FileAccess['operation'];
};

/** A line that runs nothing in a hook. */
const INERT_LINE_RE = /^\s*(#.*|exit(\s+0)?|true|:|set\s+-[a-z]+)?\s*$/;

/** Text that, as a whole hook, runs nothing. */
export function hookTextRunsNothing(text: string): boolean {
  return text.split(/\r?\n/).every((line) => INERT_LINE_RE.test(line));
}

/** An edit whose new text disarms the hook: empty, or `exit` / `true` alone on a line. */
function editDisarms(newText: string): boolean {
  if (newText.trim() === '') return true;
  return newText.split(/\r?\n/).some((line) => /^\s*(exit(\s+0)?|true)\s*(;|$)/.test(line));
}

function hookAccess(access: FileAccess, context: FileAccessContext): boolean {
  const home = context.homeDirs?.[0] ?? '~';
  const candidates = access.candidates ?? [
    normalizeFilePath(access.path, access.cwd ?? context.cwd, home),
  ];
  return candidates.some((p) => isHookPath(p)) || isHookPath(access.path);
}

/**
 * The strictest hook-file finding among the accesses, or null. `shell` says
 * whether the accesses came from a shell command (content unseen) or from a
 * file tool (content in `args`).
 */
export function evaluateGitHooksFileAccess(
  args: unknown,
  accesses: FileAccess[],
  context: FileAccessContext,
  settings: CatalogSettings,
  shell: boolean
): GitHooksFileVerdict | null {
  const value = checkValue(settings, CHECK_ID);
  if (value === 'off') return null;
  const texts = shell ? null : writtenTexts(args);
  for (const access of accesses) {
    if (access.operation === 'read' || access.operation === 'create') continue;
    if (access.append) continue;
    if (!hookAccess(access, context)) continue;
    let disarms: boolean;
    let how: string;
    if (access.operation === 'remove') {
      disarms = true;
      how = 'removed';
    } else if (texts === null) {
      disarms = true;
      how = 'overwritten';
    } else if (texts.whole.length > 0) {
      disarms = texts.whole.some(hookTextRunsNothing);
      how = 'emptied';
    } else if (texts.edits.length > 0) {
      disarms = texts.edits.some(editDisarms);
      how = 'edited to exit';
    } else {
      disarms = true;
      how = 'overwritten';
    }
    if (!disarms) continue;
    const reason = `Git hook ${how}: ${access.path}`;
    return {
      decision: value === 'log' ? 'allow' : value,
      ...(value === 'log' ? { logged: true } : {}),
      checkId: CHECK_ID,
      ruleName: RULE_NAME,
      path: access.path,
      operation: access.operation,
      reason,
      ruleDescription:
        'The AI disarms a git hook (a file under .git/hooks or .husky). Hooks are the checks you set up on the agent’s own work; confirm this is intentional.',
      blockedByLabel: `Node9 Files: ${reason}`,
      tier: 2,
      ...(value === 'block' ? { overridable: false } : {}),
    };
  }
  return null;
}
