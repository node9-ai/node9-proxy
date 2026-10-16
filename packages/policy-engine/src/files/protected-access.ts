import type { ToolInspection } from '../shell/tool-input';
import picomatch from 'picomatch';
import { checkValue, type CatalogSettings } from '../catalog';
import { resolveShellInput } from '../shell/tool-input';
import { collectShellFileAccesses } from '../shell/file-access';
import type { PolicyVerdict } from '../policy';
import {
  normalizeFilePath,
  PASSWORD_HASH_FILES,
  STARTUP_NAMES,
  SYSTEM_AUTH_DIRS,
  SYSTEM_AUTH_FILES,
  type FileAccess,
  type FileAccessContext,
} from './paths';

export type ProtectedFileVerdict = PolicyVerdict & {
  path: string;
  operation: FileAccess['operation'];
};

/**
 * The file policy could not finish inspecting a call (a pattern the matcher
 * cannot compile, or an exception while preparing accesses). That is never a
 * clean result: the call needs an explicit approval, like an uninspectable
 * shell command.
 */
export function incompleteFileVerdict(
  operation: FileAccess['operation'] = 'write'
): ProtectedFileVerdict {
  return {
    decision: 'review',
    ruleName: 'file-inspection-incomplete',
    blockedByLabel: 'File inspection incomplete',
    reason: 'The file operation target could not be inspected. Approve this call explicitly.',
    ruleDescription: 'The file operation target could not be inspected.',
    path: '[uninspected]',
    operation,
    tier: 2,
  };
}

/** Closed adapters: an arbitrary tool's path-shaped argument is not an operation. */
export function fileToolOperation(tool: string, args: unknown): FileAccess['operation'] | null {
  const name = tool.toLowerCase();
  if (['read', 'read_file', 'grep', 'grep_search'].includes(name)) return 'read';
  if (name === 'str_replace_based_edit_tool') {
    const action = (args as Record<string, unknown> | null)?.command;
    if (action === 'view') return 'read';
    return ['create', 'str_replace', 'insert', 'undo_edit'].includes(String(action))
      ? 'write'
      : null;
  }
  return [
    'write',
    'write_file',
    'create_file',
    'edit',
    'edit_file',
    'multiedit',
    'replace',
  ].includes(name)
    ? 'write'
    : null;
}

export function collectFileAccesses(
  tool: string,
  args: unknown,
  context: FileAccessContext = {},
  inspection: ToolInspection = {}
): FileAccess[] {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return [];
  const a = args as Record<string, unknown>;
  const shell = resolveShellInput(tool, args, inspection);
  if (shell.kind === 'shell') return collectShellFileAccesses(shell.command, context);
  const operation = fileToolOperation(tool, args);
  if (!operation) return [];
  const out: FileAccess[] = [];
  const visit = (entry: Record<string, unknown>): void => {
    for (const key of ['file_path', 'path', 'filename']) {
      if (typeof entry[key] === 'string' && entry[key]) {
        out.push({ operation, path: entry[key], cwd: context.cwd, followFinal: true });
      }
    }
  };
  visit(a);
  // MultiEdit providers either share a top-level path or put it on each edit.
  if (tool.toLowerCase() === 'multiedit' && Array.isArray(a.edits)) {
    for (const edit of a.edits) if (edit && typeof edit === 'object') visit(edit);
  }
  return out;
}

function within(path: string, root: string): boolean {
  return path === root || path.startsWith(root === '/' ? '/' : root + '/');
}

function hits(
  access: FileAccess,
  paths: readonly string[],
  directories: readonly string[],
  context: FileAccessContext
): boolean {
  const home = context.homeDirs?.[0] ?? '~';
  const candidates = access.candidates ?? [
    normalizeFilePath(access.path, access.cwd ?? context.cwd, home),
  ];
  for (const p of candidates) {
    if (paths.includes(p) || directories.some((d) => within(p, d))) return true;
    if (access.recursive && [...paths, ...directories].some((target) => within(target, p)))
      return true;
  }
  if (access.glob) {
    // A shell `*` never selects a dotfile; find's does. A pattern that itself
    // starts a segment with `.` still matches dotfiles either way.
    const options = { dot: access.dotGlob === true, nonegate: true };
    const pattern = normalizeFilePath(access.glob, access.cwd ?? context.cwd, home);
    // A pattern that is still relative has no working directory to anchor it
    // and cannot select an absolute protected path.
    if (!pattern.startsWith('/') && !pattern.startsWith('~')) return false;
    const match = picomatch(pattern, options);
    if ([...paths, ...directories].some((p) => match(p))) return true;
    if (
      access.recursive &&
      [...paths, ...directories].some((p) => {
        const parts = p.split('/');
        return parts.some((_, i) => i > 0 && match(parts.slice(0, i).join('/') || '/'));
      })
    )
      return true;
    // A pattern selecting a name inside a protected subtree is sufficient;
    // no directory listing or expansion on the host is necessary.
    const components = pattern.split('/');
    for (const root of directories) {
      const count = root.split('/').length;
      if (
        components.length > count &&
        picomatch(components.slice(0, count).join('/'), options)(root)
      )
        return true;
    }
  }
  return false;
}

const RANK = { allow: 0, review: 1, block: 2 } as const;

export function evaluateProtectedFileAccess(
  accesses: FileAccess[],
  context: FileAccessContext,
  settings: CatalogSettings
): ProtectedFileVerdict | null {
  const homes = [...new Set([...(context.homeDirs ?? ['~']), '/root'])];
  const startup = homes.flatMap((home) =>
    STARTUP_NAMES.map((name) => `${home.replace(/\/$/, '')}/${name}`)
  );
  let best: ProtectedFileVerdict | null = null;
  const consider = (result: ProtectedFileVerdict): void => {
    if (!best || RANK[result.decision] > RANK[best.decision]) best = result;
  };
  for (const access of accesses) {
    const mutation = access.operation !== 'read';
    let kind: [string, string, string] | null;
    try {
      kind =
        mutation && hits(access, SYSTEM_AUTH_FILES, SYSTEM_AUTH_DIRS, context)
          ? [
              'files.system-auth',
              'block-system-auth-mutation',
              'Changing system authentication files is blocked',
            ]
          : mutation && hits(access, startup, [], context)
            ? [
                'files.shell-startup',
                'review-shell-startup-mutation',
                'Changing shell startup files requires approval',
              ]
            : !mutation && hits(access, PASSWORD_HASH_FILES, [], context)
              ? [
                  'files.password-hashes',
                  'review-password-hash-read',
                  'Reading system password hashes requires approval',
                ]
              : null;
    } catch {
      // picomatch refuses patterns beyond its input limit. An operand the
      // matcher cannot evaluate is not evidence that the target is harmless.
      consider(incompleteFileVerdict(access.operation));
      continue;
    }
    if (!kind) continue;
    const [checkId, ruleName, reason] = kind;
    const value = checkValue(settings, checkId);
    if (value === 'off') continue;
    consider({
      decision: value === 'log' ? 'allow' : value,
      ...(value === 'log' ? { logged: true } : {}),
      checkId,
      ruleName,
      path: access.path,
      operation: access.operation,
      reason: `${reason}: ${access.path}`,
      ruleDescription: reason,
      blockedByLabel: `Node9 Files: ${reason}`,
      tier: 2,
      ...(value === 'block' ? { overridable: false } : {}),
    });
  }
  return best;
}
