import type { ToolInspection } from '@node9/policy-engine';
// Host metadata preparation for the shared file policy. Never opens file contents.
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  collectFileAccesses,
  normalizeFilePath,
  SYSTEM_AUTH_FILES,
  SYSTEM_AUTH_DIRS,
  STARTUP_NAMES,
  type FileAccessContext,
  type FileAccess,
} from '@node9/policy-engine';

export interface PreparedFileAccess extends FileAccessContext {
  accesses: FileAccess[];
  /** Paths whose legacy system-file DLP match is now owned by the new policy. */
  handledPaths: Set<string>;
}

function absoluteSpelling(p: string, cwd: string, home: string): string {
  if (p === '~' || p.startsWith('~/')) p = home + p.slice(1);
  return path.isAbsolute(p) ? p : `${cwd}/${p}`;
}

/** Resolve existing parents without collapsing symlink/.. before native lookup. */
function physical(p: string, followFinal: boolean, links = 0): { path: string; missing: boolean } {
  if (links > 40) throw new Error('Too many symbolic links');
  if (!followFinal) {
    const parent = physical(path.dirname(p), true, links);
    return { path: `${parent.path}/${path.basename(p)}`, missing: parent.missing };
  }
  try {
    return { path: fs.realpathSync.native(p), missing: false };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (!['ENOENT', 'ENOTDIR'].includes(code ?? '')) throw error;
    // realpath cannot resolve a dangling link, but a write can create its target.
    try {
      if (fs.lstatSync(p).isSymbolicLink()) {
        const target = fs.readlinkSync(p);
        return physical(
          path.isAbsolute(target) ? target : `${path.dirname(p)}/${target}`,
          true,
          links + 1
        );
      }
    } catch (linkError) {
      if (!['ENOENT', 'ENOTDIR'].includes((linkError as NodeJS.ErrnoException).code ?? ''))
        throw linkError;
    }
    const parent = path.dirname(p);
    if (parent === p) return { path: p, missing: true };
    const resolved = physical(parent, true, links);
    return { path: `${resolved.path}/${path.basename(p)}`, missing: true };
  }
}

export function prepareFileAccesses(
  tool: string,
  args: unknown,
  cwd = process.cwd(),
  inspection: ToolInspection = {},
  home = os.homedir()
): PreparedFileAccess {
  const context = { cwd, homeDirs: [home, '/root'] };
  const accesses = collectFileAccesses(tool, args, context, inspection);
  const handledPaths = new Set<string>();
  if (!accesses.length || process.platform === 'win32')
    return { ...context, accesses: [], handledPaths };
  // Resolve the protected names too: /etc can itself be a symlink (macOS),
  // and a configured startup file can point at a dotfiles checkout.
  const aliases: Array<[string, string, boolean]> = [];
  const roots = [
    ...SYSTEM_AUTH_FILES.map((p) => [p, false] as const),
    ...SYSTEM_AUTH_DIRS.map((p) => [p, true] as const),
    ...context.homeDirs.flatMap((h) => STARTUP_NAMES.map((n) => [`${h}/${n}`, false] as const)),
  ];
  for (const [root, directory] of roots) {
    try {
      aliases.push([normalizeFilePath(physical(root, true).path), root, directory]);
    } catch {
      /* The lexical protected name still applies if host lookup fails. */
    }
  }
  const prepared: FileAccess[] = [];
  for (const access of accesses) {
    const raw = absoluteSpelling(access.path, access.cwd ?? cwd, home);
    if (access.directoryTarget) {
      try {
        if (
          !fs
            .statSync(absoluteSpelling(access.directoryTarget, access.cwd ?? cwd, home))
            .isDirectory()
        )
          continue;
      } catch {
        /* Retain both destination interpretations if type is unknown. */
      }
    }
    if (access.operation === 'create') {
      try {
        fs.statSync(raw);
        continue;
      } catch {
        /* Missing target: touch can create it. */
      }
    }
    const candidates = new Set([normalizeFilePath(raw)]);
    let resolution: FileAccess['resolution'] = 'lexical';
    try {
      if (access.glob) {
        // Resolve the literal prefix of a pattern without enumerating files.
        const pattern = absoluteSpelling(access.glob, access.cwd ?? cwd, home);
        const magic = pattern.search(/[*?[{]/);
        const slash = pattern.lastIndexOf('/', magic);
        if (slash > 0) {
          const prefix = physical(pattern.slice(0, slash), true).path;
          prepared.push({ ...access, glob: prefix + pattern.slice(slash), candidates: [] });
          for (const [physicalRoot, logical, directory] of aliases) {
            if (directory && (prefix === physicalRoot || prefix.startsWith(physicalRoot + '/'))) {
              prepared.push({
                ...access,
                glob: logical + prefix.slice(physicalRoot.length) + pattern.slice(slash),
                candidates: [],
              });
            }
          }
        }
      }
      if (!access.glob) {
        const real = physical(raw, access.followFinal);
        const normalized = normalizeFilePath(real.path);
        candidates.add(normalized);
        for (const [physicalRoot, logical, directory] of aliases) {
          if (access.recursive && physicalRoot.startsWith(normalized.replace(/\/$/, '') + '/')) {
            candidates.add(logical);
          }
          if (
            normalized === physicalRoot ||
            (directory && normalized.startsWith(physicalRoot + '/'))
          )
            candidates.add(logical + normalized.slice(physicalRoot.length));
        }
        resolution = real.missing ? 'missing' : 'resolved';
        handledPaths.add(access.path);
      }
    } catch {
      resolution = 'failed';
    }
    prepared.push({ ...access, candidates: [...candidates], resolution });
  }
  return { ...context, accesses: prepared, handledPaths };
}
