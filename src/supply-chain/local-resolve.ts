// src/supply-chain/local-resolve.ts
// Which copy of a package `npx <pkg>` would run: the one in node_modules when
// there is one (npx, bunx and `npm exec` prefer it and download only
// otherwise). The walk mirrors Node's own resolution: node_modules/<name>
// from the working directory up to the filesystem root.
//
// `cwd` is the hook's validated absolute working directory. A relative or
// missing cwd resolves nothing; the walk never follows a relative path.
import fs from 'fs';
import path from 'path';

export interface InstalledPackage {
  version: string;
  /** The package directory the copy lives in. */
  dir: string;
}

const MAX_LEVELS = 32;

/** Managers that run a local copy when one exists. pnpm dlx, yarn dlx, uvx and
 *  pipx always fetch, so they are not here. */
export const LOCAL_FIRST_MANAGERS: ReadonlySet<string> = new Set(['npx', 'bunx', 'npm exec']);

export function resolveInstalled(name: string, cwd: string | undefined): InstalledPackage | null {
  if (!cwd || !path.isAbsolute(cwd)) return null;
  // A registry name never carries a path separator beyond the scope slash.
  if (!/^(?:@[^/\\]+\/)?[^/\\]+$/.test(name)) return null;
  let dir = path.resolve(cwd);
  for (let i = 0; i < MAX_LEVELS; i++) {
    const pkgDir = path.join(dir, 'node_modules', ...name.split('/'));
    const manifest = path.join(pkgDir, 'package.json');
    try {
      const raw = fs.readFileSync(manifest, 'utf8');
      const parsed = JSON.parse(raw) as { version?: unknown };
      if (typeof parsed.version === 'string' && parsed.version.length > 0) {
        return { version: parsed.version, dir: pkgDir };
      }
      return null; // present but unreadable: treat as not installed
    } catch {
      // not here; climb
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}
