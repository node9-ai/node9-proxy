#!/usr/bin/env node
// The `node9` binary (fw#425). Dependency-free on purpose: it runs on every
// tool call an agent makes, before anything else is loaded.
//
// 1. Turns on Node's compile cache, so the next call reuses the bytecode of the
//    big bundles instead of compiling ~3.5 MB of JavaScript again. It must be
//    enabled before those files are compiled, which is why it lives here and
//    not inside them. One directory per node9 version under
//    ~/.node9/compile-cache; older versions are removed.
// 2. Hands the two hook commands (`check`, `log`, run on every tool call) to a
//    bundle that holds only them, and everything else to the full CLI.
//
// Nothing here may break a hook call: every step that can fail is optional.

import fs from 'fs';
import os from 'os';
import path from 'path';
import nodeModule from 'module';

/** The commands a hook runs; they load `hook.js`, not the full CLI. */
export const HOOK_COMMANDS: ReadonlySet<string> = new Set(['check', 'log']);

/** Which bundle serves a command line (`argv[2]` is the subcommand). */
export function bundleFor(subcommand: string | undefined): 'hook.js' | 'cli-main.js' {
  return subcommand !== undefined && HOOK_COMMANDS.has(subcommand) ? 'hook.js' : 'cli-main.js';
}

/** Enable the compile cache under `<home>/.node9/compile-cache/<version>` and
 *  remove other versions' directories. Returns the directory, or null when the
 *  cache is not used (an old Node, the user set NODE_COMPILE_CACHE, a failure). */
export function enableCompileCache(home: string, version: string): string | null {
  try {
    const api = nodeModule as unknown as {
      enableCompileCache?: (dir: string) => { status?: number } | undefined;
      constants?: { compileCacheStatus?: { FAILED?: number; DISABLED?: number } };
    };
    const enable = api.enableCompileCache;
    if (typeof enable !== 'function') return null;
    // A cache the user or the environment chose wins.
    if (process.env.NODE_COMPILE_CACHE) return null;
    if (!/^[\w.+-]+$/.test(version)) return null;
    const root = path.join(home, '.node9', 'compile-cache');
    const dir = path.join(root, version);
    // Node reports a failure in the returned status, not by throwing.
    const result = enable(dir);
    const status = api.constants?.compileCacheStatus;
    if (
      status &&
      result &&
      (result.status === status.FAILED || result.status === status.DISABLED)
    ) {
      return null;
    }
    try {
      for (const name of fs.readdirSync(root)) {
        if (name !== version) fs.rmSync(path.join(root, name), { recursive: true, force: true });
      }
    } catch {
      /* the cache still works; an old version lingers until the next call */
    }
    return dir;
  } catch {
    return null;
  }
}

function readVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf-8')) as {
      version?: string;
    };
    return pkg.version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

// Run only as the entry point: the spec imports the helpers above.
if (require.main === module) {
  enableCompileCache(os.homedir(), readVersion());
  // A runtime path, so the bundler leaves the target out of this file.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  require(path.join(__dirname, bundleFor(process.argv[2])));
}
