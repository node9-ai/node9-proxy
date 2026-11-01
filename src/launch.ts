#!/usr/bin/env node
// The `node9` binary (fw#425). Dependency-free on purpose: it runs on every
// tool call an agent makes, before anything else is loaded.
//
// 1. Turns on Node's compile cache, so the next call reuses the bytecode of the
//    big bundles instead of compiling ~3.5 MB of JavaScript again. It must be
//    enabled before those files are compiled, which is why it lives here and
//    not inside them.
// 2. Hands the two hook commands (`check`, `log`, run on every tool call) to a
//    bundle that holds only them, and everything else to the full CLI.
//
// Nothing here may break a hook call: every step that can fail is optional.
//
// The cache holds compiled code that every node9 process loads, so it is used
// only where it cannot lower the bar below the code it caches: never as root,
// only when the node9 install is writable by this user anyway (planting
// bytecode then gives nothing that editing dist/ would not), and only in a
// real directory owned by this user that nobody else can write. It lives in
// the user's cache directory, not in ~/.node9, whose files node9 guards.

import fs from 'fs';
import os from 'os';
import path from 'path';
import nodeModule from 'module';

/** The commands a hook runs; they load `hook.js`, not the full CLI. */
export const HOOK_COMMANDS: ReadonlySet<string> = new Set(['check', 'log']);

/** Other versions' caches unchanged for longer than this are removed. */
const PRUNE_AFTER_MS = 7 * 24 * 60 * 60 * 1000;

const VERSION_NAME = /^[\w.+-]+$/;

interface CompileCacheApi {
  enableCompileCache?: (dir: string) => { status?: number } | undefined;
  constants?: { compileCacheStatus?: { FAILED?: number; DISABLED?: number } };
}

/** Which bundle serves a command line (`argv[2]` is the subcommand). */
export function bundleFor(subcommand: string | undefined): 'hook.js' | 'cli-main.js' {
  return subcommand !== undefined && HOOK_COMMANDS.has(subcommand) ? 'hook.js' : 'cli-main.js';
}

/** The compile cache root for this platform: `%LOCALAPPDATA%\node9\compile-cache`
 *  on Windows, `$XDG_CACHE_HOME/node9/compile-cache` or `~/.cache/...` elsewhere. */
export function cacheRoot(home: string, env: NodeJS.ProcessEnv = process.env): string {
  const base =
    process.platform === 'win32'
      ? env.LOCALAPPDATA || path.join(home, 'AppData', 'Local')
      : env.XDG_CACHE_HOME && path.isAbsolute(env.XDG_CACHE_HOME)
        ? env.XDG_CACHE_HOME
        : path.join(home, '.cache');
  return path.join(base, 'node9', 'compile-cache');
}

/** A directory this process may trust: a real directory (not a link), owned by
 *  this user, writable by nobody else. POSIX only; Windows has no such bits. */
export function trustedDir(dir: string): boolean {
  const st = fs.lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) return false;
  if (process.platform === 'win32') return true;
  const uid = process.getuid?.();
  return (uid === undefined || st.uid === uid) && (st.mode & 0o022) === 0;
}

/** Remove other versions' cache directories unchanged for a week: real
 *  directories with version names only, never a link or a stray file. */
export function pruneOld(root: string, keep: string, now: number): void {
  for (const name of fs.readdirSync(root)) {
    if (name === keep || !VERSION_NAME.test(name)) continue;
    const full = path.join(root, name);
    const st = fs.lstatSync(full);
    if (st.isSymbolicLink() || !st.isDirectory()) continue;
    if (now - st.mtimeMs < PRUNE_AFTER_MS) continue;
    fs.rmSync(full, { recursive: true, force: true });
  }
}

/**
 * Enable the compile cache for this node9 version. Returns the directory, or
 * null when the cache is not used: an old Node, a cache the environment chose
 * (NODE_COMPILE_CACHE), root, an install this user cannot write, an untrusted
 * cache directory, or any failure.
 */
export function enableCompileCache(
  home: string,
  version: string,
  installDir: string,
  now: number = Date.now()
): string | null {
  try {
    const api = nodeModule as unknown as CompileCacheApi;
    if (typeof api.enableCompileCache !== 'function') return null;
    if (process.env.NODE_COMPILE_CACHE) return null;
    if (!VERSION_NAME.test(version)) return null;
    if (process.getuid?.() === 0) return null;
    fs.accessSync(installDir, fs.constants.W_OK);

    const root = cacheRoot(home);
    fs.mkdirSync(root, { recursive: true, mode: 0o700 });
    if (!trustedDir(root)) return null;
    const dir = path.join(root, version);
    try {
      fs.mkdirSync(dir, { mode: 0o700 });
    } catch (err) {
      // The normal case after the first call; a link or a file in its place
      // is caught by trustedDir below.
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') return null;
    }
    if (!trustedDir(dir)) return null;

    // Node reports a failure in the returned status, not by throwing.
    const result = api.enableCompileCache(dir);
    const status = api.constants?.compileCacheStatus;
    if (
      status &&
      result &&
      (result.status === status.FAILED || result.status === status.DISABLED)
    ) {
      return null;
    }
    try {
      pruneOld(root, version, now);
    } catch {
      /* the cache still works; an old version lingers until a later call */
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
  enableCompileCache(os.homedir(), readVersion(), path.resolve(__dirname, '..'));
  const bundle = bundleFor(process.argv[2]);
  // A runtime path, so the bundler leaves the target out of this file.
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require(path.join(__dirname, bundle));
  } catch (err) {
    // A missing or broken hook bundle (a partial install) must not take the
    // gate down: the full CLI serves check and log too.
    if (bundle !== 'hook.js') throw err;
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require(path.join(__dirname, 'cli-main.js'));
  }
}
