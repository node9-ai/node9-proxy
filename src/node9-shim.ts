// src/node9-shim.ts
// The two files node9 keeps in ~/.node9/bin, so that the commands it writes
// into agent configs are constant per machine:
//
//   hook    the command of every hook
//   node9   the command of every MCP entry: node9's own server and the wraps
//
// Both are the same short sh script: run node9 on the Node that ran setup,
// whatever the agent's PATH holds. An agent's config holds only the fixed
// path, so an upgrade of Node or of node9 rewrites the script and leaves the
// config alone.
//
// Why MCP entries need it (found 2026-11-21): node9 wrote them as
// `{ command: 'node9' }`. The bin starts through `#!/usr/bin/env node`, which
// takes `node` from the AGENT's PATH. A desktop app whose PATH begins with an
// old system Node started node9 on it, node9 refused to run there, and the
// agent reported only "failed to connect": node9's own server and every
// wrapped server were down, the user's servers with them.
//
// Why a second file and not the hook shim: released versions already read a
// command whose last segment is `node9` as node9's, and read `.../bin/hook`
// as a third-party server. A daemon outlives an upgrade, so an old daemon
// meeting `hook mcp-gateway ...` would nudge about it and, with auto-wrap on,
// wrap the wrap.
//
// A leaf module: fs, os, path and the entry parser. setup.ts, the `mcp
// gateway` command and the daemon's reconciler all need the launcher, and
// they already import each other.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parseNode9Launch } from './mcp-entry';

export type ShimName = 'hook' | 'node9';

export function toForwardSlashes(p: string): string {
  return p.replace(/\\/g, '/');
}

/** ~/.node9/bin/<name> */
export function shimPath(name: ShimName, home: string = os.homedir()): string {
  return path.join(home, '.node9', 'bin', name);
}

// The hook body must not change by a byte without a reason: ensureShim
// rewrites a file whose body differs, on every machine, at the next setup.
const SHIM_HEADER: Record<ShimName, string> = {
  hook:
    '# node9 hook shim — written by `node9 init` / `node9 agents add`. Do not edit.\n' +
    '# Agents call this fixed path; node9 rewrites the lines below on upgrade so\n' +
    '# the hook command they trusted never changes (Codex keys trust to it).\n' +
    "# The node that ran setup runs node9, whatever the agent's PATH holds. If an\n" +
    '# upgrade removed it, the first node on PATH does, as a global install would.\n',
  node9:
    '# node9 launcher, written by `node9 init` / `node9 agents add`. Do not edit.\n' +
    '# MCP entries in agent configs call this fixed path, so node9 starts on the\n' +
    "# Node that ran setup, whatever the agent's PATH holds. If an upgrade removed\n" +
    '# that Node, the first node on PATH runs it, as a global install would.\n',
};

export function shimBody(name: ShimName, nodeExec: string, cliScript: string): string {
  return (
    '#!/bin/sh\n' +
    SHIM_HEADER[name] +
    `node="${nodeExec}"\n` +
    '[ -x "$node" ] || node=node\n' +
    `exec "$node" "${cliScript}" "$@"\n`
  );
}

/**
 * Write one shim when it is missing or its body no longer points at the
 * current node + cli.js. Idempotent and cheap (one read + compare); safe to
 * call from every setup flow. Returns whether it wrote.
 */
export function ensureShim(
  name: ShimName,
  home: string,
  nodeExec: string,
  cliScript: string
): boolean {
  const shim = shimPath(name, home);
  const body = shimBody(name, nodeExec, cliScript);
  try {
    if (fs.readFileSync(shim, 'utf-8') === body) return false;
  } catch {
    // missing: fall through and write
  }
  fs.mkdirSync(path.dirname(shim), { recursive: true });
  fs.writeFileSync(shim, body, { mode: 0o755 });
  fs.chmodSync(shim, 0o755); // writeFileSync's mode is masked by umask and ignored on overwrite
  return true;
}

/** Both shims, in one call: a setup that pins the hooks pins the MCP entries
 *  to the same Node. Returns whether either file was written. */
export function ensureShims(home: string, nodeExec: string, cliScript: string): boolean {
  const hook = ensureShim('hook', home, nodeExec, cliScript);
  const launcher = ensureShim('node9', home, nodeExec, cliScript);
  return hook || launcher;
}

/**
 * The node and the node9 script a shim runs, read from its body. null when
 * the file is missing or its body is not one node9 wrote.
 * Current body: node="<node>" ... exec "$node" "<cli>". Older body: exec "<node>" "<cli>".
 */
export function readShimTargets(shim: string): { node: string; cli: string } | null {
  let body: string;
  try {
    body = fs.readFileSync(shim, 'utf-8');
  } catch {
    return null;
  }
  const pinned = /^node="([^"]+)"$/m.exec(body)?.[1];
  const exec = /^exec "([^"]+)" "([^"]+)" "\$@"$/m.exec(body);
  if (!exec) return null;
  const node = exec[1] === '$node' ? pinned : exec[1];
  return node ? { node, cli: exec[2] } : null;
}

/**
 * True when the shim at `shim` points at a node or a cli.js that no longer
 * exists (an nvm version removed, node9 reinstalled elsewhere). The command an
 * agent holds is still the shim's fixed path, so only the body tells.
 * A body that does not parse is not called stale: it is left for a human.
 */
export function isShimTargetStale(shim: string): boolean {
  const targets = readShimTargets(shim);
  if (!targets) return false;
  // A missing node still runs (PATH fallback) but no longer as set up: rewrite it.
  return !fs.existsSync(targets.node) || !fs.existsSync(targets.cli);
}

/**
 * The daemon's one write to ~/.node9/bin: when there is no launcher, make it
 * from the hook shim.
 *
 * Why the daemon needs it. A user who upgrades node9 and runs no setup command
 * has no launcher, so nothing the daemon does could move their MCP entries to
 * one, and those entries keep failing on an old Node. The hook shim is there
 * on any machine that ran setup since it shipped.
 *
 * Why this is not "the daemon choosing a Node". It copies the node and the
 * node9 the hook shim names, the choice an attended setup made. It never uses
 * its own process.execPath (the daemon may run on another Node), and it never
 * touches a launcher that exists, stale or not: rewriting is setup's job, so
 * there is one writer of a pinned Node and it cannot flap.
 *
 * Returns the targets it wrote, or null when it wrote nothing: a launcher is
 * already there, there is no hook shim, or the hook shim does not parse or
 * points at something that is gone.
 */
export function createLauncherFromHookShim(
  home: string = os.homedir()
): { node: string; cli: string } | null {
  if (process.platform === 'win32') return null;
  const launcher = shimPath('node9', home);
  if (fs.existsSync(launcher)) return null;
  const hook = shimPath('hook', home);
  const targets = readShimTargets(hook);
  if (!targets || isShimTargetStale(hook)) return null;
  // Exclusive create: a setup command running at this moment wins, whole.
  try {
    fs.writeFileSync(launcher, shimBody('node9', targets.node, targets.cli), {
      mode: 0o755,
      flag: 'wx',
    });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return null;
    throw err;
  }
  fs.chmodSync(launcher, 0o755); // writeFileSync's mode is masked by umask
  return targets;
}

/**
 * Whether node9 is run as `<nodeExec> <cliScript>`, pinning the Node, rather
 * than through its bin. A .js path always is. A bin is pinned when it links to
 * JavaScript and the running binary is node: under `bunx --bun` it is bun, and
 * the bin's own `#!/usr/bin/env node` is the better choice there.
 */
export function pinsNode(nodeExec: string, cliScript: string): boolean {
  if (cliScript.endsWith('.js')) return true;
  return resolvesToJsFile(cliScript) && runsOnNode(nodeExec);
}

/** True when `execPath` is node itself, not bun or another runtime. */
export function runsOnNode(execPath: string): boolean {
  return /^node(js)?(\.exe)?$/i.test(path.basename(execPath));
}

/**
 * The node path to write into the shim. process.execPath is the resolved
 * binary, and a package manager deletes it on upgrade (Homebrew's
 * Cellar/node/<version>/bin/node). npm puts its global bin next to the node
 * that owns it (nvm, Homebrew, /usr/local), and that link survives upgrades:
 * use it when it leads to the same binary.
 */
export function pinnedNode(nodeExec: string, cliScript: string): string {
  const beside = toForwardSlashes(path.join(path.dirname(cliScript), 'node'));
  try {
    if (fs.realpathSync(beside) === fs.realpathSync(nodeExec)) return beside;
  } catch {
    /* no node beside the bin: keep execPath */
  }
  return nodeExec;
}

/** True when `bin` is, or links to, a JavaScript file that node can run. */
export function resolvesToJsFile(bin: string): boolean {
  try {
    return fs.realpathSync(bin).endsWith('.js');
  } catch {
    return false;
  }
}

/**
 * The argv prefix that starts the node9 CLI from a child process, for the
 * process that is running setup now:
 *
 *   - node9 is JavaScript run by node (a cli.js path, or a global bin that
 *     links to one): on POSIX the shim named `name`, written here if needed;
 *     on Windows node + cli.js.
 *   - A bin that is not JavaScript (pnpm's shell wrapper), or a bin run by
 *     bun: the bin itself.
 *
 * Under NODE9_TESTING=1 it is the bare ['node9'], so unit tests do not depend
 * on the local filesystem layout.
 */
export function node9Argv(name: ShimName, home: string = os.homedir()): string[] {
  if (process.env.NODE9_TESTING === '1') return ['node9'];
  const nodeExec = process.execPath;
  const cliScript = process.argv[1];
  if (!cliScript || !pinsNode(nodeExec, cliScript)) return [cliScript];
  // POSIX: the shims, so the caller runs on the Node that set it up, falls back
  // to PATH when an upgrade removed it, and is healed with the other agents.
  if (process.platform !== 'win32') {
    ensureShims(home, pinnedNode(nodeExec, cliScript), cliScript);
    return [shimPath(name, home)];
  }
  return [nodeExec, cliScript];
}

/**
 * What an ATTENDED command (init, agents add, mcp gateway) puts in front of
 * the subcommand of an MCP entry. On POSIX the launcher, written or refreshed
 * by this call.
 *
 * Windows keeps the PATH-resolved name: the failure this fixes was measured
 * on POSIX only, and `node9` there is a .cmd wrapper, not a shebang script.
 */
export function mcpLauncherArgv(home: string = os.homedir()): string[] {
  if (process.platform === 'win32') return ['node9'];
  const argv = node9Argv('node9', home);
  // node9 must never write an entry it would not read back as its own: setup
  // would wrap it on the next run and the reconciler would nudge about it.
  const readsBack =
    typeof argv[0] === 'string' &&
    parseNode9Launch({ command: argv[0], args: [...argv.slice(1), 'mcp-server'] }) !== null;
  return readsBack ? argv : ['node9'];
}

/**
 * The same, for code that must not write the launcher: the daemon. It may run
 * on another Node than the one the user set up with, and two writers would
 * make the pinned Node flap. The launcher when setup left a usable one, else
 * the bare name, as before the launcher existed.
 */
export function readyLauncherArgv(home: string = os.homedir()): string[] {
  if (process.platform === 'win32') return ['node9'];
  const launcher = shimPath('node9', home);
  try {
    fs.accessSync(launcher, fs.constants.X_OK);
  } catch {
    return ['node9'];
  }
  return isShimTargetStale(launcher) ? ['node9'] : [launcher];
}
