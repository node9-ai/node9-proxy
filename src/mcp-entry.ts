// src/mcp-entry.ts
// The one reading of "does this MCP server entry start node9, and how".
//
// node9 owns two kinds of entries in an agent's MCP config: its own server
// (`node9 mcp-server`) and the wraps (`node9 mcp-gateway --upstream <cmd>`).
// Several pieces of code must recognise them: the inventory (status, pins, the
// daemon's reconciler), the setup and teardown flows, doctor's wiring table and
// posture. Each used to carry its own test, and they disagreed: an entry that
// pins its Node (`<node> <node9 bin> mcp-server`, the only form that starts
// where the agent's PATH holds an old Node) was node9's to posture and a
// third-party server to everything else, so the reconciler nudged about
// node9's own server and `mcp gateway --all` offered to wrap it.
//
// A leaf module on purpose: no imports from setup, agent-wiring or mcp-wrap,
// which already import each other.

// ── Wrap vocabulary ───────────────────────────────────────────────────────────

// The subcommand that actually accepts `--upstream`. `node9 mcp` is a PARENT
// command (gateway | ungateway | status | pin) and has no such option, so a
// wrap written as `node9 mcp --upstream <cmd>` dies on startup with
// `error: unknown option '--upstream'`. Every agent's wrap carried that form.
//
// The damage is worse than lost governance: node9 REPLACES the user's server
// command, so the wrap also broke the very server it was meant to protect.
// Found 2026-09-22 in Codex's own log, not in ours — node9 had no idea the
// server it wrapped was failing to start.
export const MCP_WRAP_SUBCOMMAND = 'mcp-gateway';
export const LEGACY_MCP_WRAP_SUBCOMMAND = 'mcp';
const MCP_SERVER_SUBCOMMAND = 'mcp-server';

// Recognises the legacy subcommand too. An install still carrying it must read
// back as OURS — otherwise teardown stops unwrapping it and the user is left
// with a dead server and no way to undo it.
export function isMcpWrapSubcommand(arg: unknown): boolean {
  return arg === MCP_WRAP_SUBCOMMAND || arg === LEGACY_MCP_WRAP_SUBCOMMAND;
}

// ── Launch forms ──────────────────────────────────────────────────────────────

export type Node9LaunchForm =
  /** The node9 bin: bare `node9`, a path to it, or a Windows wrapper. */
  | 'bin'
  /** `~/.node9/bin/node9`, the fixed path that pins the Node. */
  | 'launcher'
  /** `~/.node9/bin/hook`, the hook shim, used as an MCP command. */
  | 'hook-shim'
  /** A Node runtime in front of the node9 script: `node <script> <subcommand>`. */
  | 'runtime'
  /** A package runner: `npx node9-ai <subcommand>`. Read, never written. */
  | 'runner';

export interface Node9Launch {
  form: Node9LaunchForm;
  /** argv before the subcommand, e.g. ['node9'] or ['/abs/node', '/abs/node9']. */
  launcher: string[];
  /** The node9 subcommand. Empty when a bin entry has no arguments. */
  subcommand: string;
  /** Everything after the subcommand, untouched. */
  rest: string[];
}

const lastSegment = (p: string): string => p.split(/[\\/]/).pop() ?? '';

// The `(^|[\\/])` anchor keeps `mynode9` / `notnode9` out.
const NODE9_BIN = /(^|[\\/])node9(\.(exe|cmd|ps1|bat))?$/i;
const LAUNCHER_PATH = /[\\/]\.node9[\\/]bin[\\/]node9$/;
const HOOK_SHIM_PATH = /[\\/]\.node9[\\/]bin[\\/]hook$/;
const NODE_RUNTIME = /^(node|nodejs|bun)(\.exe)?$/i;
const PACKAGE_RUNNERS = new Set(['npx', 'pnpx', 'bunx', 'dlx', 'yarn', 'pnpm', 'bun']);
// What a runner puts between itself and the package: flags, and the words
// `pnpm dlx` / `bun x` / `yarn dlx` / `npm exec` style runners take.
const RUNNER_WORDS = new Set(['dlx', 'x', 'exec']);
// The published names, optionally with a version: `node9-ai@2.66.3`.
const NODE9_PACKAGE = /^(node9|node9-ai|@node9\/proxy)(@[^@/\s]+)?$/;

// Behind a runtime or a runner the subcommand must be one node9 puts in an MCP
// entry: a script that merely sits in a folder named node9 is not node9.
const MCP_ENTRY_SUBCOMMANDS = new Set([
  MCP_SERVER_SUBCOMMAND,
  MCP_WRAP_SUBCOMMAND,
  LEGACY_MCP_WRAP_SUBCOMMAND,
]);

/** The node9 entry script: the file npm links as `node9`, or `cli.js` inside
 *  a node9 package folder (an install, or a development checkout). */
export function isNode9Script(arg: string): boolean {
  if (/^node9(\.(js|cjs|mjs|cmd))?$/i.test(lastSegment(arg))) return true;
  return /(^|[\\/])(node9-ai|node9-proxy|@node9[\\/]proxy)[\\/]dist[\\/]cli\.js$/i.test(arg);
}

/**
 * Read an MCP server entry as a node9 launch, or null when it does not start
 * node9. Takes `unknown` fields: the entry comes from a config file a person
 * or another tool may have written.
 */
export function parseNode9Launch(s: { command?: unknown; args?: unknown }): Node9Launch | null {
  const command = s.command;
  if (typeof command !== 'string' || command.trim() === '') return null;
  const args = Array.isArray(s.args)
    ? s.args.map((a) => (typeof a === 'string' ? a : String(a)))
    : [];

  // Order matters: the launcher's path also matches the bin pattern.
  const direct: Node9LaunchForm | null = LAUNCHER_PATH.test(command)
    ? 'launcher'
    : HOOK_SHIM_PATH.test(command)
      ? 'hook-shim'
      : NODE9_BIN.test(command)
        ? 'bin'
        : null;
  if (direct) {
    return { form: direct, launcher: [command], subcommand: args[0] ?? '', rest: args.slice(1) };
  }

  const name = lastSegment(command).toLowerCase();

  // `args[0]` must be the script: an entry with Node flags in front of it is
  // not recognised, and reads as a third-party server.
  if (NODE_RUNTIME.test(name) && isNode9Script(args[0] ?? '')) {
    if (!MCP_ENTRY_SUBCOMMANDS.has(args[1] ?? '')) return null;
    return {
      form: 'runtime',
      launcher: [command, args[0]],
      subcommand: args[1],
      rest: args.slice(2),
    };
  }

  // `bun` is both a runtime and a runner, so this is not an else.
  if (PACKAGE_RUNNERS.has(name)) {
    let i = 0;
    while (i < args.length && (args[i].startsWith('-') || RUNNER_WORDS.has(args[i]))) i++;
    if (!NODE9_PACKAGE.test(args[i] ?? '')) return null;
    if (!MCP_ENTRY_SUBCOMMANDS.has(args[i + 1] ?? '')) return null;
    return {
      form: 'runner',
      launcher: [command, ...args.slice(0, i + 1)],
      subcommand: args[i + 1],
      rest: args.slice(i + 2),
    };
  }

  return null;
}

/** The `--upstream` value of a wrap, or null: not a wrap, or no usable value. */
export function gatewayUpstream(l: Node9Launch): string | null {
  if (!isMcpWrapSubcommand(l.subcommand)) return null;
  const i = l.rest.indexOf('--upstream');
  if (i < 0) return null;
  const upstream = l.rest[i + 1];
  return typeof upstream === 'string' && upstream.length > 0 ? upstream : null;
}
