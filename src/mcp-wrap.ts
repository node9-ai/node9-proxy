// src/mcp-wrap.ts
// MCP auto-wire reconciler engine (P3 Phase 2.6): inventory every agent's MCP
// servers, classify governed / ungoverned / node9-self, and wrap/unwrap an
// upstream through `node9 mcp-gateway`. Pure transforms + a backup-first writer.
// Deliberately free of the heavy gateway/orchestrator import tree so the CLI
// command stays light.
import fs from 'fs';
import os from 'os';
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';
import { AGENT_SPECS, readMcpServers, type McpServer, type McpFormat } from './agent-wiring';
import { tokenize, quoteArg } from './mcp-cmd';
import { getServerKey } from './mcp-pin';
import {
  parseNode9Launch,
  gatewayUpstream,
  MCP_WRAP_SUBCOMMAND,
  type Node9Launch,
  type Node9LaunchForm,
} from './mcp-entry';
import { mcpLauncherArgv, readyLauncherArgv, readShimTargets } from './node9-shim';
export type { McpServer, McpFormat } from './agent-wiring';
export { tokenize } from './mcp-cmd';

export type McpServerState = 'ungoverned' | 'gatewayed' | 'node9-self' | 'remote';

export interface McpEntry {
  agent: string; // AgentSpec.id
  agentLabel: string;
  mcpFile: string;
  format: McpFormat;
  name: string;
  command: string;
  args: string[];
  state: McpServerState;
  raw: McpServer; // the FULL original entry (env/type/…) — wrap/unwrap must preserve it
}

/** ungoverned = a spawnable upstream to wrap · gatewayed = already governed ·
 *  node9-self = node9's OWN mcp-server entry (never wrap) · remote = URL/SSE
 *  server with no command (can't be gatewayed via --upstream — never wrap). */
export function classifyMcp(s: McpServer): McpServerState {
  // Whether the entry starts node9, and with which subcommand, is read by
  // parseNode9Launch: the bin (bare or a path, fix #7), the launcher, and the
  // forms that pin a Node in front of it. Requiring node9 avoids misclassifying
  // a NON-node9 server that merely takes 'mcp-gateway' as its first arg as
  // "already governed".
  const launch = parseNode9Launch(s);
  if (launch) {
    if (launch.subcommand === MCP_WRAP_SUBCOMMAND) return 'gatewayed';
    // The legacy wrap, `node9 mcp --upstream <cmd>`. The upstream is required:
    // `mcp` is also the parent of `mcp status` and the other mcp commands.
    if (gatewayUpstream(launch) !== null) return 'gatewayed';
    return 'node9-self';
  }
  // No spawnable command (remote HTTP/SSE server, or a malformed entry) → not
  // wrappable; wrapping it would produce a broken `--upstream ""`.
  if (typeof s.command !== 'string' || s.command.trim() === '') return 'remote';
  return 'ungoverned';
}

/**
 * Rewrite an upstream entry to launch through the gateway (preserves env/type).
 * `configName` (the agent-config key, e.g. "redis-dev") rides along as
 * `--config-name` so the gateway can report a stable display name instead of the
 * command-derived one — fixing the "redis-dev + redis-prod both show as redis"
 * collision. It's a SEPARATE arg from --upstream, so serverKey (hashed from the
 * upstream only) is unchanged: existing pins + app-permission rules survive a
 * re-wrap. Passed as its own argv element (no shell, no re-tokenization), so a
 * name with spaces needs no quoting.
 */
/**
 * The single `--upstream` string builder. Quoting is not cosmetic: the gateway
 * re-splits this string with tokenize(), which treats `\` as an escape, so an
 * unquoted Windows path loses every separator between config write and spawn
 * (`C:\Users\x` → `C:Usersx`, ENOENT). Four agent setup flows built it with a
 * bare join and shipped that bug; they call this now, and so does toGateway,
 * so there is one implementation rather than five.
 */
export function mcpUpstreamString(s: Pick<McpServer, 'command' | 'args'>): string {
  return [s.command ?? '', ...(s.args ?? [])].map(quoteArg).join(' ');
}

/**
 * `launcher` is the argv that starts node9, in front of the subcommand:
 * `['node9']`, or `['/abs/node', '/abs/node9']` for an entry that pins its Node.
 */
export function toGateway(
  s: McpServer,
  configName?: string,
  launcher: string[] = ['node9']
): McpServer {
  const upstream = mcpUpstreamString(s);
  // Omit the flag when empty OR when the name starts with '-': a name like
  // "--upstream" would make commander swallow the next token as its value.
  const nameArgs = configName && !configName.startsWith('-') ? ['--config-name', configName] : [];
  const [command, ...launcherArgs] = launcher.length > 0 ? launcher : ['node9'];
  return {
    ...s,
    command,
    args: [...launcherArgs, MCP_WRAP_SUBCOMMAND, ...nameArgs, '--upstream', upstream],
  };
}

/** Reverse toGateway. null when not a gateway-wrapped entry. */
export function fromGateway(s: McpServer): McpServer | null {
  // The subcommand and the upstream come from the parsed launch, never from
  // args[0]: an entry that pins its Node has the node9 script there. This
  // reverses exactly the entries classifyMcp surfaces as 'gatewayed'.
  const launch = parseNode9Launch(s);
  if (!launch) return null;
  // A gatewayed entry with no (or empty) --upstream is corrupt/hand-edited — can't
  // reverse it, so decline rather than write back an empty command (re-review).
  const upstream = gatewayUpstream(launch);
  if (!upstream) return null;
  const [command, ...rest] = tokenize(upstream);
  if (!command) return null;
  return { ...s, command, args: rest };
}

/**
 * Wrap an already-wrapped entry again (to stamp `--config-name`, or to repair
 * a legacy wrap), keeping the launcher it has. null when it cannot be reversed.
 * Keeping the launcher matters: an entry that pins its Node was written that
 * way because the bare `node9` does not start on that agent's PATH, and a
 * refresh that put `command: "node9"` back would take the server down.
 */
export function regateway(s: McpServer, configName?: string): McpServer | null {
  const launch = parseNode9Launch(s);
  const orig = fromGateway(s);
  if (!launch || !orig) return null;
  return toGateway(orig, configName, launch.launcher);
}

/** The `--upstream` of an inventory entry, or null when it is not a wrap. */
export function entryUpstream(e: Pick<McpEntry, 'command' | 'args'>): string | null {
  const launch = parseNode9Launch(e);
  return launch ? gatewayUpstream(launch) : null;
}

/** Every MCP server across all agent configs, classified. */
export function inventoryMcp(home: string = os.homedir()): McpEntry[] {
  const out: McpEntry[] = [];
  for (const spec of AGENT_SPECS) {
    if (!spec.mcpFile || spec.mcpInventory === false) continue;
    const mcpFile = spec.mcpFile(home);
    const format: McpFormat = spec.mcpFormat ?? 'json';
    const servers = readMcpServers(mcpFile, format);
    for (const [name, s] of Object.entries(servers)) {
      if (!s || typeof s !== 'object') continue;
      out.push({
        agent: String(spec.id),
        agentLabel: spec.label,
        mcpFile,
        format,
        name,
        command: s.command ?? '',
        args: Array.isArray(s.args) ? s.args : [],
        state: classifyMcp(s),
        raw: s,
      });
    }
  }
  return out;
}

/**
 * True when a stored `--upstream` shows the signature of a wrap written by the
 * pre-fix code on Windows: a drive letter whose path separators are GONE.
 *
 *   C:\Users\m\srv.exe   written with a bare join   →   C:Usersmsrv.exe
 *
 * The gateway re-splits `--upstream` with tokenize(), which treats `\` as an
 * escape, so the separators were consumed between config write and spawn and
 * the server died with ENOENT. Since the wrap REPLACES the user's command, the
 * pre-corruption path exists nowhere in node9's config: this is detectable but
 * NOT repairable, which is why the only caller reports rather than rewrites.
 *
 * The signature is narrow on purpose. A drive letter with no `\` or `/`
 * anywhere in the string is not a shape anyone configures by hand, while
 * `redis://host:6379` and `https://…` arguments are everywhere — hence the
 * separator test rather than a bare colon test.
 */
export function isCorruptedUpstream(upstream: string): boolean {
  if (!upstream) return false;
  if (upstream.includes('\\') || upstream.includes('/')) return false;
  return /(^|\s)[A-Za-z]:[^\s]/.test(upstream);
}

export interface CorruptedMcpWrap {
  agent: string;
  agentLabel: string;
  mcpFile: string;
  name: string;
  upstream: string;
}

/**
 * Every node9-wrapped MCP entry, across all agent configs, whose upstream was
 * corrupted by the pre-fix wrap. Surfaced by `node9 heal`.
 */
export function findCorruptedMcpWraps(home: string = os.homedir()): CorruptedMcpWrap[] {
  const out: CorruptedMcpWrap[] = [];
  for (const e of inventoryMcp(home)) {
    if (e.state !== 'gatewayed') continue;
    const upstream = entryUpstream(e) ?? '';
    if (!isCorruptedUpstream(upstream)) continue;
    out.push({
      agent: e.agent,
      agentLabel: e.agentLabel,
      mcpFile: e.mcpFile,
      name: e.name,
      upstream,
    });
  }
  return out;
}

/**
 * Derive the set of serverKeys (pin identities) from an inventory snapshot.
 * For gatewayed entries: hashes the --upstream value (matching how the gateway pins).
 * For ungoverned entries: hashes the upstream string the gateway WOULD build on
 * wrapping — which is `toGateway`'s `[command, ...args].map(quoteArg).join(' ')`,
 * NOT a naive join. A naive join diverges the moment an arg needs quoting (a path
 * with a space), producing a different serverKey than the pin the gateway created,
 * so a still-configured server would look orphaned. Used by both the reconciler
 * and the CLI forget command.
 */
export function inventoryServerKeys(inv: McpEntry[]): Set<string> {
  const keys = new Set<string>();
  for (const e of inv) {
    if (e.state === 'gatewayed') {
      const upstream = entryUpstream(e);
      if (upstream) keys.add(getServerKey(upstream));
    } else if (e.state === 'ungoverned') {
      // Mirror toGateway exactly — quoteArg each token before joining.
      const cmd = [e.command, ...e.args].map(quoteArg).join(' ');
      keys.add(getServerKey(cmd));
    }
  }
  return keys;
}

/** The key each config format keeps its servers under. */
const MCP_FILE_KEY: Record<McpFormat, string> = {
  json: 'mcpServers',
  toml: 'mcp_servers',
  vscode: 'servers',
};

/**
 * Change the servers map of an agent's config through `mutate`, which edits
 * the map in place and returns whether it changed anything. Returns the same.
 *
 * The file is backed up once (`<mcpFile>.node9-bak`) before node9's first
 * rewrite, and replaced atomically (tmp + rename).
 * NOTE: JSON/TOML round-trip reformats the file (drops comments/layout) — the
 * backup preserves the original; agents re-read the rewritten file fine.
 * Concurrency (#6): this re-reads the CURRENT file, so whatever another
 * process wrote BEFORE this read is preserved: only the servers map is
 * edited. The only loss window is a concurrent write to the SAME file between
 * this read and the rename — sub-millisecond, and agents read their MCP
 * config at launch rather than continuously, so this is accepted for v1 (no
 * file lock). A caller must therefore pass its change as `mutate`, never a
 * map it read earlier: Claude Code keeps its whole state in the file its MCP
 * servers live in, and rewrites it while it runs.
 *
 * Throws when the file exists and does not parse, and writes nothing: a
 * config node9 cannot read is never replaced by one that holds only node9's
 * entries.
 */
export function updateMcpServers(
  mcpFile: string,
  format: McpFormat,
  mutate: (servers: Record<string, McpServer>) => boolean
): boolean {
  // VS Code keeps its servers under `servers`. This wrote them under
  // `mcpServers`, a key VS Code does not read: the entry it meant to change
  // stayed as it was and the file grew a second map.
  const key = MCP_FILE_KEY[format];
  let root: Record<string, unknown> = {};
  let raw: string | null = null;
  if (fs.existsSync(mcpFile)) {
    raw = fs.readFileSync(mcpFile, 'utf-8');
    root = (format === 'toml' ? parseToml(raw) : JSON.parse(raw)) as Record<string, unknown>;
    if (!root || typeof root !== 'object' || Array.isArray(root)) {
      throw new Error(`${mcpFile} does not hold a config object`);
    }
  }
  const existing = root[key];
  const servers: Record<string, McpServer> =
    existing && typeof existing === 'object' && !Array.isArray(existing)
      ? (existing as Record<string, McpServer>)
      : {};
  if (!mutate(servers)) return false;
  if (raw !== null) {
    // Back up ONCE, on the first node9 write to this file, so the backup is the
    // user's PRISTINE original. (Re-review corrected the earlier "refresh every
    // write" — for a file with 2+ servers, the 2nd wrap would back up the
    // already-wrapped file, losing the true original.) Per-server reversibility
    // is separate: fromGateway reads the original out of the embedded --upstream.
    const bak = `${mcpFile}.node9-bak`;
    // Exclusive create rather than existsSync-then-write: this backup holds
    // the user's pristine original, and a concurrent wrap between the check
    // and the write would overwrite it with already-wrapped content. Same
    // guard canary/plant.ts already uses.
    try {
      fs.writeFileSync(bak, raw, { mode: 0o600, flag: 'wx' });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      // Backup already present; never overwrite it.
    }
  }
  root[key] = servers;
  const serialized = format === 'toml' ? stringifyToml(root) : JSON.stringify(root, null, 2);
  const tmp = `${mcpFile}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, serialized, { mode: 0o600 });
  fs.renameSync(tmp, mcpFile);
  return true;
}

/** Set servers[name] = entry in an agent's config. See updateMcpServers. */
export function writeMcpEntry(
  mcpFile: string,
  format: McpFormat,
  name: string,
  entry: McpServer
): void {
  updateMcpServers(mcpFile, format, (servers) => {
    servers[name] = entry;
    return true;
  });
}

// ── Moving existing entries to the launcher ───────────────────────────────────

export interface LauncherMigration {
  agent: string; // AgentSpec.id
  agentLabel: string;
  mcpFile: string;
  name: string;
  /** How the entry started node9 before it was moved. */
  from: Node9LaunchForm;
}

const hasPathSeparator = (p: string): boolean => /[\\/]/.test(p);

/** True when both paths lead to the same file. False when either is missing. */
function sameFile(a: string, b: string): boolean {
  try {
    return fs.realpathSync(a) === fs.realpathSync(b);
  } catch {
    return false;
  }
}

/**
 * Whether this entry moves to the launcher.
 *
 *   bin        The bare name: yes, it starts on whatever Node the agent's PATH
 *              holds. A path to a bin: yes when it is this node9, or is gone.
 *   runtime    A Node written in front of the node9 script by hand. Yes when
 *              the Node or the script is gone. When both exist and the script
 *              is this node9: yes for an attended command, no for the daemon.
 *              It works, and a person wrote it.
 *   hook-shim  The same body, under a name older node9 versions read as a
 *              third-party server. Attended: yes. The daemon leaves it: it
 *              starts on a pinned Node already.
 *   launcher   Already there.
 *   runner     `npx node9-ai ...` is a choice to run without an install: no.
 *
 * "This node9" is the script the launcher runs. An entry that names ANOTHER
 * node9 that exists (a development checkout beside the installed one, a
 * wrapper that is not JavaScript) is someone's choice of which node9 to run:
 * the launcher would silently swap it for this one, so it is left alone.
 */
function movesToLauncher(launch: Node9Launch, cliScript: string, unattended: boolean): boolean {
  const [command, script] = launch.launcher;
  switch (launch.form) {
    case 'hook-shim':
      return !unattended;
    case 'bin':
      if (!hasPathSeparator(command)) return true;
      return !fs.existsSync(command) || sameFile(command, cliScript);
    case 'runtime':
      if (hasPathSeparator(command) && !fs.existsSync(command)) return true;
      if (!fs.existsSync(script)) return true;
      return !unattended && sameFile(script, cliScript);
    default:
      return false;
  }
}

export interface LauncherMigrationOptions {
  home?: string;
  /** The node9 script running an attended command. Default: process.argv[1]. */
  cliScript?: string;
  /**
   * True for the daemon. It never writes the launcher (it uses the one on
   * disk, when that one is usable), never rewrites TOML (smol-toml reformats
   * the whole file, comments included), and leaves an entry that works and
   * that a person pinned by hand.
   */
  unattended?: boolean;
  /** Called for an entry that should have moved and could not be written. */
  onError?: (entry: Omit<LauncherMigration, 'from'>, err: unknown) => void;
}

/**
 * Move node9's own MCP entries, in every agent's config, to the launcher
 * (~/.node9/bin/node9), so they start on the Node that ran setup. An attended
 * command (init, agents add, heal) writes or refreshes the launcher on the
 * way; the daemon passes `unattended`.
 *
 * Driven by the registry, not by each setup flow, so it reaches the file each
 * agent really loads, and the three agents the inventory leaves out (Windsurf,
 * VS Code, Claude Desktop): desktop apps, the ones most likely to start
 * servers with a short PATH.
 *
 * It rewrites only the part of an entry that starts node9. The subcommand's
 * arguments, `env`, `type` and every other key stay, so the `--upstream`
 * string, and with it the serverKey that pins and app-permission rules hang
 * on, does not change. A wrap with no `--config-name` gets the config key, as
 * the daemon's refresh pass would give it; without it a daemon still running
 * older code would "refresh" the entry back to the bare `node9`. A legacy
 * `mcp --upstream` wrap becomes `mcp-gateway`. An entry already on the
 * launcher is skipped, so a second call writes nothing.
 *
 * A file that cannot be read or written is skipped: one agent's broken config
 * must not stop the others.
 */
export function migrateMcpLaunchers(opts: LauncherMigrationOptions = {}): LauncherMigration[] {
  const home = opts.home ?? os.homedir();
  const unattended = opts.unattended === true;

  // The daemon reads the launcher first: with none on disk it has nothing to
  // move to, and "this node9" is whatever that launcher runs.
  let launcher: string[] | null = null;
  let cliScript = opts.cliScript ?? process.argv[1] ?? '';
  if (unattended) {
    launcher = readyLauncherArgv(home);
    if (!isLauncherArgv(launcher)) return [];
    cliScript = readShimTargets(launcher[0])?.cli ?? '';
  }

  // Read first, write after: with nothing to move, nothing is created either.
  interface Candidate {
    spec: (typeof AGENT_SPECS)[number];
    mcpFile: string;
    format: McpFormat;
    name: string;
    server: McpServer;
    launch: Node9Launch;
    isWrap: boolean;
  }
  const candidates: Candidate[] = [];
  for (const spec of AGENT_SPECS) {
    if (!spec.mcpFile) continue;
    const mcpFile = spec.mcpFile(home);
    const format: McpFormat = spec.mcpFormat ?? 'json';
    if (unattended && format === 'toml') continue;
    for (const [name, server] of Object.entries(readMcpServers(mcpFile, format))) {
      if (!server || typeof server !== 'object') continue;
      const launch = parseNode9Launch(server);
      if (!launch) continue;
      const state = classifyMcp(server);
      const isWrap = state === 'gatewayed';
      const isOwnServer = state === 'node9-self' && launch.subcommand === 'mcp-server';
      if (!isWrap && !isOwnServer) continue;
      if (!movesToLauncher(launch, cliScript, unattended)) continue;
      candidates.push({ spec, mcpFile, format, name, server, launch, isWrap });
    }
  }
  if (candidates.length === 0) return [];

  // Nothing to move to: Windows, a test run, or a node9 that is not started by
  // node (mcpLauncherArgv returns the bare name or the bin itself for those).
  launcher ??= mcpLauncherArgv(home);
  if (!isLauncherArgv(launcher)) return [];

  const moved: LauncherMigration[] = [];
  for (const { spec, mcpFile, format, name, server, launch, isWrap } of candidates) {
    const stamp =
      isWrap && !launch.rest.includes('--config-name') && !name.startsWith('-')
        ? ['--config-name', name]
        : [];
    const entry: McpServer = {
      ...server,
      command: launcher[0],
      args: [
        ...launcher.slice(1),
        isWrap ? MCP_WRAP_SUBCOMMAND : launch.subcommand,
        ...stamp,
        ...launch.rest,
      ],
    };
    const row = { agent: String(spec.id), agentLabel: spec.label, mcpFile, name };
    try {
      writeMcpEntry(mcpFile, format, name, entry);
      moved.push({ ...row, from: launch.form });
    } catch (err) {
      // Read-only or changed under us: leave the entry, the next run retries.
      opts.onError?.(row, err);
    }
  }
  return moved;
}

/** True when the argv is the launcher itself, not the bare name or a bin. */
function isLauncherArgv(argv: string[]): boolean {
  return parseNode9Launch({ command: argv[0], args: ['mcp-server'] })?.form === 'launcher';
}
