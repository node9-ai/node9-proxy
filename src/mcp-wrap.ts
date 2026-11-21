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
import { parseNode9Launch, gatewayUpstream, MCP_WRAP_SUBCOMMAND } from './mcp-entry';
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

/**
 * Set servers[name] = entry in an agent's config, backing the file up once
 * (`<mcpFile>.node9-bak`) before the first rewrite. Atomic (tmp + rename).
 * NOTE: JSON/TOML round-trip reformats the file (drops comments/layout) — the
 * backup preserves the original; agents re-read the rewritten file fine.
 * Concurrency (#6): this re-reads the CURRENT file, so a server added by another
 * process BEFORE this read is preserved (only servers[name] is set). The only
 * loss window is a concurrent write to the SAME file between this read and the
 * rename — sub-millisecond, and agents read their MCP config at launch rather
 * than continuously, so this is accepted for v1 (no file lock).
 */
export function writeMcpEntry(
  mcpFile: string,
  format: McpFormat,
  name: string,
  entry: McpServer
): void {
  const key = format === 'toml' ? 'mcp_servers' : 'mcpServers';
  let root: Record<string, unknown> = {};
  if (fs.existsSync(mcpFile)) {
    const raw = fs.readFileSync(mcpFile, 'utf-8');
    root = (format === 'toml' ? parseToml(raw) : JSON.parse(raw)) as Record<string, unknown>;
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
  const existing = root[key];
  const servers: Record<string, McpServer> =
    existing && typeof existing === 'object' && !Array.isArray(existing)
      ? (existing as Record<string, McpServer>)
      : {};
  servers[name] = entry;
  root[key] = servers;
  const serialized = format === 'toml' ? stringifyToml(root) : JSON.stringify(root, null, 2);
  const tmp = `${mcpFile}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, serialized, { mode: 0o600 });
  fs.renameSync(tmp, mcpFile);
}
