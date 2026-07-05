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

/** Is this entry launched via the node9 binary (bare, an absolute path, or a
 *  Windows node9.exe/.cmd/.ps1/.bat)? The `(^|[\\/])` anchor avoids matching
 *  `mynode9` / `notnode9`. */
function isNode9Command(command: string | undefined): boolean {
  return /(^|[\\/])node9(\.(exe|cmd|ps1|bat))?$/i.test(command ?? '');
}

/** ungoverned = a spawnable upstream to wrap · gatewayed = already governed ·
 *  node9-self = node9's OWN mcp-server entry (never wrap) · remote = URL/SSE
 *  server with no command (can't be gatewayed via --upstream — never wrap). */
export function classifyMcp(s: McpServer): McpServerState {
  // A node9 wrap = the node9 binary (bare OR absolute path, fix #7) AND
  // args[0]==='mcp-gateway'. Requiring node9 avoids misclassifying a NON-node9
  // server that merely takes 'mcp-gateway' as its first arg as "already governed".
  if (isNode9Command(s.command)) {
    return (s.args ?? [])[0] === 'mcp-gateway' ? 'gatewayed' : 'node9-self';
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
export function toGateway(s: McpServer, configName?: string): McpServer {
  const upstream = [s.command ?? '', ...(s.args ?? [])].map(quoteArg).join(' ');
  // Omit the flag when empty OR when the name starts with '-': a name like
  // "--upstream" would make commander swallow the next token as its value.
  const nameArgs = configName && !configName.startsWith('-') ? ['--config-name', configName] : [];
  return {
    ...s,
    command: 'node9',
    args: ['mcp-gateway', ...nameArgs, '--upstream', upstream],
  };
}

/** Reverse toGateway. null when not a gateway-wrapped entry. */
export function fromGateway(s: McpServer): McpServer | null {
  // Accept an absolute-path node9 too (fix #7 asymmetry) so `ungateway` can
  // reverse exactly the entries classifyMcp now surfaces as 'gatewayed'.
  if (!isNode9Command(s.command) || (s.args ?? [])[0] !== 'mcp-gateway') return null;
  const args = s.args ?? [];
  const i = args.indexOf('--upstream');
  // A gatewayed entry with no (or empty) --upstream is corrupt/hand-edited — can't
  // reverse it, so decline rather than write back an empty command (re-review).
  if (i < 0 || !args[i + 1]) return null;
  const [command, ...rest] = tokenize(args[i + 1]);
  if (!command) return null;
  return { ...s, command, args: rest };
}

/** Every MCP server across all agent configs, classified. */
export function inventoryMcp(home: string = os.homedir()): McpEntry[] {
  const out: McpEntry[] = [];
  for (const spec of AGENT_SPECS) {
    if (!spec.mcpFile) continue;
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
    if (!fs.existsSync(bak)) fs.writeFileSync(bak, raw, { mode: 0o600 });
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
