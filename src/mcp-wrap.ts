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
export type { McpServer, McpFormat } from './agent-wiring';

export type McpServerState = 'ungoverned' | 'gatewayed' | 'node9-self';

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

// Mirrors mcp-gateway/index.ts `tokenize` (double-quote + backslash aware) so the
// `--upstream` string we write round-trips with what the gateway parses at runtime.
// Kept local (not imported) to avoid pulling the gateway into the CLI; a round-trip
// test guards against drift.
export function tokenize(cmd: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inDouble = false;
  let i = 0;
  while (i < cmd.length) {
    const ch = cmd[i];
    if (inDouble) {
      if (ch === '"') inDouble = false;
      else if (ch === '\\' && i + 1 < cmd.length) current += cmd[++i];
      else current += ch;
    } else if (ch === '"') {
      inDouble = true;
    } else if (ch === ' ' || ch === '\t') {
      if (current) {
        tokens.push(current);
        current = '';
      }
    } else if (ch === '\\' && i + 1 < cmd.length) {
      current += cmd[++i];
    } else {
      current += ch;
    }
    i++;
  }
  if (current) tokens.push(current);
  return tokens;
}

function quoteArg(s: string): string {
  if (s === '') return '""';
  if (/[\s"\\]/.test(s)) return `"${s.replace(/(["\\])/g, '\\$1')}"`;
  return s;
}

/** ungoverned = a real upstream to wrap · gatewayed = already governed · node9-self
 *  = node9's OWN mcp-server entry (never wrap it). */
export function classifyMcp(s: McpServer): McpServerState {
  if (s.command === 'node9') {
    return (s.args ?? [])[0] === 'mcp-gateway' ? 'gatewayed' : 'node9-self';
  }
  return 'ungoverned';
}

/** Rewrite an upstream entry to launch through the gateway (preserves env/type). */
export function toGateway(s: McpServer): McpServer {
  const upstream = [s.command ?? '', ...(s.args ?? [])].map(quoteArg).join(' ');
  return { ...s, command: 'node9', args: ['mcp-gateway', '--upstream', upstream] };
}

/** Reverse toGateway. null when not a gateway-wrapped entry. */
export function fromGateway(s: McpServer): McpServer | null {
  if (s.command !== 'node9' || (s.args ?? [])[0] !== 'mcp-gateway') return null;
  const args = s.args ?? [];
  const i = args.indexOf('--upstream');
  const [command, ...rest] = tokenize(i >= 0 ? (args[i + 1] ?? '') : '');
  return { ...s, command: command ?? '', args: rest };
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
