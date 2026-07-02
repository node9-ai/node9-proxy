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

// Mirrors mcp-gateway/index.ts `tokenize` (double-quote + backslash aware) so the
// `--upstream` string we write round-trips with what the gateway parses at runtime.
// Kept local (not imported) to avoid pulling the gateway into the CLI; a round-trip
// test guards against drift.
export function tokenize(cmd: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inDouble = false;
  let quoted = false; // this token had an explicit quote → push even if empty (fix #4)
  let i = 0;
  while (i < cmd.length) {
    const ch = cmd[i];
    if (inDouble) {
      if (ch === '"') inDouble = false;
      else if (ch === '\\' && i + 1 < cmd.length) current += cmd[++i];
      else current += ch;
    } else if (ch === '"') {
      inDouble = true;
      quoted = true;
    } else if (ch === ' ' || ch === '\t') {
      if (current || quoted) {
        tokens.push(current);
        current = '';
        quoted = false;
      }
    } else if (ch === '\\' && i + 1 < cmd.length) {
      current += cmd[++i];
    } else {
      current += ch;
    }
    i++;
  }
  if (current || quoted) tokens.push(current);
  return tokens;
}

function quoteArg(s: string): string {
  if (s === '') return '""';
  if (/[\s"\\]/.test(s)) return `"${s.replace(/(["\\])/g, '\\$1')}"`;
  return s;
}

/** ungoverned = a spawnable upstream to wrap · gatewayed = already governed ·
 *  node9-self = node9's OWN mcp-server entry (never wrap) · remote = URL/SSE
 *  server with no command (can't be gatewayed via --upstream — never wrap). */
export function classifyMcp(s: McpServer): McpServerState {
  // Recognize a node9 wrap by its ARGS, not just a bare 'node9' command — an entry
  // launched via an absolute path (/usr/local/bin/node9 mcp-gateway …) must not be
  // double-wrapped (fix #7). args[0] === 'mcp-gateway' ⟹ already governed.
  if ((s.args ?? [])[0] === 'mcp-gateway') return 'gatewayed';
  const isNode9 = s.command === 'node9' || /(^|\/)node9$/.test(s.command ?? '');
  if (isNode9) return 'node9-self'; // node9's own (mcp-server etc.) — never wrap
  // No spawnable command (remote HTTP/SSE server, or a malformed entry) → not
  // wrappable; wrapping it would produce a broken `--upstream ""`.
  if (typeof s.command !== 'string' || s.command.trim() === '') return 'remote';
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
    // Refresh the backup on EVERY write (fix #9): a write-once backup goes stale
    // after later edits. This keeps <mcpFile>.node9-bak = the state immediately
    // before node9's most recent modification — a reliable one-step undo.
    // (Per-server reversibility is separate: fromGateway reads the original out
    // of the embedded --upstream string.)
    fs.writeFileSync(`${mcpFile}.node9-bak`, raw, { mode: 0o600 });
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
