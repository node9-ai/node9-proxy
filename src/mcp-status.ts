// src/mcp-status.ts
// P3 2.6 follow-up — the ONE merged MCP status model shared by `node9 mcp status`,
// `node9 status`, and (later) the policy snapshot. It joins the CONFIG side (what
// each agent has wired + whether node9 governs it — from mcp-wrap.inventoryMcp)
// with the CONNECTED side (what actually launched through the gateway + when —
// from mcp-tools.json), and lints unresolvable ${ENV} placeholders.
//
// The join is by serverKey = getServerKey(<resolved upstream>). CRITICAL: the
// config stores the upstream with ${VAR} placeholders UNsubstituted, but the
// running gateway keys mcp-tools.json by the SUBSTITUTED command (the agent
// expands ${VAR} before spawn). So we must env-substitute here before hashing,
// or the join silently misses every server that uses a placeholder.
import { inventoryMcp, type McpEntry, type McpServerState } from './mcp-wrap';
import { readMcpToolsConfig } from './daemon/mcp-tools';
import { getServerKey } from './mcp-pin';

/** A governed server is "stale" once it hasn't launched through the gateway in
 *  this long — connected before, but not recently (agent stopped, tool removed). */
export const STALE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export type McpConnection =
  | 'connected' // governed + launched through the gateway recently
  | 'stale' // governed, launched before, but not within STALE_MS
  | 'pending-launch' // governed, but never launched (restart the agent to connect)
  | 'unlaunchable' // governed, but references an ${ENV} var that isn't set (restart won't fix)
  | 'ungoverned' // wired but NOT routed through node9
  | 'node9-self' // node9's own mcp-server entry
  | 'remote'; // URL/SSE server with no command — can't be gatewayed

export interface McpStatusEntry {
  agent: string;
  agentLabel: string;
  name: string;
  /** Config-side governance class (from classifyMcp). */
  state: McpServerState;
  /** Derived connection state — the one field every surface renders. */
  connection: McpConnection;
  lastSeenAt?: number;
  connectedTools?: number;
  /** ${VARS} referenced in the upstream that resolve to nothing → unlaunchable. */
  missingEnv?: string[];
  /** Pin serverKey for a governed+resolvable server (identity on the dashboard). */
  serverKey?: string;
}

/**
 * Expand `${VAR}` and `${VAR:-default}` against an env map (default: process.env),
 * mimicking how an agent expands an MCP arg before spawn. Returns the resolved
 * string and the set of vars that resolved to nothing (unset/empty, no default).
 * Only `${...}` forms are handled — bare `$VAR` is left as-is (agents use braces).
 */
export function substituteEnv(
  input: string,
  env: NodeJS.ProcessEnv = process.env
): { resolved: string; missing: string[] } {
  const missing: string[] = [];
  const resolved = input.replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}/g,
    (_full, name: string, hasDefault: string | undefined, def: string | undefined) => {
      const val = env[name];
      if (val !== undefined && val !== '') return val;
      // `${VAR:-default}` — use the default when the var is unset/empty (launchable).
      if (hasDefault !== undefined) return def ?? '';
      missing.push(name);
      return '';
    }
  );
  return { resolved, missing: [...new Set(missing)] };
}

/** Extract the raw `--upstream` string from a gatewayed entry's args, or null. */
function upstreamOf(e: McpEntry): string | null {
  const i = e.args.indexOf('--upstream');
  if (i < 0) return null;
  const u = e.args[i + 1];
  return typeof u === 'string' && u.length > 0 ? u : null;
}

/**
 * Merge one inventory entry with the connected-side + env lint into a status row.
 * Pure over its inputs (env + the tools config are passed in) so it's trivially
 * testable and free of hidden global reads.
 */
export function resolveEntryStatus(
  e: McpEntry,
  tools: ReturnType<typeof readMcpToolsConfig>,
  env: NodeJS.ProcessEnv,
  now: number
): McpStatusEntry {
  const base = { agent: e.agent, agentLabel: e.agentLabel, name: e.name, state: e.state };

  if (e.state === 'node9-self') return { ...base, connection: 'node9-self' };
  if (e.state === 'remote') return { ...base, connection: 'remote' };
  if (e.state === 'ungoverned') return { ...base, connection: 'ungoverned' };

  // gatewayed → resolve the upstream, lint env, then join by serverKey.
  const upstream = upstreamOf(e);
  if (!upstream) return { ...base, connection: 'pending-launch' };

  const { resolved, missing } = substituteEnv(upstream, env);
  if (missing.length > 0) {
    return { ...base, connection: 'unlaunchable', missingEnv: missing };
  }

  const serverKey = getServerKey(resolved);
  const connected = tools[serverKey];
  if (!connected) return { ...base, connection: 'pending-launch', serverKey };

  // Present in mcp-tools.json → it launched at least once. Undated legacy entries
  // count as connected (they DID launch; we just didn't stamp the time).
  const lastSeenAt = connected.lastSeenAt;
  const stale = typeof lastSeenAt === 'number' && now - lastSeenAt > STALE_MS;
  return {
    ...base,
    connection: stale ? 'stale' : 'connected',
    lastSeenAt,
    connectedTools: connected.tools.length,
    serverKey,
  };
}

/** The full merged status across every agent's MCP servers. */
export function resolveMcpStatus(
  home?: string,
  env: NodeJS.ProcessEnv = process.env,
  now: number = Date.now()
): McpStatusEntry[] {
  const tools = readMcpToolsConfig();
  return inventoryMcp(home).map((e) => resolveEntryStatus(e, tools, env, now));
}
