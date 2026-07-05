import fs from 'fs';
import path from 'path';
import os from 'os';

export interface McpToolInfo {
  name: string;
  description?: string;
}

export interface McpServerConfig {
  tools: McpToolInfo[];
  disabled: string[];
  status: 'pending' | 'approved';
  /** Friendly server name derived from the upstream launch command (e.g.
   *  "filesystem"). Display-only — the serverKey stays the identity. */
  name?: string;
  /** Epoch-ms the gateway last reported this server through discovery (i.e. the
   *  server actually LAUNCHED and ran a tools/list). Absence = discovered by a
   *  build that predates this field; treat as connected-but-undated, not stale.
   *  This is the "connected" freshness signal the status resolver joins on. */
  lastSeenAt?: number;
}

/**
 * Derive a friendly server name from an MCP upstream launch command, e.g.
 * `npx -y @modelcontextprotocol/server-filesystem /home` → "filesystem".
 * Best-effort + display-only; falls back to "MCP Server".
 */
export function deriveServerName(cmd: string): string {
  if (!cmd || typeof cmd !== 'string') return 'MCP Server';
  const strip = (s: string) =>
    s.replace(/^(mcp-server|server|mcp)-/i, '').replace(/-(mcp-server|server|mcp)$/i, '') || s;
  // Scoped npm package: @scope/server-filesystem → filesystem
  const scoped = cmd.match(/@[\w.-]+\/([\w.-]+)/);
  if (scoped) return strip(scoped[1]);
  // Otherwise the first non-flag, non-runner token's basename.
  const runners = new Set([
    'npx',
    'node',
    'uvx',
    'uv',
    'python',
    'python3',
    'bunx',
    'bun',
    'deno',
    'run',
    'sh',
    '-c',
  ]);
  const bin = cmd
    .split(/\s+/)
    .filter(Boolean)
    .find((p) => !p.startsWith('-') && !runners.has(p.toLowerCase()));
  if (!bin) return 'MCP Server';
  const base = (bin.split('/').pop() || bin).replace(/\.(js|mjs|cjs|ts|py)$/i, '');
  return strip(base) || 'MCP Server';
}

export type McpToolsConfig = Record<string, McpServerConfig>;

function getMcpToolsFile(): string {
  return path.join(os.homedir(), '.node9', 'mcp-tools.json');
}

export function readMcpToolsConfig(): McpToolsConfig {
  try {
    const file = getMcpToolsFile();
    if (!fs.existsSync(file)) return {};
    const raw = fs.readFileSync(file, 'utf-8');
    return JSON.parse(raw) as McpToolsConfig;
  } catch {
    return {};
  }
}

export function writeMcpToolsConfig(config: McpToolsConfig): void {
  try {
    const file = getMcpToolsFile();
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    // Atomic write
    const tmpPath = `${file}.${os.hostname()}.${process.pid}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(config, null, 2));
    fs.renameSync(tmpPath, file);
  } catch (e) {
    console.error('Failed to write mcp-tools.json', e);
  }
}

export function getServerConfig(serverKey: string): McpServerConfig | undefined {
  const config = readMcpToolsConfig();
  return config[serverKey];
}

export function updateServerDiscovery(
  serverKey: string,
  tools: McpToolInfo[],
  name?: string
): 'new' | 'drift' | 'match' {
  const config = readMcpToolsConfig();
  const existing = config[serverKey];
  const now = Date.now();

  if (!existing) {
    config[serverKey] = {
      tools,
      disabled: [],
      status: 'pending',
      lastSeenAt: now,
      ...(name && { name }),
    };
    writeMcpToolsConfig(config);
    return 'new';
  }

  // Every discovery report means the server just launched through the gateway —
  // stamp freshness unconditionally (a 'match' still proves it's connected NOW).
  existing.lastSeenAt = now;

  // Backfill the name on an existing entry that predates name capture.
  if (name && !existing.name) {
    existing.name = name;
  }

  // Check for drift (new tools added)
  const existingNames = new Set(existing.tools.map((t) => t.name));
  const newTools = tools.filter((t) => !existingNames.has(t.name));

  if (newTools.length > 0) {
    existing.tools = tools; // Update full list
    existing.status = 'pending'; // Require re-approval
    writeMcpToolsConfig(config);
    return 'drift';
  }

  writeMcpToolsConfig(config); // persist the refreshed lastSeenAt (+ any backfilled name)
  return 'match';
}

export function approveServer(serverKey: string, disabledTools: string[]): void {
  const config = readMcpToolsConfig();
  if (config[serverKey]) {
    config[serverKey].status = 'approved';
    config[serverKey].disabled = disabledTools;
    writeMcpToolsConfig(config);
  }
}
