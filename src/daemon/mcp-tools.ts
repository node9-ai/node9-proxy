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
  tools: McpToolInfo[]
): 'new' | 'drift' | 'match' {
  const config = readMcpToolsConfig();
  const existing = config[serverKey];

  if (!existing) {
    config[serverKey] = {
      tools,
      disabled: [],
      status: 'pending',
    };
    writeMcpToolsConfig(config);
    return 'new';
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
