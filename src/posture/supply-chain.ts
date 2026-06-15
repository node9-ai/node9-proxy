// src/posture/supply-chain.ts
// Check 4 — Supply chain (MCP servers).
//
// Enumerates every MCP server configured across all known agents and reports
// the attack surface: servers that run OUTSIDE node9 (so their tool calls
// aren't gated — tool-poisoning / rug-pull risk) and any launched from an
// untrusted path (provenance via the same `checkProvenance` the gate uses).
//
// Config inspection only — no MCP server is launched or contacted.

import fs from 'fs';
import os from 'os';
import { parse as parseToml } from 'smol-toml';
import { checkProvenance } from '../utils/provenance';
import { AGENT_SPECS } from '../agent-wiring';
import type { CheckContext, Finding } from './types';

interface McpEntry {
  name: string;
  command?: string;
  agent: string;
}

// Agent config files are normally small, but Claude's `.claude.json` (its MCP
// file) accrues history/project state and can reach several MB. Cap the read
// so a pathological file can't make every posture run parse hundreds of MB.
const MAX_CONFIG_BYTES = 10 * 1024 * 1024;

/** Parse an agent's MCP config into server entries. Malformed/absent → []. */
function readServers(file: string, format: 'json' | 'toml', agent: string): McpEntry[] {
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > MAX_CONFIG_BYTES) return [];
    const text = fs.readFileSync(file, 'utf8');
    const map = (
      format === 'toml'
        ? (parseToml(text) as { mcp_servers?: Record<string, { command?: string }> })?.mcp_servers
        : (JSON.parse(text) as { mcpServers?: Record<string, { command?: string }> })?.mcpServers
    ) as Record<string, { command?: string }> | undefined;
    if (!map || typeof map !== 'object') return [];
    return Object.entries(map).map(([name, v]) => ({ name, command: v?.command, agent }));
  } catch {
    return [];
  }
}

export function checkSupplyChain(ctx: CheckContext): Finding[] {
  const home = ctx.home || os.homedir();

  const servers: McpEntry[] = [];
  for (const spec of AGENT_SPECS) {
    if (!spec.mcpFile) continue;
    servers.push(...readServers(spec.mcpFile(home), spec.mcpFormat ?? 'json', spec.label));
  }
  if (servers.length === 0) return [];

  const findings: Finding[] = [];

  // node9-wrapped servers launch as `node9` (gated). Anything else runs direct.
  const unmanaged = servers.filter((s) => s.command && s.command !== 'node9');

  // Launch binaries in /tmp or world-writable dirs = anyone on the box can swap them.
  const suspect = unmanaged.filter(
    (s) => checkProvenance(s.command as string, ctx.cwd).trustLevel === 'suspect'
  );

  if (suspect.length > 0) {
    findings.push({
      category: 'Supply chain',
      severity: 'high',
      title: `${suspect.length} MCP server${suspect.length === 1 ? '' : 's'} launched from an untrusted path`,
      detail: [
        ...suspect.map((s) => `${s.name} → ${s.command} (${s.agent})`),
        'A binary in /tmp or a world-writable dir can be replaced by anything on the host.',
      ],
      fix: 'node9 can pin + provenance-check MCP servers before they run.',
    });
  }

  if (unmanaged.length > 0) {
    findings.push({
      category: 'Supply chain',
      severity: 'medium',
      title: `${unmanaged.length} of ${servers.length} MCP server${servers.length === 1 ? '' : 's'} run outside node9`,
      detail: [
        ...unmanaged.slice(0, 5).map((s) => `${s.name} (${s.agent})`),
        'Their tool calls execute without node9 gating — tool-poisoning / rug-pull risk.',
      ],
      fix: 'node9 can wrap MCP servers so every tool call is gated + pinned.',
    });
  }

  return findings;
}
