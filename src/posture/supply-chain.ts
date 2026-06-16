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
import path from 'path';
import { parse as parseToml } from 'smol-toml';
import { checkProvenance } from '../utils/provenance';
import { AGENT_SPECS } from '../agent-wiring';
import type { CheckContext, Finding } from './types';

interface McpEntry {
  name: string;
  command?: string;
  args?: string[];
  agent: string;
}

interface McpServerConfig {
  command?: string;
  args?: string[];
}

// Package-runner wrappers that launch a tool by name from args.
const PACKAGE_RUNNERS = new Set(['npx', 'pnpx', 'bunx', 'dlx', 'yarn', 'pnpm', 'bun']);

/**
 * True when a server is launched THROUGH node9 (so its calls are gated).
 * Matches the bare `node9` binary, an absolute/relative path to it
 * (`/usr/local/bin/node9`), and `npx node9 …` style wrappers — so a wrapped
 * server isn't mislabeled "runs outside node9".
 */
export function isNode9Managed(command?: string, args: string[] = []): boolean {
  if (!command) return false;
  if (path.basename(command).toLowerCase() === 'node9') return true;
  if (PACKAGE_RUNNERS.has(path.basename(command).toLowerCase())) {
    return args.some((a) => a === 'node9' || path.basename(a).toLowerCase() === 'node9');
  }
  return false;
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
        ? (parseToml(text) as { mcp_servers?: Record<string, McpServerConfig> })?.mcp_servers
        : (JSON.parse(text) as { mcpServers?: Record<string, McpServerConfig> })?.mcpServers
    ) as Record<string, McpServerConfig> | undefined;
    if (!map || typeof map !== 'object') return [];
    return Object.entries(map).map(([name, v]) => ({
      name,
      command: v?.command,
      args: Array.isArray(v?.args) ? v.args : undefined,
      agent,
    }));
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

  // node9-wrapped servers are gated; anything else runs direct (bypasses node9).
  const unmanaged = servers.filter((s) => s.command && !isNode9Managed(s.command, s.args));

  // Launch binaries in /tmp or world-writable dirs = anyone on the box can swap them.
  const suspect = unmanaged.filter(
    (s) => checkProvenance(s.command as string, ctx.cwd).trustLevel === 'suspect'
  );

  if (suspect.length > 0) {
    findings.push({
      category: 'Supply chain',
      severity: 'high',
      title: `${suspect.length} MCP server${suspect.length === 1 ? '' : 's'} launched from an untrusted path`,
      what: 'An MCP tool-server runs from an untrusted location.',
      why: 'Its binary lives in /tmp or a world-writable directory.',
      who: 'Anything on the machine could swap that binary for malware the agent then runs.',
      detail: suspect.map((s) => `${s.name} → ${s.command} (${s.agent})`),
      owner: 'node9',
      fix: 'node9 can pin + provenance-check MCP servers before they run.',
    });
  }

  if (unmanaged.length > 0) {
    findings.push({
      category: 'Supply chain',
      severity: 'medium',
      title: `${unmanaged.length} of ${servers.length} MCP server${servers.length === 1 ? '' : 's'} run outside node9`,
      what: 'Some MCP tool-servers run without node9 watching their tool calls.',
      why: "They're launched directly, not wrapped by node9.",
      who: 'A poisoned or silently-updated server could act freely (tool-poisoning / rug-pull).',
      detail: unmanaged.slice(0, 5).map((s) => `${s.name} (${s.agent})`),
      owner: 'node9',
      fix: 'node9 can wrap MCP servers so every tool call is gated + pinned.',
    });
  }

  return findings;
}
