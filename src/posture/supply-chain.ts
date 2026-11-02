// src/posture/supply-chain.ts
// Check 4 — Supply chain (MCP servers).
//
// Enumerates every MCP server configured across all known agents and reports
// the attack surface: servers that run OUTSIDE node9 (so their tool calls
// aren't gated — tool-poisoning / rug-pull risk) and any launched from an
// untrusted path (provenance via the same `checkProvenance` the gate uses).
//
// Config inspection only — no MCP server is launched or contacted.

import os from 'os';
import path from 'path';
import { parse as parseToml } from 'smol-toml';
import { checkProvenance } from '../utils/provenance';
import { checkValue } from '@node9/policy-engine';
import { getConfig, catalogSettingsFrom } from '../config';
import { defaultSkillRoots, getRootKey, readSkillPinsSafe } from '../skill-pin';
import { AGENT_SPECS, type McpFormat } from '../agent-wiring';
import type { CheckContext, Finding } from './types';
import { readCappedText } from '../utils/read-capped';

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
function readServers(file: string, format: McpFormat, agent: string): McpEntry[] {
  try {
    // Cap enforced by the read; see read-capped.ts.
    const capped = readCappedText(file, MAX_CONFIG_BYTES);
    if (!capped || capped.truncated) return [];
    const text = capped.text;
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
    if (!spec.mcpFile || spec.mcpInventory === false) continue;
    servers.push(...readServers(spec.mcpFile(home), spec.mcpFormat ?? 'json', spec.label));
  }
  const findings: Finding[] = [...pluginsAndPackages(ctx, home)];
  if (servers.length === 0) return findings;

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

// ── Plugins and packages (OWASP ASI04, node9Firewall#320 phase 1) ───────────
//
// Skills and plugins the agent loads are code that runs with the agent's
// rights. node9 pins each plugin root by content hash (`loading.skill-tamper`,
// `node9 skill-pin`); a root with no pin is loaded unverified. The package
// check (`loading.malicious-package`) is the other door into the supply chain.

/** Installed plugin roots and which of them have a pin. Exported for tests. */
export function pluginPinState(home: string): { roots: string[]; unpinned: string[] } {
  const roots = defaultSkillRoots(undefined, home);
  const pins = readSkillPinsSafe();
  const pinned = pins.ok ? pins.pins.roots : {};
  return { roots, unpinned: roots.filter((r) => !pinned[getRootKey(r)]) };
}

function pluginsAndPackages(ctx: CheckContext, home: string): Finding[] {
  const findings: Finding[] = [];
  const config = getConfig(ctx.cwd);
  const settings = catalogSettingsFrom(config.settings, config.policy);
  const { roots, unpinned } = pluginPinState(home);
  const tamper = checkValue(settings, 'loading.skill-tamper');
  if (roots.length > 0 && tamper === 'off') {
    findings.push({
      category: 'Supply chain',
      severity: 'medium',
      title: `${roots.length} installed plugin${roots.length === 1 ? '' : 's'} load${roots.length === 1 ? 's' : ''} unverified`,
      what: 'Plugins and skills the agent loads are code that runs with its rights, and no content hash is kept for them.',
      why: 'The check loading.skill-tamper is off, so node9 does not pin them.',
      who: 'An update or a tampered file runs with the agent on the next session, unnoticed.',
      detail: roots.slice(0, 6).map((r) => (r.startsWith(home) ? '~' + r.slice(home.length) : r)),
      owner: 'node9',
      fix: 'Set loading.skill-tamper to block (the Checks page, or `checks.loading.skill-tamper` in the config file); node9 pins each plugin the first time it loads.',
    });
  } else if (unpinned.length > 0) {
    findings.push({
      category: 'Supply chain',
      severity: 'medium',
      title: `${unpinned.length} of ${roots.length} installed plugin${roots.length === 1 ? '' : 's'} ${unpinned.length === 1 ? 'has' : 'have'} no pin yet`,
      what: 'A plugin the agent can load has no recorded content hash yet.',
      why: 'node9 pins a plugin the first time it loads; these have not loaded since pinning was turned on.',
      who: 'Until the first load, a changed file in one of them is not noticed.',
      detail: unpinned
        .slice(0, 6)
        .map((r) => (r.startsWith(home) ? '~' + r.slice(home.length) : r)),
      owner: 'node9',
      fix: 'Run `node9 skill pin list` to see the pins; the next session that loads a plugin pins it.',
    });
  }
  const pkg = checkValue(settings, 'loading.malicious-package');
  if (pkg === 'off') {
    findings.push({
      category: 'Supply chain',
      severity: 'medium',
      title: 'Package installs are not checked against the malicious-package index',
      what: 'An install of a package the index flags goes through unnoticed.',
      why: 'The check loading.malicious-package is off.',
      who: "A typosquat or a compromised release installs with the agent's rights.",
      detail: [],
      owner: 'node9',
      fix: 'Set loading.malicious-package to block (the Checks page, or `checks.loading.malicious-package` in the config file).',
    });
  }
  return findings;
}
