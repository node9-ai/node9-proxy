// src/policy-snapshot/build.ts
// Config mirror (Phase 1b): builds the EFFECTIVE local policy the proxy ships
// to the SaaS so the dashboard can SEE what this machine enforces. Pure +
// exported so the caps + field mapping are testable without the network.
//
// Policy, not secrets: smartRules are regexes/verdicts, the egress allowlist is
// hostnames — the same class of data BlastSnapshot already ships. Arrays are
// capped to mirror the SaaS zod schema (a valid build never gets 400'd);
// smartRuleCount carries the true total so truncation stays honest.

import type { Config } from '../config/index.js';
import type { ShieldOverrides } from '@node9/policy-engine';
import { ENGINE_VERSION } from '@node9/policy-engine';
import type { McpToolsConfig } from '../daemon/mcp-tools.js';
import type { McpStatusEntry } from '../mcp-status.js';
import type { SyncHealth } from '../daemon/sync.js';

const MAX_RULES = 500;
const MAX_EGRESS = 200;
const MAX_MCP_SERVERS = 100;
const MAX_MCP_TOOLS = 200;

export interface PolicySnapshotBody {
  mode: string;
  panicMode: boolean;
  shadowMode: boolean;
  activeShields: string[];
  shieldOverrides: ShieldOverrides;
  smartRuleCount: number;
  smartRules: Array<{
    name?: string;
    tool?: string;
    verdict?: string;
    reason?: string;
  }>;
  egress: { enabled: boolean; mode: string; allow: string[] };
  dlpEnabled: boolean;
  engineVersion: string;
  // SEE-tier MCP inventory (Phase 1): which MCP apps this machine can reach + the
  // tools each exposes. `key` is the pin serverKey (sha256(cmd)[:16]) for a
  // launched server, or a synthetic `cfg:<agent>:<name>` for a governed server
  // that never launched. tool names are bare (from tools/list). Policy, not secrets.
  //   connection: 'connected' | 'stale' | 'pending-launch' | 'unlaunchable'
  //   missingEnv: for 'unlaunchable' — the ${ENV} var NAMES (never values) that
  //     aren't set, so the dashboard can say exactly what to fix.
  mcpServers: Array<{
    key: string;
    name?: string;
    tools: string[];
    toolCount: number;
    status: string;
    connection?: string;
    missingEnv?: string[];
  }>;
  // fleet-ship Step 2: the proxy's own cloud-policy sync health, so the dashboard
  // can show "sync failing" badges. The SaaS schema treats consecutiveFailures as
  // the load-bearing signal; lastErrorAt is stripped by the SaaS schema (.strip()).
  syncHealth?: {
    lastCheckedAt?: string;
    lastChangedAt?: string;
    lastError?: string;
    consecutiveFailures: number;
  };
}

export function buildPolicySnapshot(
  config: Config,
  activeShields: string[],
  overrides: ShieldOverrides,
  mcpTools: McpToolsConfig = {},
  // Merged config-vs-connected status (P2.1). Computed by the CALLER (sync.ts) so
  // build.ts stays a pure builder — it does no inventory/env reads. Empty = the
  // pre-P2 behavior (connected rows only, no connection field, no extra rows).
  statusEntries: McpStatusEntry[] = [],
  // fleet-ship Step 2: the proxy's own sync health. Passed in by the caller
  // (readSyncHealth() in sync.ts) — build.ts imports nothing runtime from sync
  // (sync imports build → circular if reversed). undefined = old call site / omit.
  syncHealth?: SyncHealth
): PolicySnapshotBody {
  const p = config.policy;

  // Index the resolver's entries by serverKey so a connected row can pick up its
  // connection freshness (connected vs stale). First-wins across agents.
  const statusByKey = new Map<string, McpStatusEntry>();
  for (const s of statusEntries) {
    if (s.serverKey && !statusByKey.has(s.serverKey)) statusByKey.set(s.serverKey, s);
  }
  const connectedKeys = new Set(Object.keys(mcpTools));

  // Connected rows = GROUND TRUTH from mcp-tools.json (they launched through the
  // gateway). Unchanged from pre-P2 except the connection tag. Name stays the
  // gateway-derived one; the config-name fix is P2.2 (gateway --config-name).
  const connectedRows = Object.entries(mcpTools)
    .slice(0, MAX_MCP_SERVERS)
    .map(([key, cfg]) => ({
      key,
      ...(cfg.name && { name: cfg.name }),
      tools: cfg.tools.map((t) => t.name).slice(0, MAX_MCP_TOOLS),
      toolCount: cfg.tools.length,
      status: cfg.status,
      // In mcp-tools.json ⇒ it launched ⇒ connected, unless the resolver says stale.
      connection: statusByKey.get(key)?.connection === 'stale' ? 'stale' : 'connected',
    }));

  // Non-connected governed rows (SEE-only): a server node9 governs that never
  // launched (pending-launch) or can't (unlaunchable). tools: [] — so it carries
  // NO governance surface downstream (the FE renders no per-tool selects). Skip a
  // resolvable pending server whose real key is ALREADY connected (avoids a dupe).
  const seenKeys = new Set(connectedKeys);
  // Names of servers that ARE connected (ground truth). Used to suppress a
  // false-positive non-connected row for a server that actually launched but that
  // THIS process couldn't env-resolve to its serverKey — the daemon-env-differs
  // case: the daemon lacks a shell-only ${VAR}, so resolveMcpStatus marks the
  // server 'unlaunchable' even though mcp-tools.json shows it connected. With
  // P2.2, connected rows carry the config name, so a name match reliably means
  // "same server" and we drop the phantom card. (An old, not-yet-rewrapped server
  // whose connected name is still command-derived won't match — it re-wraps away.)
  const connectedNames = new Set(connectedRows.map((r) => r.name).filter((n): n is string => !!n));
  const extraRows: PolicySnapshotBody['mcpServers'] = [];
  for (const s of statusEntries) {
    if (s.connection !== 'pending-launch' && s.connection !== 'unlaunchable') continue;
    if (s.serverKey && connectedKeys.has(s.serverKey)) continue;
    if (s.name && connectedNames.has(s.name)) continue; // actually connected — no phantom row
    const key = s.serverKey ?? `cfg:${s.agent}:${s.name}`;
    if (seenKeys.has(key)) continue; // dedupe (same server wired in two agents, etc.)
    seenKeys.add(key);
    extraRows.push({
      key,
      ...(s.name && { name: s.name }),
      tools: [],
      toolCount: 0,
      status: 'pending',
      connection: s.connection,
      ...(s.missingEnv && s.missingEnv.length > 0 && { missingEnv: s.missingEnv }),
    });
  }

  return {
    mode: config.settings.mode,
    panicMode: config.settings.panicMode === true,
    // The proxy expresses shadow/observe as mode === 'observe' (cloud shadowMode
    // forces it); there's no separate settings flag.
    shadowMode: config.settings.mode === 'observe',
    activeShields,
    shieldOverrides: overrides,
    smartRuleCount: p.smartRules.length,
    smartRules: p.smartRules.slice(0, MAX_RULES).map((r) => ({
      name: r.name,
      tool: r.tool,
      verdict: r.verdict,
      reason: r.reason,
    })),
    egress: {
      enabled: p.egress.enabled,
      mode: p.egress.mode,
      allow: p.egress.allow.slice(0, MAX_EGRESS),
    },
    dlpEnabled: p.dlp.enabled,
    engineVersion: ENGINE_VERSION,
    // Connected rows first so they win the cap; non-connected SEE rows fill the rest.
    mcpServers: [...connectedRows, ...extraRows].slice(0, MAX_MCP_SERVERS),
    // fleet-ship Step 2: ship the proxy's own sync health so the dashboard can
    // derive a "sync failing" badge. Only included when the caller passes it.
    ...(syncHealth && {
      syncHealth: {
        lastCheckedAt: syncHealth.lastCheckedAt,
        lastChangedAt: syncHealth.lastChangedAt,
        lastError: syncHealth.lastError,
        consecutiveFailures: syncHealth.consecutiveFailures,
      },
    }),
  };
}
