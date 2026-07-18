// src/mcp-server/index.ts
// Node9 MCP Server — exposes node9 capabilities (undo, rules, …) as MCP tools
// over stdio (newline-delimited JSON-RPC 2.0).
//
// Architecture:
//   Claude / Cursor / Gemini (MCP client)
//     ↓ stdin/stdout
//   Node9 MCP Server  ← this file
//     ↓ direct function calls
//   node9 internals (undo.ts, config, …)
import readline from 'readline';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { getSnapshotHistory, applyUndo } from '../undo';
import { classifyDecision, decisionTag } from '../audit/decision';
import { getConfig, checkPause } from '../core';
import { isDaemonRunning } from '../auth/daemon';
import {
  listShields,
  readActiveShields,
  writeActiveShields,
  resolveShieldName,
  getShield,
} from '../shields';
import {
  type EgressMode,
  getEgress,
  setEgress,
  addEgressHost,
  normalizeEgressHost,
  isValidEgressHost,
} from '../auth/egress-config';
import { DEFAULT_EGRESS_ALLOWLIST } from '@node9/policy-engine';

// ── JSON-RPC helpers ──────────────────────────────────────────────────────────

function ok(id: unknown, result: unknown): string {
  return JSON.stringify({ jsonrpc: '2.0', id: id ?? null, result });
}

function err(id: unknown, code: number, message: string): string {
  return JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
}

// ── Tool capability tiers ─────────────────────────────────────────────────────
// node9's threat model is the agent itself, so the MCP surface must never let an
// agent WEAKEN its own governance.
//   weaken   — reduces protection → refused over MCP by default (see runMcpServer)
//   add      — only adds protection / restorative → always allowed
//   readonly — no mutation → always allowed
// IMPORTANT: EVERY tool in TOOLS must be classified here — this is enforced by
// mcp-capability.unit.test.ts (an unlisted tool fails the build). When adding a
// tool, if it can reduce protection in ANY way, mark it 'weaken' — never leave a
// mutating tool unclassified (it would otherwise default to readonly and bypass
// the gate).
export const TOOL_CAPABILITY: Record<string, 'readonly' | 'add' | 'weaken'> = {
  // weaken — gated over MCP
  node9_shield_disable: 'weaken',
  node9_approver_set: 'weaken',
  // NOTE: egress LOOSENING (allow a host / turn egress off) is intentionally NOT
  // exposed over MCP — it has no legitimate agent use case (it's exactly the
  // exfil-exit the egress gate exists to prevent) and would be attack surface
  // even gated. A human loosens egress at the CLI: `node9 egress allow|off`.
  // add / restorative — always allowed
  node9_shield_enable: 'add',
  node9_rule_add: 'add', // already block/review-only — handleRuleAdd rejects "allow"
  node9_undo_revert: 'add', // restorative
  node9_egress_protect: 'add', // enable/strengthen egress (monotonic — never reduces)
  node9_egress_deny: 'add', // add a deny host (deny always wins)
  // readonly
  node9_status: 'readonly',
  node9_config_get: 'readonly',
  node9_policy_get: 'readonly',
  node9_audit_get: 'readonly',
  node9_session: 'readonly',
  node9_scan: 'readonly',
  node9_report: 'readonly',
  node9_posture: 'readonly',
  node9_explain: 'readonly',
  node9_shield_list: 'readonly',
  node9_approver_list: 'readonly',
  node9_undo_list: 'readonly',
  node9_undo_detail: 'readonly',
  node9_egress_status: 'readonly',
};

function capabilityOf(tool: string): 'readonly' | 'add' | 'weaken' {
  return TOOL_CAPABILITY[tool] ?? 'readonly';
}

// ── Tool definitions ──────────────────────────────────────────────────────────

export const TOOLS = [
  {
    name: 'node9_status',
    description:
      'Show the current node9 protection status: mode, daemon state, undo engine, pause state, ' +
      'active shields, and whether agent hooks are wired. Use this to understand what protection ' +
      'is active before doing risky work.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'node9_config_get',
    description:
      'Read the current node9 configuration: security mode, approver channels, timeouts, ' +
      'DLP settings, and the number of active smart rules. Returns the merged config ' +
      '(env > cloud > project > global > defaults).',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'node9_shield_list',
    description:
      'List all available node9 shields and which ones are currently active. ' +
      'Shields are pre-packaged rule sets for specific services (postgres, aws, github, filesystem).',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'node9_shield_enable',
    description:
      'Enable a node9 shield for a specific service. Shields only add protection — they cannot ' +
      'be used to weaken or bypass node9. Use node9_shield_list to see available shield names.',
    inputSchema: {
      type: 'object',
      properties: {
        service: {
          type: 'string',
          description: 'Shield name to enable (e.g. "postgres", "aws", "github", "filesystem").',
        },
      },
      required: ['service'],
    },
  },
  {
    name: 'node9_shield_disable',
    description:
      'Disable a node9 shield. WEAKENING action — refused over MCP by default (a human must run ' +
      '"node9 shield disable <name>" from the CLI). Use node9_shield_list to see active shields.',
    inputSchema: {
      type: 'object',
      properties: {
        service: {
          type: 'string',
          description: 'Shield name to disable (e.g. "postgres", "aws", "github", "filesystem").',
        },
      },
      required: ['service'],
    },
  },
  {
    name: 'node9_approver_list',
    description:
      'List all node9 approver channels and their current enabled/disabled state. ' +
      'Approvers are the channels through which node9 asks a human to approve risky tool calls. ' +
      'Channels: native (OS popup), browser (web UI), cloud (team policy server), terminal (stdin).',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'node9_approver_set',
    description:
      'Enable or disable a specific node9 approver channel in the global config (~/.node9/config.json). ' +
      'Use this to turn individual channels on or off without touching other settings. ' +
      'Channels: native, browser, cloud, terminal. ' +
      'WEAKENING action — refused over MCP by default (a human must run it from the CLI). ' +
      'WARNING: disabling all approvers means node9 cannot prompt for human approval — use with care.',
    inputSchema: {
      type: 'object',
      properties: {
        channel: {
          type: 'string',
          enum: ['native', 'browser', 'cloud', 'terminal'],
          description: 'Approver channel to configure.',
        },
        enabled: {
          type: 'boolean',
          description: 'true to enable the channel, false to disable it.',
        },
      },
      required: ['channel', 'enabled'],
    },
  },
  {
    name: 'node9_undo_list',
    description:
      'List the node9 snapshot history. Each entry shows the git hash, tool that triggered it, ' +
      'a short summary, affected files, working directory, and timestamp. ' +
      'Use this to find a hash before calling node9_undo_revert or node9_undo_detail.',
    inputSchema: {
      type: 'object',
      properties: {
        cwd: {
          type: 'string',
          description:
            'Filter to snapshots for a specific project directory. Omit to show all projects.',
        },
      },
      required: [],
    },
  },
  {
    name: 'node9_undo_detail',
    description:
      'Show the full details of a specific node9 snapshot: unified diff, exact files changed, ' +
      'tool that triggered it, command summary, working directory, and timestamp. ' +
      'Use this to understand exactly what a snapshot contains before deciding to revert.',
    inputSchema: {
      type: 'object',
      properties: {
        hash: {
          type: 'string',
          description: 'The git commit hash (full or 7-char prefix) from node9_undo_list.',
        },
      },
      required: ['hash'],
    },
  },
  {
    name: 'node9_undo_revert',
    description:
      'Revert the working directory to a specific node9 snapshot. ' +
      'Call node9_undo_list first to find the hash you want to restore. ' +
      'WARNING: this overwrites current files — any unsaved work will be lost.',
    inputSchema: {
      type: 'object',
      properties: {
        hash: {
          type: 'string',
          description: 'The full git commit hash from node9_undo_list.',
        },
        cwd: {
          type: 'string',
          description: 'Absolute path to the project directory. Defaults to process.cwd().',
        },
      },
      required: ['hash'],
    },
  },
  {
    name: 'node9_audit_get',
    description:
      'Read recent entries from the node9 audit log (~/.node9/audit.log). Each entry shows ' +
      'timestamp, outcome, tool name, the command, and the rule that fired. Outcomes use the ' +
      'same words as the dashboard: Auto-allowed, Approved, Ran, Blocked, Denied (a human ' +
      'refused), Timed out (nobody answered), Would block (shadow mode let it through), ' +
      'Finding, Info. Use this to review what AI actions were taken, especially refused ones.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Number of recent entries to return (default: 20, max: 100).',
        },
        filter: {
          type: 'string',
          enum: ['all', 'allow', 'deny', 'observe', 'info', 'block'],
          description:
            'Filter by outcome. "deny" covers every refusal (rule block, human denial, ' +
            'timeout); "observe" is shadow-mode would-blocks; "block" is an alias for "deny". ' +
            'Omit or use "all" for every entry.',
        },
      },
      required: [],
    },
  },
  {
    name: 'node9_policy_get',
    description:
      'Show all active smart rules in detail — name, tool, verdict, conditions, and reason. ' +
      'Includes default rules, shield rules, and any custom project rules. ' +
      'Use this to understand exactly what is being blocked or reviewed.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'node9_scan',
    description:
      'Scan all AI agent history (Claude + Gemini) and report what node9 would have blocked or ' +
      'flagged. Shows blocked operations, reviewed commands, credential leaks, and agent spend. ' +
      'Use this to audit past activity and find security gaps before they become incidents.',
    inputSchema: {
      type: 'object',
      properties: {
        drill_down: {
          type: 'boolean',
          description:
            'Show full commands and session IDs for every finding (default: false for a clean summary).',
        },
      },
      required: [],
    },
  },
  {
    name: 'node9_report',
    description:
      'Show an activity and security report: tool call counts, blocks, DLP findings, agent cost, ' +
      'and daily trends for a chosen period. Covers all AI agents (Claude, Gemini, etc.).',
    inputSchema: {
      type: 'object',
      properties: {
        period: {
          type: 'string',
          enum: ['today', '7d', '30d', 'month'],
          description: 'Time period for the report (default: 7d).',
        },
        no_tests: {
          type: 'boolean',
          description: 'Exclude test runner calls (npm test, vitest, pytest…) from stats.',
        },
      },
      required: [],
    },
  },
  {
    name: 'node9_session',
    description:
      'List recent AI agent sessions with per-session summaries: tool calls, cost, modified files, ' +
      'and any blocked operations. Pass a session_id to see the full tool trace for that session.',
    inputSchema: {
      type: 'object',
      properties: {
        detail: {
          type: 'string',
          description:
            'Session ID to show the full tool trace for. Omit to list all recent sessions.',
        },
      },
      required: [],
    },
  },
  {
    name: 'node9_posture',
    description:
      'Run the node9 security posture scorecard for the agent on this host — grades how exposed ' +
      'the machine is to a compromised agent across isolation, egress, secrets-on-disk, supply ' +
      'chain, and privilege, with the #1 risk and a concrete fix for each finding. Read-only.',
    inputSchema: {
      type: 'object',
      properties: {
        agent: {
          type: 'string',
          description: 'Optional label / policy scope for the agent being graded.',
        },
      },
      required: [],
    },
  },
  {
    name: 'node9_explain',
    description:
      'Preview exactly how node9 would evaluate a tool call BEFORE running it — the full ' +
      'allow / review / block waterfall and step-by-step policy trace. Use this to self-check a ' +
      'command (e.g. "git push --force") and see whether it would be allowed, sent for human ' +
      'review, or blocked, and why. Read-only — nothing executes.',
    inputSchema: {
      type: 'object',
      properties: {
        tool: {
          type: 'string',
          description: 'Tool name to evaluate. Defaults to "bash" for plain shell commands.',
        },
        args: {
          type: 'string',
          description:
            'Tool arguments as JSON, or a plain shell command string (e.g. "git push --force").',
        },
      },
      required: [],
    },
  },
  {
    name: 'node9_rule_add',
    description:
      'Add a new protective smart rule to the global node9 config (~/.node9/config.json). ' +
      'Rules can block or send dangerous commands for human review based on regex conditions. ' +
      'IMPORTANT: only "block" and "review" verdicts are permitted — "allow" rules are never ' +
      'accepted because they would weaken node9 security. Rules can only be added, never removed.',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Unique rule name (e.g. "block-drop-prod-db").',
        },
        tool: {
          type: 'string',
          description: 'Tool to match — "bash", "*", or a specific tool name.',
        },
        field: {
          type: 'string',
          description: 'Field to inspect — "command" for bash, "sql" for database tools.',
        },
        pattern: {
          type: 'string',
          description: 'Regex pattern to match against the field.',
        },
        verdict: {
          type: 'string',
          enum: ['block', 'review'],
          description:
            'Action to take when the rule matches. Only "block" or "review" are allowed.',
        },
        reason: {
          type: 'string',
          description: 'Human-readable explanation shown when the rule triggers.',
        },
      },
      required: ['name', 'tool', 'field', 'pattern', 'verdict', 'reason'],
    },
  },
  {
    name: 'node9_egress_status',
    description:
      'Show egress (outbound network) control: whether it is enabled, the mode ' +
      '(off / review / block), and your allow + deny host lists. Common dev/LLM hosts ' +
      '(github, npm, pypi, anthropic, …) are always allowed by a built-in list. ' +
      'Read-only.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'node9_egress_protect',
    description:
      'Turn on egress control (or strengthen it). mode="review" prompts on unknown hosts; ' +
      'mode="block" hard-blocks them. Monotonic — it only ever ADDS protection and never ' +
      'reduces it (a request for review will not downgrade an existing block). Only adds ' +
      'protection, so it is always allowed over MCP.',
    inputSchema: {
      type: 'object',
      properties: {
        mode: {
          type: 'string',
          enum: ['review', 'block'],
          description:
            'Enforcement to apply. "review" = prompt, "block" = deny. Defaults to review.',
        },
      },
      required: [],
    },
  },
  {
    name: 'node9_egress_deny',
    description:
      'Add a host to the egress deny list (deny always wins over allow). Only adds ' +
      'protection, so it is always allowed over MCP. Host is an FQDN or wildcard glob ' +
      '(e.g. evil.com or *.evil.com).',
    inputSchema: {
      type: 'object',
      properties: {
        host: { type: 'string', description: 'Host to deny (FQDN or *.glob).' },
      },
      required: ['host'],
    },
  },
  // Egress LOOSENING (allow a host / turn egress off) is deliberately CLI-only —
  // see the note in TOOL_CAPABILITY. The agent can see and tighten egress over
  // MCP, but never loosen it.
];

// ── Tool handlers ─────────────────────────────────────────────────────────────

function handleStatus(): string {
  const config = getConfig();
  const settings = config.settings;
  const paused = checkPause();
  const daemonUp = isDaemonRunning();
  const activeShields = readActiveShields();

  const lines: string[] = [];

  lines.push(`Mode: ${settings.mode}`);
  lines.push(`Daemon: ${daemonUp ? 'running' : 'stopped'}`);
  lines.push(`Undo engine: ${settings.enableUndo ? 'enabled' : 'disabled'}`);

  if (paused.paused) {
    const until = paused.expiresAt
      ? new Date(paused.expiresAt).toLocaleTimeString()
      : 'indefinitely';
    lines.push(`PAUSED until ${until} — all tool calls currently allowed`);
  } else {
    lines.push(`Pause state: not paused`);
  }

  lines.push(`Active shields: ${activeShields.length > 0 ? activeShields.join(', ') : 'none'}`);
  lines.push(`Smart rules: ${config.policy.smartRules.length} loaded`);
  lines.push(`DLP: ${config.policy.dlp?.enabled !== false ? 'enabled' : 'disabled'}`);

  const projectConfig = path.join(process.cwd(), 'node9.config.json');
  const globalConfig = path.join(os.homedir(), '.node9', 'config.json');
  lines.push(
    `Project config (node9.config.json): ${fs.existsSync(projectConfig) ? 'present' : 'not found'}`
  );
  lines.push(
    `Global config (~/.node9/config.json): ${fs.existsSync(globalConfig) ? 'present' : 'not found'}`
  );

  return lines.join('\n');
}

function handleConfigGet(): string {
  const config = getConfig();
  const s = config.settings;
  const lines: string[] = [
    `mode: ${s.mode}`,
    `enableUndo: ${s.enableUndo}`,
    `flightRecorder: ${s.flightRecorder}`,
    `approvalTimeoutMs: ${s.approvalTimeoutMs}`,
    `approvers:`,
    `  native:   ${s.approvers.native}`,
    `  browser:  ${s.approvers.browser}`,
    `  cloud:    ${s.approvers.cloud}`,
    `  terminal: ${s.approvers.terminal}`,
    `dlp.enabled: ${config.policy.dlp?.enabled !== false}`,
    `dlp.scanIgnoredTools: ${config.policy.dlp?.scanIgnoredTools !== false}`,
    `smartRules: ${config.policy.smartRules.length} active`,
    `sandboxPaths: ${config.policy.sandboxPaths.length > 0 ? config.policy.sandboxPaths.join(', ') : 'none'}`,
  ];
  return lines.join('\n');
}

function handleShieldList(): string {
  const all = listShields();
  const active = new Set(readActiveShields());

  if (all.length === 0) return 'No shields available.';

  const lines = all.map((shield) => {
    const on = active.has(shield.name);
    const ruleCount = shield.smartRules.length;
    return `${on ? '[active]' : '[off]   '} ${shield.name.padEnd(12)} — ${shield.description ?? ''} (${ruleCount} rule${ruleCount === 1 ? '' : 's'})`;
  });

  lines.unshift(`${active.size} of ${all.length} shields active:\n`);
  return lines.join('\n');
}

function handleShieldEnable(args: Record<string, unknown>): string {
  const service = args.service;
  if (typeof service !== 'string' || !service) {
    throw new Error('service is required');
  }
  const name = resolveShieldName(service);
  if (!name) {
    throw new Error(
      `Unknown shield: "${service}". Run node9_shield_list to see available shields.`
    );
  }
  const active = readActiveShields();
  if (active.includes(name)) {
    return `Shield "${name}" is already active.`;
  }
  writeActiveShields([...active, name]);
  const shield = getShield(name)!;
  return `Shield "${name}" enabled — ${shield.smartRules.length} smart rule${shield.smartRules.length === 1 ? '' : 's'} now active.`;
}

function handleShieldDisable(args: Record<string, unknown>): string {
  const service = args.service;
  if (typeof service !== 'string' || !service) {
    throw new Error('service is required');
  }
  const name = resolveShieldName(service);
  if (!name) {
    throw new Error(
      `Unknown shield: "${service}". Run node9_shield_list to see available shields.`
    );
  }
  const active = readActiveShields();
  if (!active.includes(name)) {
    return `Shield "${name}" is not active.`;
  }
  writeActiveShields(active.filter((s) => s !== name));
  return `Shield "${name}" disabled.`;
}

// ── Egress control handlers ───────────────────────────────────────────────────
// Only status/protect/deny are exposed — all read-only or strengthening. Egress
// LOOSENING (allow a host / turn egress off) is deliberately CLI-only and has no
// handler. STATUS reads the merged/effective config (getConfig) so it matches
// the CLI and reflects any project-level override; MUTATIONS go through the
// shared egress-config module, which writes the global ~/.node9/config.json —
// the same file (and merge layer) the `node9 egress` CLI writes.

function handleEgressStatus(): string {
  const e = getConfig().policy.egress;
  const state = !e.enabled
    ? 'OFF — the agent can reach any host'
    : e.mode === 'block'
      ? 'LOCKED (block) — unknown hosts are denied'
      : 'WATCHING (review) — unknown hosts prompt for approval';
  const lines = [
    `Egress control: ${state}`,
    `${DEFAULT_EGRESS_ALLOWLIST.length} common dev/LLM hosts are always allowed (github, npm, pypi, anthropic, …).`,
    `Your allow list: ${e.allow.length ? e.allow.join(', ') : '(none)'}`,
    `Your deny list:  ${e.deny.length ? e.deny.join(', ') : '(none)'}`,
  ];
  return lines.join('\n');
}

function handleEgressProtect(args: Record<string, unknown>): string {
  const rawMode = args.mode;
  if (rawMode !== undefined && rawMode !== 'review' && rawMode !== 'block') {
    throw new Error('mode must be "review" or "block".');
  }
  const requested: EgressMode = (rawMode as EgressMode) ?? 'review';
  const current = getEgress();
  // Monotonic: never downgrade. If already blocking, a "review" request keeps block.
  const mode: EgressMode = current.enabled && current.mode === 'block' ? 'block' : requested;
  setEgress({ enabled: true, mode });
  return mode === 'block'
    ? 'Egress is now LOCKED (block) — unknown hosts are denied. Routine hosts stay allowed.'
    : 'Egress is now WATCHED (review) — unknown hosts prompt for approval.';
}

function handleEgressDeny(args: Record<string, unknown>): string {
  const host = typeof args.host === 'string' ? normalizeEgressHost(args.host) : '';
  if (!isValidEgressHost(host)) {
    throw new Error(
      `Invalid host: "${String(args.host)}". Use an FQDN or *.glob (e.g. *.evil.com).`
    );
  }
  addEgressHost('deny', host);
  return `Denied egress to ${host} (deny always wins over allow).`;
}

// ── Approver config helpers ───────────────────────────────────────────────────

const GLOBAL_CONFIG_PATH = path.join(os.homedir(), '.node9', 'config.json');
const APPROVER_CHANNELS = ['native', 'browser', 'cloud', 'terminal'] as const;
type ApproverChannel = (typeof APPROVER_CHANNELS)[number];

function readGlobalConfigRaw(): Record<string, unknown> {
  try {
    if (fs.existsSync(GLOBAL_CONFIG_PATH)) {
      return JSON.parse(fs.readFileSync(GLOBAL_CONFIG_PATH, 'utf-8')) as Record<string, unknown>;
    }
  } catch {
    // corrupt or missing — start fresh
  }
  return {};
}

function writeGlobalConfigRaw(data: Record<string, unknown>): void {
  const dir = path.dirname(GLOBAL_CONFIG_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(GLOBAL_CONFIG_PATH, JSON.stringify(data, null, 2) + '\n');
}

function handleApproverList(): string {
  const config = getConfig();
  const approvers = config.settings.approvers;
  const lines: string[] = ['Approver channels:\n'];
  for (const ch of APPROVER_CHANNELS) {
    const on = approvers[ch];
    lines.push(`  ${on ? '[enabled] ' : '[disabled]'} ${ch}`);
  }

  const enabledCount = APPROVER_CHANNELS.filter((ch) => approvers[ch]).length;
  if (enabledCount === 0) {
    lines.push('\nWARNING: all approver channels are disabled — node9 cannot prompt for approval.');
  }

  return lines.join('\n');
}

function handleApproverSet(args: Record<string, unknown>): string {
  const channel = args.channel as string | undefined;
  const enabled = args.enabled;

  if (!channel || !APPROVER_CHANNELS.includes(channel as ApproverChannel)) {
    throw new Error(
      `Invalid channel: "${channel}". Must be one of: ${APPROVER_CHANNELS.join(', ')}.`
    );
  }
  if (typeof enabled !== 'boolean') {
    throw new Error('enabled must be a boolean (true or false).');
  }

  const raw = readGlobalConfigRaw();
  const settings = (raw.settings ?? {}) as Record<string, unknown>;
  const approvers = (settings.approvers ?? {}) as Record<string, unknown>;
  approvers[channel] = enabled;
  settings.approvers = approvers;
  raw.settings = settings;
  writeGlobalConfigRaw(raw);

  // Warn if all channels are now disabled
  const currentApprovers = getConfig().settings.approvers;
  const anyEnabled = APPROVER_CHANNELS.some((ch) =>
    ch === channel ? enabled : currentApprovers[ch]
  );
  const suffix = anyEnabled
    ? ''
    : '\nWARNING: all approver channels are now disabled — node9 cannot prompt for approval.';

  return `Approver channel "${channel}" ${enabled ? 'enabled' : 'disabled'} in ~/.node9/config.json.${suffix}`;
}

function handleAuditGet(args: Record<string, unknown>): string {
  const limit = Math.min(typeof args.limit === 'number' ? args.limit : 20, 100);
  const filter = typeof args.filter === 'string' && args.filter !== 'all' ? args.filter : null;
  const auditPath = path.join(os.homedir(), '.node9', 'audit.log');
  if (!fs.existsSync(auditPath)) return 'No audit log found.';

  const rawLines = fs.readFileSync(auditPath, 'utf-8').trim().split('\n').filter(Boolean);

  // `block` is kept as an alias for `deny`: this tool's published schema
  // advertised it, and a client may already be sending it. It matched nothing
  // before — the log writes `deny`, never `block`.
  const wanted = filter === 'block' ? 'deny' : filter;

  // Parse all, filter by outcome if requested, then take the last N
  const parsed: Array<{ raw: string; outcome: string; formatted: string }> = [];
  for (const line of rawLines) {
    try {
      const e = JSON.parse(line) as Record<string, unknown>;
      // classifyDecision is the ONE mapper (audit/decision.ts). This used to be
      // an inline `!== 'block' ? '[allow]'`, which reported every one of the
      // log's `deny` rows as ALLOWED.
      const view = classifyDecision(e.decision, e.checkedBy ?? e.source);
      if (wanted && view.outcome !== wanted) continue;

      // The gate stores `argsPreview` (its args are redacted/hashed); only the
      // PostToolUse hook stores `args`. Reading just `args` left every BLOCKED
      // action with an empty detail column.
      const argsObj = e.args as Record<string, unknown> | undefined;
      let detail = '';
      if (argsObj) {
        const cmd = argsObj.command ?? argsObj.file_path ?? argsObj.path ?? argsObj.sql;
        if (typeof cmd === 'string' && cmd) detail = cmd;
      }
      if (!detail && typeof e.argsPreview === 'string') detail = e.argsPreview;
      detail = detail.replace(/\s+/g, ' ').trim();
      if (detail.length > 80) detail = detail.slice(0, 80) + '…';

      // Name the rule that fired — a refusal the reader can't attribute is
      // half an audit trail.
      const why = typeof e.ruleName === 'string' && e.ruleName ? `  (${e.ruleName})` : '';
      const toolPad = String(e.tool ?? '').padEnd(20);
      const line2 = `${e.ts}  ${decisionTag(view)}  ${toolPad}  ${detail}${why}`;
      parsed.push({ raw: line, outcome: view.outcome, formatted: line2 });
    } catch {
      // An unparseable row is NOT an allow — surface it rather than bury it.
      parsed.push({ raw: line, outcome: 'unknown', formatted: `[? unparseable]  ${line}` });
    }
  }

  const recent = parsed.slice(-limit);
  if (recent.length === 0) {
    return filter ? `No ${wanted} entries found in audit log.` : 'Audit log is empty.';
  }

  const header = filter
    ? `Last ${recent.length} ${String(wanted).toUpperCase()} entries:`
    : `Last ${recent.length} audit entries:`;

  return `${header}\n\n${recent.map((e) => e.formatted).join('\n')}`;
}

function handlePolicyGet(): string {
  const config = getConfig();
  const rules = config.policy.smartRules;
  if (rules.length === 0) return 'No smart rules active.';
  const lines = rules.map((r, i) => {
    const conditions = r.conditions
      .map((c: { field: string; op: string; value?: string }) => `${c.field} ${c.op} "${c.value}"`)
      .join(` ${r.conditionMode ?? 'all'} `);
    return `[${i + 1}] ${r.name ?? '(unnamed)'}  tool:${r.tool}  verdict:${r.verdict}\n    conditions: ${conditions}\n    reason: ${r.reason ?? '—'}`;
  });
  return `${rules.length} active smart rules:\n\n${lines.join('\n\n')}`;
}

function handleRuleAdd(args: Record<string, unknown>): string {
  const name = args.name as string;
  const tool = args.tool as string;
  const field = args.field as string;
  const pattern = args.pattern as string;
  const verdict = args.verdict as string;
  const reason = args.reason as string;

  if (!['block', 'review'].includes(verdict)) {
    throw new Error(
      'verdict must be "block" or "review" — "allow" rules are not permitted as they would weaken node9 security'
    );
  }

  // Validate regex
  try {
    new RegExp(pattern);
  } catch {
    throw new Error(`Invalid regex pattern: ${pattern}`);
  }

  const raw = readGlobalConfigRaw();
  const policy = (raw.policy ?? {}) as Record<string, unknown>;
  const smartRules = (policy.smartRules ?? []) as unknown[];

  // Check for duplicate name
  const existing = smartRules.find(
    (r) => typeof r === 'object' && r !== null && (r as Record<string, unknown>).name === name
  );
  if (existing) throw new Error(`A rule named "${name}" already exists.`);

  smartRules.push({
    name,
    tool,
    conditions: [{ field, op: 'matches', value: pattern }],
    conditionMode: 'all',
    verdict,
    reason,
  });

  policy.smartRules = smartRules;
  raw.policy = policy;
  writeGlobalConfigRaw(raw);

  return `Rule "${name}" added to ~/.node9/config.json — verdict: ${verdict} when ${field} matches "${pattern}"`;
}

function runCliCommand(subArgs: string[]): string {
  const result = spawnSync(process.execPath, [process.argv[1], ...subArgs], {
    encoding: 'utf-8',
    timeout: 60_000,
    // Disable colors — stdout is piped (not a TTY), chalk auto-detects, but be explicit
    env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' },
  });
  if (result.error) throw result.error;
  const out = (result.stdout ?? '').trimEnd();
  if (!out && result.stderr) throw new Error(result.stderr.trimEnd());
  return out || '(no output)';
}

function handleScanMcp(args: Record<string, unknown>): string {
  const cliArgs = ['scan'];
  if (args.drill_down === true) cliArgs.push('--drill-down');
  return runCliCommand(cliArgs);
}

function handleReportMcp(args: Record<string, unknown>): string {
  const cliArgs = ['report'];
  if (typeof args.period === 'string') cliArgs.push('--period', args.period);
  if (args.no_tests === true) cliArgs.push('--no-tests');
  return runCliCommand(cliArgs);
}

function handleSessionMcp(args: Record<string, unknown>): string {
  const cliArgs = ['sessions'];
  if (typeof args.detail === 'string' && args.detail) cliArgs.push('--detail', args.detail);
  return runCliCommand(cliArgs);
}

function handlePostureMcp(args: Record<string, unknown>): string {
  const cliArgs = ['posture'];
  if (typeof args.agent === 'string' && args.agent) cliArgs.push('--agent', args.agent);
  return runCliCommand(cliArgs);
}

function handleExplainMcp(args: Record<string, unknown>): string {
  // tool defaults to "bash" so an agent can pass just a shell command string in `args`.
  const tool = typeof args.tool === 'string' && args.tool ? args.tool : 'bash';
  const cliArgs = ['explain', tool];
  if (typeof args.args === 'string' && args.args) cliArgs.push(args.args);
  return runCliCommand(cliArgs);
}

function handleUndoList(args: Record<string, unknown>): string {
  const cwdFilter = typeof args.cwd === 'string' && args.cwd ? args.cwd : null;
  let history = getSnapshotHistory();
  if (cwdFilter) {
    history = history.filter((e) => e.cwd === cwdFilter);
  }
  if (history.length === 0) {
    const hint = cwdFilter ? ` for cwd: ${cwdFilter}` : '';
    return `No snapshots found${hint}. Node9 captures snapshots automatically before file edits.`;
  }
  const lines = history
    .slice()
    .reverse()
    .map((entry, i) => {
      const date = new Date(entry.timestamp).toLocaleString();
      const files = entry.files?.length ? `${entry.files.length} file(s)` : 'unknown files';
      const summary = entry.argsSummary ? ` — ${entry.argsSummary}` : '';
      return `[${i + 1}] ${entry.hash.slice(0, 7)}  ${date}  ${entry.tool}${summary}  (${files})  cwd: ${entry.cwd}\n    full hash: ${entry.hash}`;
    });
  const header = cwdFilter
    ? `${lines.length} snapshot(s) for ${cwdFilter}:`
    : `${lines.length} snapshot(s) across all projects:`;
  return `${header}\n\n${lines.join('\n\n')}`;
}

function handleUndoDetail(args: Record<string, unknown>): string {
  const hash = args.hash;
  if (typeof hash !== 'string' || !hash) {
    throw new Error('hash is required');
  }
  const history = getSnapshotHistory();
  // Match full hash or 7-char prefix
  const entry = history.find((e) => e.hash === hash || e.hash.startsWith(hash));
  if (!entry) {
    throw new Error(`Snapshot ${hash} not found. Run node9_undo_list to see available snapshots.`);
  }

  const lines: string[] = [];
  lines.push(`Hash:    ${entry.hash}`);
  lines.push(`Tool:    ${entry.tool}`);
  lines.push(`Summary: ${entry.argsSummary || '(none)'}`);
  lines.push(`CWD:     ${entry.cwd}`);
  lines.push(`Time:    ${new Date(entry.timestamp).toLocaleString()}`);
  lines.push(`Files:   ${entry.files?.length ? entry.files.join(', ') : '(none recorded)'}`);

  if (entry.diff) {
    lines.push('');
    lines.push('── Diff ─────────────────────────────────────────────────');
    lines.push(entry.diff);
  } else {
    lines.push('');
    lines.push(
      'No diff available (first snapshot for this project, or snapshot predates diff capture).'
    );
  }

  return lines.join('\n');
}

function handleUndoRevert(args: Record<string, unknown>): string {
  const hash = args.hash;
  if (typeof hash !== 'string' || !hash) {
    throw new Error('hash is required and must be a non-empty string');
  }
  // Basic hash format check — hex chars only, 7-40 length
  if (!/^[0-9a-f]{7,40}$/i.test(hash)) {
    throw new Error(`Invalid hash format: ${hash}`);
  }

  const cwd = typeof args.cwd === 'string' && args.cwd ? args.cwd : process.cwd();

  const success = applyUndo(hash, cwd);
  if (!success) {
    throw new Error(
      `Revert failed for hash ${hash}. The snapshot may not exist for this directory, or git encountered an error.`
    );
  }
  return `Successfully reverted to snapshot ${hash.slice(0, 7)} in ${cwd}.`;
}

// ── Protocol loop ─────────────────────────────────────────────────────────────

// LIFECYCLE GOTCHA: this server is LONG-LIVED — the MCP client (Claude Code,
// Cursor, …) spawns it once and keeps it alive for the session. So new node9 code
// AND config changes (incl. settings.mcpAllowWeakening, read via cached getConfig())
// take effect only when the client RECONNECTS and re-spawns this process.
// Rebuilding node9 or restarting the node9 daemon does NOT reload a running server —
// restart the agent app to pick up changes.
export function runMcpServer(): void {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });

  rl.on('line', (line) => {
    let msg: { jsonrpc?: string; method?: string; id?: unknown; params?: unknown };
    try {
      msg = JSON.parse(line) as typeof msg;
    } catch {
      process.stdout.write(err(null, -32700, 'Parse error') + '\n');
      return;
    }

    const { method, id, params } = msg;

    // initialize — required handshake
    if (method === 'initialize') {
      process.stdout.write(
        ok(id, {
          protocolVersion: '2024-11-05',
          serverInfo: { name: 'node9', version: '1.0.0' },
          capabilities: { tools: {} },
        }) + '\n'
      );
      return;
    }

    // notifications (no id) — acknowledge silently
    if (id === undefined || id === null) {
      return;
    }

    if (method === 'tools/list') {
      process.stdout.write(ok(id, { tools: TOOLS }) + '\n');
      return;
    }

    if (method === 'tools/call') {
      const p = (params ?? {}) as Record<string, unknown>;
      const toolName = p.name as string | undefined;
      const toolArgs = (p.arguments ?? {}) as Record<string, unknown>;

      // Security gate: a WEAKENING tool (shield_disable / approver_set) must never be
      // driven by the agent over MCP by default — that would let a compromised agent
      // disarm its own governor. A human runs these from the CLI; opt in with
      // settings.mcpAllowWeakening to re-enable agent-driven weakening.
      if (capabilityOf(toolName ?? '') === 'weaken') {
        let allowed = false;
        try {
          allowed = getConfig().settings.mcpAllowWeakening === true;
        } catch {
          allowed = false; // config error → fail-closed
        }
        if (!allowed) {
          process.stdout.write(
            err(
              id,
              -32000,
              `${toolName} weakens node9 and is disabled over MCP. A human must run it from the ` +
                `CLI (e.g. "node9 shield disable <name>"), or set "mcpAllowWeakening": true in ` +
                `~/.node9/config.json to allow agent-driven weakening.`
            ) + '\n'
          );
          return;
        }
      }

      try {
        let text: string;
        if (toolName === 'node9_status') {
          text = handleStatus();
        } else if (toolName === 'node9_config_get') {
          text = handleConfigGet();
        } else if (toolName === 'node9_shield_list') {
          text = handleShieldList();
        } else if (toolName === 'node9_shield_enable') {
          text = handleShieldEnable(toolArgs);
        } else if (toolName === 'node9_shield_disable') {
          text = handleShieldDisable(toolArgs);
        } else if (toolName === 'node9_approver_list') {
          text = handleApproverList();
        } else if (toolName === 'node9_approver_set') {
          text = handleApproverSet(toolArgs);
        } else if (toolName === 'node9_undo_list') {
          text = handleUndoList(toolArgs);
        } else if (toolName === 'node9_undo_detail') {
          text = handleUndoDetail(toolArgs);
        } else if (toolName === 'node9_undo_revert') {
          text = handleUndoRevert(toolArgs);
        } else if (toolName === 'node9_audit_get') {
          text = handleAuditGet(toolArgs);
        } else if (toolName === 'node9_policy_get') {
          text = handlePolicyGet();
        } else if (toolName === 'node9_rule_add') {
          text = handleRuleAdd(toolArgs);
        } else if (toolName === 'node9_scan') {
          text = handleScanMcp(toolArgs);
        } else if (toolName === 'node9_report') {
          text = handleReportMcp(toolArgs);
        } else if (toolName === 'node9_session') {
          text = handleSessionMcp(toolArgs);
        } else if (toolName === 'node9_posture') {
          text = handlePostureMcp(toolArgs);
        } else if (toolName === 'node9_explain') {
          text = handleExplainMcp(toolArgs);
        } else if (toolName === 'node9_egress_status') {
          text = handleEgressStatus();
        } else if (toolName === 'node9_egress_protect') {
          text = handleEgressProtect(toolArgs);
        } else if (toolName === 'node9_egress_deny') {
          text = handleEgressDeny(toolArgs);
        } else {
          process.stdout.write(err(id, -32601, `Unknown tool: ${toolName}`) + '\n');
          return;
        }
        process.stdout.write(ok(id, { content: [{ type: 'text', text }] }) + '\n');
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        process.stdout.write(
          ok(id, {
            content: [{ type: 'text', text: `Error: ${message}` }],
            isError: true,
          }) + '\n'
        );
      }
      return;
    }

    // Unknown method
    process.stdout.write(err(id, -32601, `Method not found: ${method}`) + '\n');
  });

  rl.on('close', () => {
    process.exit(0);
  });
}
