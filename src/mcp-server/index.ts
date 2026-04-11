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
import { getSnapshotHistory, applyUndo } from '../undo';
import { getConfig, checkPause } from '../core';
import { isDaemonRunning } from '../auth/daemon';
import {
  listShields,
  readActiveShields,
  writeActiveShields,
  resolveShieldName,
  getShield,
} from '../shields';

// ── JSON-RPC helpers ──────────────────────────────────────────────────────────

function ok(id: unknown, result: unknown): string {
  return JSON.stringify({ jsonrpc: '2.0', id: id ?? null, result });
}

function err(id: unknown, code: number, message: string): string {
  return JSON.stringify({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
}

// ── Tool definitions ──────────────────────────────────────────────────────────

const TOOLS = [
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
    description: 'Disable a node9 shield. Use node9_shield_list to see currently active shields.',
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
      'Use this to find a hash before calling node9_undo_revert.',
    inputSchema: { type: 'object', properties: {}, required: [] },
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
      'Read recent entries from the node9 audit log (~/.node9/audit.log). ' +
      'Each entry shows timestamp, tool name, decision (allow/block/review), and agent. ' +
      'Use this to review what AI actions have been taken recently.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Number of recent entries to return (default: 20, max: 100).',
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
  const auditPath = path.join(os.homedir(), '.node9', 'audit.log');
  if (!fs.existsSync(auditPath)) return 'No audit log found.';
  const lines = fs.readFileSync(auditPath, 'utf-8').trim().split('\n').filter(Boolean);
  const recent = lines.slice(-limit);
  const entries = recent.map((line) => {
    try {
      const e = JSON.parse(line) as Record<string, unknown>;
      return `${e.ts}  ${String(e.tool).padEnd(20)} ${String(e.decision).padEnd(8)} ${e.agent ?? ''}`;
    } catch {
      return line;
    }
  });
  return `Last ${entries.length} audit entries:\n\n${entries.join('\n')}`;
}

function handlePolicyGet(): string {
  const config = getConfig();
  const rules = config.policy.smartRules;
  if (rules.length === 0) return 'No smart rules active.';
  const lines = rules.map((r, i) => {
    const conditions = r.conditions
      .map((c) => `${c.field} ${c.op} "${c.value}"`)
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

function handleUndoList(): string {
  const history = getSnapshotHistory();
  if (history.length === 0) {
    return 'No snapshots found. Node9 captures snapshots automatically before file edits.';
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
  return lines.join('\n\n');
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
          text = handleUndoList();
        } else if (toolName === 'node9_undo_revert') {
          text = handleUndoRevert(toolArgs);
        } else if (toolName === 'node9_audit_get') {
          text = handleAuditGet(toolArgs);
        } else if (toolName === 'node9_policy_get') {
          text = handlePolicyGet();
        } else if (toolName === 'node9_rule_add') {
          text = handleRuleAdd(toolArgs);
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
