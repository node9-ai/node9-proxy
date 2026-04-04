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
import { listShields, readActiveShields, writeActiveShields, resolveShieldName, getShield } from '../shields';

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
  lines.push(`Project config (node9.config.json): ${fs.existsSync(projectConfig) ? 'present' : 'not found'}`);
  lines.push(`Global config (~/.node9/config.json): ${fs.existsSync(globalConfig) ? 'present' : 'not found'}`);

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
    throw new Error(`Unknown shield: "${service}". Run node9_shield_list to see available shields.`);
  }
  const active = readActiveShields();
  if (active.includes(name)) {
    return `Shield "${name}" is already active.`;
  }
  writeActiveShields([...active, name]);
  const shield = getShield(name)!;
  return `Shield "${name}" enabled — ${shield.smartRules.length} smart rule${shield.smartRules.length === 1 ? '' : 's'} now active.`;
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
        } else if (toolName === 'node9_undo_list') {
          text = handleUndoList();
        } else if (toolName === 'node9_undo_revert') {
          text = handleUndoRevert(toolArgs);
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
