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
import { getSnapshotHistory, applyUndo } from '../undo';

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
        if (toolName === 'node9_undo_list') {
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
