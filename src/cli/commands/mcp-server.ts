// src/cli/commands/mcp-server.ts
// Registered as `node9 mcp-server` by cli.ts.
import type { Command } from 'commander';
import { runMcpServer } from '../../mcp-server';

export function registerMcpServerCommand(program: Command): void {
  program
    .command('mcp-server')
    .description(
      'Run the Node9 MCP server — exposes node9 tools (undo, rules, …) to Claude, Cursor, and Gemini'
    )
    .action(() => {
      runMcpServer();
    });
}
