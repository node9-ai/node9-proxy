// src/cli/commands/mcp-gateway.ts
// Registered as `node9 mcp-gateway` by cli.ts.
import type { Command } from 'commander';
import { runMcpGateway } from '../../mcp-gateway';

export function registerMcpGatewayCommand(program: Command): void {
  program
    .command('mcp-gateway')
    .description(
      'Run Node9 as an MCP gateway — intercepts and authorizes tool calls before forwarding to the upstream MCP server'
    )
    .requiredOption(
      '--upstream <command>',
      'The upstream MCP server command to wrap (e.g. "npx -y @modelcontextprotocol/server-filesystem /workspace")'
    )
    .option(
      '--config-name <name>',
      'Friendly server name (the agent-config key) for display/audit — does not affect serverKey'
    )
    .action(async (options: { upstream: string; configName?: string }) => {
      await runMcpGateway(options.upstream, options.configName);
    });
}
