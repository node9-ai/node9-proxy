// src/cli/commands/mcp-gateway-cmd.ts
// `node9 mcp gateway|ungateway|status` — the manual foundation for governing MCP
// servers: route an upstream through `node9 mcp-gateway` (so per-tool app
// permissions apply), list what's governed, and reverse it. The reconcile loop
// (daemon) calls the same engine.
import type { Command } from 'commander';
import chalk from 'chalk';
import { inventoryMcp, toGateway, fromGateway, writeMcpEntry, type McpEntry } from '../../mcp-wrap';

function stateChip(state: McpEntry['state']): string {
  if (state === 'gatewayed') return chalk.green('governed');
  if (state === 'node9-self') return chalk.gray('node9');
  return chalk.yellow('UNGOVERNED');
}

// Resolve which entries a name refers to (optionally scoped to one agent).
function resolve(name: string, agent?: string): McpEntry[] {
  return inventoryMcp().filter((e) => e.name === name && (!agent || e.agent === agent));
}

function wrapEntry(e: McpEntry): void {
  // toGateway on the RAW entry so env/type/… are preserved through the wrap.
  writeMcpEntry(e.mcpFile, e.format, e.name, toGateway(e.raw));
}

export function registerMcpGatewayCommand(mcp: Command): void {
  mcp
    .command('status')
    .description('List every MCP server across your agents + whether node9 governs it')
    .action(() => {
      const inv = inventoryMcp();
      if (inv.length === 0) {
        console.error(chalk.gray('No MCP servers found in any agent config.'));
        return;
      }
      const ungoverned = inv.filter((e) => e.state === 'ungoverned').length;
      for (const e of inv) {
        console.error(`  ${e.agentLabel.padEnd(14)} ${e.name.padEnd(24)} ${stateChip(e.state)}`);
      }
      if (ungoverned > 0) {
        console.error(
          chalk.yellow(
            `\n${ungoverned} ungoverned — run ` +
              chalk.bold('node9 mcp gateway --all') +
              ' to govern.'
          )
        );
      }
    });

  mcp
    .command('gateway [name]')
    .description('Route an ungoverned MCP server through node9 (wrap it). --all for every one.')
    .option('--all', 'wrap every ungoverned server across all agents')
    .option('--agent <id>', 'disambiguate a server name that exists in more than one agent')
    .action((name: string | undefined, opts: { all?: boolean; agent?: string }) => {
      const inv = inventoryMcp();
      let targets: McpEntry[];
      if (opts.all) {
        targets = inv.filter((e) => e.state === 'ungoverned');
      } else if (name) {
        const matches = resolve(name, opts.agent);
        if (matches.length === 0) {
          console.error(chalk.red(`No MCP server named "${name}" found.`));
          process.exitCode = 1;
          return;
        }
        if (matches.length > 1) {
          console.error(
            chalk.red(`"${name}" exists in ${matches.length} agents — pass --agent <id> (`) +
              matches.map((m) => m.agent).join(', ') +
              ').'
          );
          process.exitCode = 1;
          return;
        }
        targets = matches;
      } else {
        console.error(chalk.red('Pass a server name or --all. See `node9 mcp status`.'));
        process.exitCode = 1;
        return;
      }

      const wrappable = targets.filter((e) => e.state === 'ungoverned');
      if (wrappable.length === 0) {
        console.error(chalk.gray('Nothing to do — already governed (or node9-self).'));
        return;
      }
      const agents = new Set<string>();
      for (const e of wrappable) {
        wrapEntry(e);
        agents.add(e.agentLabel);
        console.error(chalk.green(`✓ governed ${e.name}`) + chalk.gray(` (${e.agentLabel})`));
      }
      console.error(
        chalk.gray(`\nBacked up originals to <config>.node9-bak. `) +
          chalk.bold(`Restart ${[...agents].join(', ')}`) +
          chalk.gray(' to activate.')
      );
    });

  mcp
    .command('ungateway <name>')
    .description('Restore an MCP server to its original (un-route it from node9)')
    .option('--agent <id>', 'disambiguate a name in more than one agent')
    .action((name: string, opts: { agent?: string }) => {
      const matches = resolve(name, opts.agent).filter((e) => e.state === 'gatewayed');
      if (matches.length === 0) {
        console.error(chalk.red(`No governed MCP server named "${name}" found.`));
        process.exitCode = 1;
        return;
      }
      if (matches.length > 1) {
        console.error(chalk.red(`"${name}" is governed in multiple agents — pass --agent <id>.`));
        process.exitCode = 1;
        return;
      }
      const e = matches[0];
      const orig = fromGateway(e.raw);
      if (!orig) {
        console.error(chalk.red(`Couldn't parse the original command for "${name}".`));
        process.exitCode = 1;
        return;
      }
      writeMcpEntry(e.mcpFile, e.format, e.name, orig);
      console.error(
        chalk.green(`✓ restored ${e.name}`) +
          chalk.gray(` (${e.agentLabel}) — restart ${e.agentLabel} to apply.`)
      );
    });
}
