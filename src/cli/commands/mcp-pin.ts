// src/cli/commands/mcp-pin.ts
// CLI commands for managing MCP tool definition pins (rug pull defense).
// Registered under `node9 mcp pin` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import { readMcpPins, readMcpPinsSafe, removePin, clearAllPins } from '../../mcp-pin';

export function registerMcpPinCommand(program: Command): void {
  const pinCmd = program
    .command('mcp')
    .description('Manage MCP server tool definition pinning (rug pull defense)');

  const pinSubCmd = pinCmd.command('pin').description('Manage pinned MCP server tool definitions');

  pinSubCmd
    .command('list')
    .description('Show all pinned MCP servers and their tool definition hashes')
    .action(() => {
      const result = readMcpPinsSafe();
      if (!result.ok) {
        if (result.reason === 'missing') {
          console.log(chalk.gray('\nNo MCP servers are pinned yet.'));
          console.log(
            chalk.gray('Pins are created automatically when the MCP gateway first connects.\n')
          );
          return;
        }
        console.error(chalk.red(`\n❌ Pin file is corrupt: ${result.detail}`));
        console.error(chalk.yellow('   Run: node9 mcp pin reset\n'));
        process.exit(1);
      }

      const entries = Object.entries(result.pins.servers);
      if (entries.length === 0) {
        console.log(chalk.gray('\nNo MCP servers are pinned yet.'));
        console.log(
          chalk.gray('Pins are created automatically when the MCP gateway first connects.\n')
        );
        return;
      }

      console.log(chalk.bold('\n🔒 Pinned MCP Servers\n'));
      for (const [key, entry] of entries) {
        console.log(`  ${chalk.cyan(key)}  ${chalk.gray(entry.label)}`);
        console.log(`    Tools (${entry.toolCount}): ${chalk.white(entry.toolNames.join(', '))}`);
        console.log(`    Hash:  ${chalk.gray(entry.toolsHash.slice(0, 16))}...`);
        console.log(`    Pinned: ${chalk.gray(entry.pinnedAt)}`);
        console.log('');
      }
    });

  pinSubCmd
    .command('update <serverKey>')
    .description(
      'Remove a pin so the next gateway connection re-pins with current tool definitions'
    )
    .action((serverKey: string) => {
      let pins;
      try {
        pins = readMcpPins();
      } catch {
        console.error(chalk.red('\n❌ Pin file is corrupt.'));
        console.error(chalk.yellow('   Run: node9 mcp pin reset\n'));
        process.exit(1);
      }
      if (!pins.servers[serverKey]) {
        console.error(chalk.red(`\n❌ No pin found for server key "${serverKey}"\n`));
        console.error(`Run ${chalk.cyan('node9 mcp pin list')} to see pinned servers.\n`);
        process.exit(1);
      }

      const label = pins.servers[serverKey].label;
      removePin(serverKey);
      console.log(chalk.green(`\n🔓 Pin removed for ${chalk.cyan(serverKey)}`));
      console.log(chalk.gray(`   Server: ${label}`));
      console.log(chalk.gray('   Next connection will re-pin with current tool definitions.\n'));
    });

  pinSubCmd
    .command('reset')
    .description('Clear all MCP pins (next connection to each server will re-pin)')
    .action(() => {
      const result = readMcpPinsSafe();
      if (!result.ok && result.reason === 'missing') {
        console.log(chalk.gray('\nNo pins to clear.\n'));
        return;
      }
      const count = result.ok ? Object.keys(result.pins.servers).length : '?'; // corrupt — clear anyway
      clearAllPins();
      console.log(chalk.green(`\n🔓 Cleared ${count} MCP pin(s).`));
      console.log(chalk.gray('   Next connection to each server will re-pin.\n'));
    });
}
