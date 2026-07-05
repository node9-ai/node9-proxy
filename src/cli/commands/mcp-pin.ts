// src/cli/commands/mcp-pin.ts
// CLI commands for managing MCP tool definition pins (rug pull defense).
// Registered under `node9 mcp pin` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import {
  readMcpPins,
  readMcpPinsSafe,
  removePin,
  clearAllPins,
  findPinsFilePath,
  promotePin,
  type PinEntry,
} from '../../mcp-pin';
import fs from 'fs';
import { registerMcpGatewayCommand } from './mcp-gateway-cmd';

export function registerMcpPinCommand(program: Command): void {
  const pinCmd = program
    .command('mcp')
    .description('Manage MCP servers — governance (gateway) + tool-definition pinning');

  // `node9 mcp gateway|ungateway|status` — attach to the same `mcp` parent.
  registerMcpGatewayCommand(pinCmd);

  const pinSubCmd = pinCmd.command('pin').description('Manage pinned MCP server tool definitions');

  pinSubCmd
    .command('list')
    .description('Show all pinned MCP servers and their tool definition hashes')
    .action(() => {
      // Merge repo + home per-server (#179): repo wins for keys it has,
      // home fills the gaps. Track which file authored each visible entry
      // so we can annotate output with [repo] / [home] tags.
      const found = findPinsFilePath(process.cwd());
      const homeResult = readMcpPinsSafe();
      let repoEntries: Record<string, PinEntry> = {};
      let repoCorrupt = false;
      if (found.source === 'repo') {
        try {
          const raw = fs.readFileSync(found.path, 'utf-8');
          const parsed = JSON.parse(raw) as { servers?: Record<string, PinEntry> };
          repoEntries = parsed.servers ?? {};
        } catch {
          repoCorrupt = true;
        }
      }
      if (repoCorrupt) {
        console.error(chalk.red(`\n❌ Repo pin file at ${found.path} is corrupt or unreadable.`));
        process.exit(1);
      }
      if (!homeResult.ok && homeResult.reason === 'corrupt') {
        console.error(chalk.red(`\n❌ Home pin file is corrupt: ${homeResult.detail}`));
        console.error(chalk.yellow('   Run: node9 mcp pin reset\n'));
        process.exit(1);
      }
      const homeEntries = homeResult.ok ? homeResult.pins.servers : {};

      // Merge: repo overrides home per-server.
      const merged = new Map<string, { entry: PinEntry; source: 'repo' | 'home' }>();
      for (const [key, entry] of Object.entries(homeEntries)) {
        merged.set(key, { entry, source: 'home' });
      }
      for (const [key, entry] of Object.entries(repoEntries)) {
        merged.set(key, { entry, source: 'repo' });
      }

      if (merged.size === 0) {
        console.log(chalk.gray('\nNo MCP servers are pinned yet.'));
        console.log(
          chalk.gray('Pins are created automatically when the MCP gateway first connects.\n')
        );
        return;
      }

      console.log(chalk.bold('\n🔒 Pinned MCP Servers\n'));
      // Only show source tags when a repo file is in play — keeps the
      // common case (home only) visually identical to before.
      const showSource = found.source === 'repo';
      for (const [key, { entry, source }] of merged) {
        const tag = showSource ? ` ${chalk.yellow(`[${source}]`)}` : '';
        console.log(`  ${chalk.cyan(key)}${tag}  ${chalk.gray(entry.label)}`);
        console.log(`    Tools (${entry.toolCount}): ${chalk.white(entry.toolNames.join(', '))}`);
        console.log(`    Hash:  ${chalk.gray(entry.toolsHash.slice(0, 16))}...`);
        console.log(`    Pinned: ${chalk.gray(entry.pinnedAt)}`);
        console.log('');
      }
      if (showSource) {
        console.log(chalk.gray(`   [repo] entries come from ${found.path}`));
        console.log(chalk.gray('   [home] entries come from ~/.node9/mcp-pins.json\n'));
      }
    });

  pinSubCmd
    .command('promote <serverKey>')
    .description(
      'Copy a pin from ~/.node9/mcp-pins.json into <repo>/.node9/mcp-pins.json so teammates share the same vetted baseline'
    )
    .action((serverKey: string) => {
      try {
        const { repoPath, created } = promotePin(serverKey, process.cwd());
        if (created) {
          console.log(
            chalk.green(
              `\n✅ Created ${repoPath} with the promoted pin for ${chalk.cyan(serverKey)}.`
            )
          );
        } else {
          console.log(chalk.green(`\n✅ Promoted ${chalk.cyan(serverKey)} into ${repoPath}.`));
        }
        console.log(chalk.gray('   Review the change and commit it:'));
        console.log(chalk.cyan(`     git add ${repoPath}`));
        console.log(chalk.cyan(`     git commit -m "pin ${serverKey} (node9)"`));
        console.log('');
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`\n❌ ${msg}\n`));
        process.exit(1);
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
