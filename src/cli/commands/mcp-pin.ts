// src/cli/commands/mcp-pin.ts
// CLI commands for managing MCP tool definition pins (rug pull defense).
// Registered under `node9 mcp pin` by cli.ts.
import type { Command } from 'commander';
import readline from 'readline';
import chalk from 'chalk';
import { readMcpPins, getPin, updatePin, clearAllPins, hashToolDefinitions } from '../../mcp-pin';
import { execa } from 'execa';
import { tokenize } from '../../mcp-gateway/index';

export function registerMcpPinCommand(program: Command): void {
  const pinCmd = program
    .command('mcp')
    .description('Manage MCP server tool definition pinning (rug pull defense)');

  const pinSubCmd = pinCmd.command('pin').description('Manage pinned MCP server tool definitions');

  pinSubCmd
    .command('list')
    .description('Show all pinned MCP servers and their tool definition hashes')
    .action(() => {
      const pins = readMcpPins();
      const entries = Object.entries(pins.servers);

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
      'Fetch current tool definitions from upstream, show diff against pinned state, and re-pin after operator approval'
    )
    .option('--yes', 'Skip confirmation prompt and approve immediately')
    .action(async (serverKey: string, opts: { yes?: boolean }) => {
      const oldPin = getPin(serverKey);
      if (!oldPin) {
        console.error(chalk.red(`\n❌ No pin found for server key "${serverKey}"\n`));
        console.error(`Run ${chalk.cyan('node9 mcp pin list')} to see pinned servers.\n`);
        process.exit(1);
      }

      // Fetch current tools from the upstream server
      console.log(chalk.gray(`\nFetching current tool definitions from upstream...`));
      console.log(chalk.gray(`   Server: ${oldPin.label}\n`));

      let newTools: { name: string; description?: string }[];
      try {
        newTools = await fetchToolsFromUpstream(oldPin.label);
      } catch (err) {
        console.error(chalk.red(`\n❌ Failed to fetch tools from upstream: ${String(err)}\n`));
        console.error(chalk.gray('   The upstream server may not be running or accessible.'));
        console.error(chalk.gray('   To force-reset: node9 mcp pin reset\n'));
        process.exit(1);
      }

      const newHash = hashToolDefinitions(newTools);
      const newNames = newTools.map((t) => t.name).sort();

      // Show diff
      console.log(chalk.bold('📋 Tool Definition Changes:\n'));

      const oldSet = new Set(oldPin.toolNames);
      const newSet = new Set(newNames);
      const added = newNames.filter((n) => !oldSet.has(n));
      const removed = oldPin.toolNames.filter((n) => !newSet.has(n));
      const kept = newNames.filter((n) => oldSet.has(n));

      if (added.length > 0) {
        console.log(chalk.green(`  + Added (${added.length}):`));
        for (const name of added) console.log(chalk.green(`      ${name}`));
      }
      if (removed.length > 0) {
        console.log(chalk.red(`  - Removed (${removed.length}):`));
        for (const name of removed) console.log(chalk.red(`      ${name}`));
      }
      if (kept.length > 0) {
        console.log(chalk.gray(`  = Unchanged (${kept.length}): ${kept.join(', ')}`));
      }

      console.log('');
      console.log(`  Old hash: ${chalk.gray(oldPin.toolsHash.slice(0, 16))}...`);
      console.log(`  New hash: ${chalk.gray(newHash.slice(0, 16))}...`);

      if (oldPin.toolsHash === newHash) {
        console.log(chalk.green('\n✅ Tool definitions match — pin is already up to date.\n'));
        return;
      }

      console.log('');

      // Confirm with operator
      if (!opts.yes) {
        const confirmed = await askConfirmation('Accept these changes and update the pin? (y/N) ');
        if (!confirmed) {
          console.log(chalk.yellow('\n⚠️  Pin update cancelled. Session remains quarantined.\n'));
          return;
        }
      }

      // Update the pin with new definitions
      updatePin(serverKey, oldPin.label, newHash, newNames);
      console.log(chalk.green(`\n🔒 Pin updated for ${chalk.cyan(serverKey)}`));
      console.log(chalk.gray(`   Server: ${oldPin.label}`));
      console.log(chalk.gray(`   Tools: ${newNames.length} (was ${oldPin.toolCount})`));
      console.log(chalk.gray('   Restart the MCP gateway session to resume tool calls.\n'));
    });

  pinSubCmd
    .command('reset')
    .description('Clear all MCP pins (next connection to each server will re-pin)')
    .action(() => {
      const pins = readMcpPins();
      const count = Object.keys(pins.servers).length;
      if (count === 0) {
        console.log(chalk.gray('\nNo pins to clear.\n'));
        return;
      }
      clearAllPins();
      console.log(chalk.green(`\n🔓 Cleared ${count} MCP pin(s).`));
      console.log(chalk.gray('   Next connection to each server will re-pin.\n'));
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Ask a yes/no question on the terminal. Returns true if user typed 'y' or 'yes'. */
function askConfirmation(prompt: string): Promise<boolean> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(/^y(es)?$/i.test(answer.trim()));
    });
  });
}

/**
 * Spawn the upstream MCP server, send a tools/list request, and return the tools array.
 * The server is killed after the response is received.
 */
async function fetchToolsFromUpstream(
  upstreamCommand: string
): Promise<{ name: string; description?: string }[]> {
  const commandParts = tokenize(upstreamCommand);
  const cmd = commandParts[0];
  const cmdArgs = commandParts.slice(1);

  let executable = cmd;
  try {
    const { stdout } = await execa('which', [cmd]);
    if (stdout) executable = stdout.trim();
  } catch {}

  const { spawn: spawnChild } = await import('child_process');
  return new Promise((resolve, reject) => {
    const child = spawnChild(executable, cmdArgs, {
      stdio: ['pipe', 'pipe', 'inherit'],
      shell: false,
    });

    const rl = readline.createInterface({ input: child.stdout!, terminal: false });
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error('Timed out waiting for tools/list response (10s)'));
    }, 10_000);

    rl.on('line', (line) => {
      try {
        const msg = JSON.parse(line) as {
          id?: unknown;
          result?: { tools?: { name: string; description?: string }[] };
        };
        if (msg.id === 1 && msg.result?.tools) {
          clearTimeout(timeout);
          rl.close();
          child.kill();
          resolve(msg.result.tools);
        }
      } catch {
        // ignore non-JSON lines
      }
    });

    child.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    child.on('exit', (code) => {
      clearTimeout(timeout);
      if (code !== null && code !== 0) {
        reject(new Error(`Upstream exited with code ${code}`));
      }
    });

    // Send initialize then tools/list
    child.stdin!.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 0,
        method: 'initialize',
        params: { protocolVersion: '2024-11-05', capabilities: {} },
      }) + '\n'
    );
    child.stdin!.write(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) + '\n'
    );
  });
}
