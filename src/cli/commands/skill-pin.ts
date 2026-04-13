// src/cli/commands/skill-pin.ts
// CLI for managing skill pins (supply chain & update drift defense).
// Registered under `node9 skill pin` by cli.ts. Mirrors src/cli/commands/mcp-pin.ts.
//
// Subcommands:
//   list                   — show pinned roots, hashes, file counts
//   update <rootKey>       — remove a pin so next session re-pins with current state
//   reset                  — clear all pins AND wipe quarantined session flags
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readSkillPins, readSkillPinsSafe, removePin, clearAllPins } from '../../skill-pin';

function wipeSkillSessions(): void {
  try {
    fs.rmSync(path.join(os.homedir(), '.node9', 'skill-sessions'), {
      recursive: true,
      force: true,
    });
  } catch {
    /* best effort */
  }
}

export function registerSkillPinCommand(program: Command): void {
  const skillCmd = program
    .command('skill')
    .description('Manage skill pinning (supply chain & update drift defense, AST 02 + AST 07)');
  const pinSubCmd = skillCmd.command('pin').description('Manage pinned skill roots');

  pinSubCmd
    .command('list')
    .description('Show all pinned skill roots and their content hashes')
    .action(() => {
      const result = readSkillPinsSafe();
      if (!result.ok) {
        if (result.reason === 'missing') {
          console.log(chalk.gray('\nNo skill roots are pinned yet.'));
          console.log(
            chalk.gray('Pins are created automatically on the first tool call of each session.\n')
          );
          return;
        }
        console.error(chalk.red(`\n❌ Pin file is corrupt: ${result.detail}`));
        console.error(chalk.yellow('   Run: node9 skill pin reset\n'));
        process.exit(1);
      }
      const entries = Object.entries(result.pins.roots);
      if (entries.length === 0) {
        console.log(chalk.gray('\nNo skill roots are pinned yet.\n'));
        return;
      }
      console.log(chalk.bold('\n🔒 Pinned Skill Roots\n'));
      for (const [key, entry] of entries) {
        const missing = entry.exists ? '' : chalk.yellow(' (not present at pin time)');
        console.log(`  ${chalk.cyan(key)}  ${chalk.gray(entry.rootPath)}${missing}`);
        console.log(`    Files (${entry.fileCount})`);
        console.log(`    Hash:  ${chalk.gray(entry.contentHash.slice(0, 16))}...`);
        console.log(`    Pinned: ${chalk.gray(entry.pinnedAt)}\n`);
      }
    });

  pinSubCmd
    .command('update <rootKey>')
    .description('Remove a pin so the next session re-pins with current state')
    .action((rootKey: string) => {
      let pins;
      try {
        pins = readSkillPins();
      } catch {
        console.error(chalk.red('\n❌ Pin file is corrupt.'));
        console.error(chalk.yellow('   Run: node9 skill pin reset\n'));
        process.exit(1);
      }
      if (!pins.roots[rootKey]) {
        console.error(chalk.red(`\n❌ No pin found for root key "${rootKey}"\n`));
        console.error(`Run ${chalk.cyan('node9 skill pin list')} to see pinned roots.\n`);
        process.exit(1);
      }
      const rootPath = pins.roots[rootKey].rootPath;
      removePin(rootKey);
      wipeSkillSessions();
      console.log(chalk.green(`\n🔓 Pin removed for ${chalk.cyan(rootKey)}`));
      console.log(chalk.gray(`   ${rootPath}`));
      console.log(chalk.gray('   Next session will re-pin with current state.\n'));
    });

  pinSubCmd
    .command('reset')
    .description('Clear all skill pins and wipe session verification flags')
    .action(() => {
      const result = readSkillPinsSafe();
      if (!result.ok && result.reason === 'missing') {
        wipeSkillSessions();
        console.log(chalk.gray('\nNo pins to clear.\n'));
        return;
      }
      const count = result.ok ? Object.keys(result.pins.roots).length : '?';
      clearAllPins();
      wipeSkillSessions();
      console.log(chalk.green(`\n🔓 Cleared ${count} skill pin(s).`));
      console.log(chalk.gray('   Next session will re-pin with current state.\n'));
    });
}
