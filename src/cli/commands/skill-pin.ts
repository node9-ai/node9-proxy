// src/cli/commands/skill-pin.ts
// CLI commands for managing skill pin state (supply chain & update drift defense).
// Registered under `node9 skill pin` by cli.ts.
//
// Mirrors src/cli/commands/mcp-pin.ts with two additions:
//   - `update` shows a per-file diff before re-pinning (accepts --yes for scripts)
//   - `reset` wipes ~/.node9/skill-sessions/ so quarantined sessions don't persist
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { confirm } from '@inquirer/prompts';
import {
  readSkillPins,
  readSkillPinsSafe,
  clearAllPins,
  updatePin,
  hashSkillRoot,
  computePinDiff,
} from '../../skill-pin';

function skillSessionsDir(): string {
  return path.join(os.homedir(), '.node9', 'skill-sessions');
}

function wipeSkillSessions(): void {
  const dir = skillSessionsDir();
  try {
    fs.rmSync(dir, { recursive: true, force: true });
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
        console.log(chalk.gray('\nNo skill roots are pinned yet.'));
        console.log(
          chalk.gray('Pins are created automatically on the first tool call of each session.\n')
        );
        return;
      }

      console.log(chalk.bold('\n🔒 Pinned Skill Roots\n'));
      for (const [key, entry] of entries) {
        const existsMarker = entry.exists ? '' : chalk.yellow(' (not present at pin time)');
        console.log(`  ${chalk.cyan(key)}  ${chalk.gray(entry.rootPath)}${existsMarker}`);
        console.log(`    Files (${entry.fileCount})`);
        console.log(`    Hash:  ${chalk.gray(entry.contentHash.slice(0, 16))}...`);
        console.log(`    Pinned: ${chalk.gray(entry.pinnedAt)}`);
        console.log('');
      }
    });

  pinSubCmd
    .command('update <rootKey>')
    .description('Review the diff for a pinned root and re-pin to the current state')
    .option('-y, --yes', 'Skip confirmation (non-interactive)', false)
    .action(async (rootKey: string, opts: { yes?: boolean }) => {
      let pins;
      try {
        pins = readSkillPins();
      } catch {
        console.error(chalk.red('\n❌ Pin file is corrupt.'));
        console.error(chalk.yellow('   Run: node9 skill pin reset\n'));
        process.exit(1);
      }
      const entry = pins.roots[rootKey];
      if (!entry) {
        console.error(chalk.red(`\n❌ No pin found for root key "${rootKey}"\n`));
        console.error(`Run ${chalk.cyan('node9 skill pin list')} to see pinned roots.\n`);
        process.exit(1);
      }

      const diff = computePinDiff(entry, entry.rootPath);
      console.log(chalk.bold(`\n🔍 Pin review for ${chalk.cyan(rootKey)}`));
      console.log(chalk.gray(`   ${entry.rootPath}\n`));

      if (diff.kind === 'unchanged') {
        console.log(chalk.green('Root is unchanged — no diff to review.'));
        console.log(chalk.gray('Re-pinning anyway will simply refresh the pinnedAt timestamp.\n'));
      } else if (diff.kind === 'appeared') {
        console.log(chalk.yellow('Root is NEW (did not exist at pin time; now present).\n'));
      } else if (diff.kind === 'vanished') {
        console.log(chalk.yellow('Root has VANISHED (present at pin time; now missing).\n'));
      } else {
        console.log(chalk.yellow('Content changed:\n'));
        if (diff.added.length)
          console.log(chalk.green(`  + added (${diff.added.length}):    ${diff.added.join(', ')}`));
        if (diff.removed.length)
          console.log(
            chalk.red(`  - removed (${diff.removed.length}):  ${diff.removed.join(', ')}`)
          );
        if (diff.modified.length)
          console.log(
            chalk.cyan(`  ~ modified (${diff.modified.length}): ${diff.modified.join(', ')}`)
          );
        console.log('');
      }

      let approved = Boolean(opts.yes);
      if (!approved) {
        try {
          approved = await confirm({
            message: 'Approve and re-pin?',
            default: false,
          });
        } catch {
          // Inquirer throws on EOF / Ctrl+C — treat as abort.
          approved = false;
        }
      }

      if (!approved) {
        console.log(chalk.gray('\nAborted — pin unchanged.\n'));
        return;
      }

      const current = hashSkillRoot(entry.rootPath);
      updatePin(
        rootKey,
        entry.rootPath,
        current.contentHash,
        current.exists,
        current.fileCount,
        current.fileManifest
      );
      console.log(chalk.green(`\n🔒 Re-pinned ${chalk.cyan(rootKey)}`));
      console.log(chalk.gray(`   ${entry.rootPath}\n`));
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
      console.log(chalk.gray('   Next session will re-pin with current skill state.\n'));
    });
}
