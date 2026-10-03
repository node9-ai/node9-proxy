// src/cli/commands/config-cmd.ts
// `node9 config <show|migrate>`: the config file's own commands.
//   show     the full effective configuration (lives in shield.ts)
//   migrate  move ~/.node9/config.json to the v2 shape, or --undo

import type { Command } from 'commander';
import chalk from 'chalk';
import { registerConfigShowCommand } from './shield';
import { migrateConfigFile, undoMigration } from '../../config/migrate';
import { globalConfigPath } from '../../config/write';

export function registerConfigCommand(program: Command): void {
  const config = program.command('config').description('Inspect and migrate the config file');
  registerConfigShowCommand(config);

  config
    .command('migrate')
    .description('Move ~/.node9/config.json to the new format (keyed by check), with a backup')
    .option('--dry-run', 'Print what would be written, change nothing')
    .option('--undo', 'Put the newest backup back')
    .action((opts: { dryRun?: boolean; undo?: boolean }) => {
      if (opts.undo) {
        const r = undoMigration();
        if (!r) {
          console.error(chalk.yellow(`\n  No backup of ${globalConfigPath()} to restore.\n`));
          process.exitCode = 1;
          return;
        }
        console.error(chalk.green(`\n  ✓ Restored ${globalConfigPath()} from ${r.restored}\n`));
        return;
      }
      const outcome = migrateConfigFile({ dryRun: opts.dryRun });
      switch (outcome.status) {
        case 'no-file':
          console.error(
            chalk.gray(`\n  ${globalConfigPath()} does not exist; nothing to migrate.\n`)
          );
          return;
        case 'already-v2':
          console.error(chalk.gray(`\n  ${globalConfigPath()} is already in the new format.\n`));
          return;
        case 'dry-run':
          console.error(chalk.bold('\n  Would write:\n'));
          console.log(JSON.stringify(outcome.wouldWrite, null, 2));
          return;
        case 'migrated':
          console.error(chalk.green(`\n  ✓ ${globalConfigPath()} moved to the new format.`));
          console.error(chalk.gray(`    Backup: ${outcome.backup}`));
          console.error(chalk.gray('    Undo:   node9 config migrate --undo'));
          console.error(chalk.gray('    See:    node9 checks\n'));
          return;
        case 'failed':
          console.error(chalk.red(`\n  ✗ Migration failed: ${outcome.error}\n`));
          process.exitCode = 1;
          return;
      }
    });
}
