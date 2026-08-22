// src/cli/commands/undo.ts
// Registered as `node9 undo` by cli.ts.
//
// The undo feature is REMOVED. This command survives only to say so: a command
// that vanished would leave `node9 undo` printing "unknown command", which reads
// as a broken install rather than a decision. It also tells the user what the
// feature left on their disk, because node9 does not delete their data for them
// (`npm install -g` runs unattended in CI and Docker, and the store holds copies
// of the user's own code).
//
// Why it went: the snapshot store had no size ceiling. It grew ~19 MB per minute
// of active agent work and took one machine to 378 GB.
import type { Command } from 'commander';
import chalk from 'chalk';
import { findUndoLeftovers, formatLeftovers, cleanupCommand } from '../../utils/undo-leftovers.js';

export function registerUndoCommand(program: Command): void {
  program
    .command('undo')
    .description('Removed — the snapshot store had no size ceiling. Reports leftover files.')
    .action(() => {
      const leftovers = findUndoLeftovers();
      console.log(
        chalk.yellow('\nℹ️  The undo feature has been removed.\n') +
          chalk.gray(
            '    Its snapshot store had no size ceiling — it grew by roughly 19 MB per\n' +
              '    minute of agent work and took one machine to 378 GB. Snapshots are no\n' +
              '    longer taken, and no setting turns them back on.\n'
          ) +
          (leftovers
            ? chalk.gray(
                `\n    ${formatLeftovers(leftovers)} of old snapshots are still on disk.\n` +
                  '    node9 will not delete them for you. To remove them yourself:\n\n'
              ) + chalk.cyan(`      ${cleanupCommand(leftovers)}\n`)
            : '')
      );
    });
}
