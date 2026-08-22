// src/cli/commands/undo.ts
// Registered as `node9 undo` by cli.ts.
//
// The undo feature is REMOVED. This command survives to say so and to clean up:
// a command that vanished would print "unknown command", which reads as a broken
// install rather than a decision. The old flags (--list / --steps / --all) are
// still accepted for the same reason — a user or a script that runs one should
// get an explanation, not a commander parse error.
//
// Exit codes follow one rule: a flag that asked us to DO something exits
// non-zero when it did not happen; a flag that asked a QUESTION exits 0 with the
// answer. So `--steps 2` exits 1 (no revert occurred, and exiting 0 would claim
// otherwise) while `--list` exits 0 (asked, answered: there is nothing).
//
// Why it went: the snapshot store had no size ceiling. It grew ~19 MB per minute
// of active agent work and took one machine to 378 GB.
import type { Command } from 'commander';
import chalk from 'chalk';
import { confirm } from '@inquirer/prompts';
import { undoLeftoverPaths, purgeUndoLeftovers } from '../../utils/undo-leftovers.js';

function removalNotice(): string {
  return (
    chalk.yellow('\nℹ️  The undo feature has been removed.\n') +
    chalk.gray(
      '    Its snapshot store had no size ceiling — it grew by roughly 19 MB per\n' +
        '    minute of agent work and took one machine to 378 GB. Snapshots are no\n' +
        '    longer taken, and no setting turns them back on.\n'
    )
  );
}

function leftoverNotice(paths: string[]): string {
  if (paths.length === 0) return '';
  return (
    chalk.gray('\n    Files the feature left behind are still on disk:\n') +
    paths.map((p) => chalk.gray(`      ${p}\n`)).join('') +
    chalk.gray('\n    node9 does not delete them for you. To remove them:\n') +
    chalk.cyan('      node9 undo --purge\n')
  );
}

async function runPurge(assumeYes: boolean): Promise<void> {
  const paths = undoLeftoverPaths();

  if (paths.length === 0) {
    console.log(chalk.green('\n✅ Nothing to remove — the undo store is already gone.\n'));
    return;
  }

  console.log(chalk.yellow('\n⚠️  This will permanently delete:\n'));
  for (const p of paths) console.log(chalk.gray(`      ${p}`));
  console.log(
    chalk.gray(
      '\n    These hold snapshots of your own source code. Nothing else in\n' +
        '    ~/.node9 is touched (config, audit log and credentials stay).\n'
    )
  );

  if (!assumeYes) {
    // An unattended run must never delete a user's data. `preuninstall` runs
    // node9 without a TTY, and so does CI.
    if (!process.stdin.isTTY) {
      console.error(
        chalk.red('\n  Refusing to delete without confirmation.') +
          chalk.gray('\n  No terminal is attached — re-run with --yes to confirm.\n')
      );
      process.exitCode = 1;
      return;
    }
    const ok = await confirm({ message: 'Delete these files?', default: false });
    if (!ok) {
      console.log(chalk.gray('\n  Skipped — nothing was deleted.\n'));
      return;
    }
  }

  const result = purgeUndoLeftovers();

  for (const p of result.deleted) console.log(chalk.green(`  ✅ removed ${p}`));
  for (const s of result.skipped)
    console.log(chalk.yellow(`  ⚠️  skipped ${s.path} — ${s.reason}`));
  for (const f of result.failed) console.error(chalk.red(`  ❌ ${f.path} — ${f.reason}`));

  if (result.skipped.length > 0 || result.failed.length > 0) {
    console.error(chalk.red('\n  Some files remain — see above.\n'));
    process.exitCode = 1;
  } else {
    console.log(chalk.green('\n  Done.\n'));
  }
}

export function registerUndoCommand(program: Command): void {
  program
    .command('undo')
    .description('Removed — the snapshot store had no size ceiling. Use --purge to clean up.')
    .option('--purge', 'Delete the files the removed feature left on disk')
    .option('--yes', 'Skip the confirmation prompt (required when there is no terminal)')
    .option('--list', 'Removed — kept so an existing script gets an explanation')
    .option('--all', 'Removed — kept so an existing script gets an explanation')
    .option('--steps <n>', 'Removed — kept so an existing script gets an explanation')
    .action(async (options: { purge?: boolean; yes?: boolean; steps?: string }) => {
      if (options.purge) {
        await runPurge(options.yes === true);
        return;
      }

      console.log(removalNotice() + leftoverNotice(undoLeftoverPaths()));

      // `--steps N` asked for a revert. It did not happen, so we do not exit 0.
      if (options.steps !== undefined) process.exitCode = 1;
    });
}
