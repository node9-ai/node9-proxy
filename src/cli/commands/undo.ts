// src/cli/commands/undo.ts
// Registered as `node9 undo` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import { confirm } from '@inquirer/prompts';
import { applyUndo, getSnapshotHistory, computeUndoDiff } from '../../undo';

export function registerUndoCommand(program: Command): void {
  program
    .command('undo')
    .description(
      'Revert files to a pre-AI snapshot. Shows a diff and asks for confirmation before reverting. Use --steps N to go back N actions, --all to include snapshots from other directories.'
    )
    .option('--steps <n>', 'Number of snapshots to go back (default: 1)', '1')
    .option('--all', 'Show snapshots from all directories, not just the current one')
    .action(async (options: { steps: string; all?: boolean }) => {
      const steps = Math.max(1, parseInt(options.steps, 10) || 1);
      const allHistory = getSnapshotHistory();
      const history = options.all ? allHistory : allHistory.filter((s) => s.cwd === process.cwd());

      if (history.length === 0) {
        if (!options.all && allHistory.length > 0) {
          console.log(
            chalk.yellow(
              `\nℹ️  No snapshots found for the current directory (${process.cwd()}).\n` +
                `    Run ${chalk.cyan('node9 undo --all')} to see snapshots from all projects.\n`
            )
          );
        } else {
          console.log(chalk.yellow('\nℹ️  No undo snapshots found.\n'));
        }
        return;
      }

      // Pick the snapshot N steps back (newest is last in array)
      const idx = history.length - steps;
      if (idx < 0) {
        console.log(
          chalk.yellow(
            `\nℹ️  Only ${history.length} snapshot(s) available, cannot go back ${steps}.\n`
          )
        );
        return;
      }
      const snapshot = history[idx];

      const age = Math.round((Date.now() - snapshot.timestamp) / 1000);
      const ageStr =
        age < 60
          ? `${age}s ago`
          : age < 3600
            ? `${Math.round(age / 60)}m ago`
            : `${Math.round(age / 3600)}h ago`;

      console.log(
        chalk.magenta.bold(`\n⏪  Node9 Undo${steps > 1 ? ` (${steps} steps back)` : ''}`)
      );
      console.log(
        chalk.white(
          `    Tool:  ${chalk.cyan(snapshot.tool)}${snapshot.argsSummary ? chalk.gray(' → ' + snapshot.argsSummary) : ''}`
        )
      );
      console.log(chalk.white(`    When:  ${chalk.gray(ageStr)}`));
      console.log(chalk.white(`    Dir:   ${chalk.gray(snapshot.cwd)}`));
      if (steps > 1)
        console.log(
          chalk.yellow(`    Note:  This will also undo the ${steps - 1} action(s) after it.`)
        );
      console.log('');

      // Show diff
      const diff = computeUndoDiff(snapshot.hash, snapshot.cwd);
      if (diff) {
        const lines = diff.split('\n');
        for (const line of lines) {
          if (line.startsWith('+++') || line.startsWith('---')) {
            console.log(chalk.bold(line));
          } else if (line.startsWith('+')) {
            console.log(chalk.green(line));
          } else if (line.startsWith('-')) {
            console.log(chalk.red(line));
          } else if (line.startsWith('@@')) {
            console.log(chalk.cyan(line));
          } else {
            console.log(chalk.gray(line));
          }
        }
        console.log('');
      } else {
        console.log(
          chalk.gray('    (no diff available — working tree may already match snapshot)\n')
        );
      }

      const proceed = await confirm({
        message: `Revert to this snapshot?`,
        default: false,
      });

      if (proceed) {
        if (applyUndo(snapshot.hash, snapshot.cwd)) {
          console.log(chalk.green('\n✅ Reverted successfully.\n'));
        } else {
          console.error(chalk.red('\n❌ Undo failed. Ensure you are in a Git repository.\n'));
        }
      } else {
        console.log(chalk.gray('\nCancelled.\n'));
      }
    });
}
