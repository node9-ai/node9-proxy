// src/cli/commands/undo.ts
// Registered as `node9 undo` by cli.ts.
import path from 'path';
import type { Command } from 'commander';
import chalk from 'chalk';
import { applyUndo, getSnapshotHistory, computeUndoDiff } from '../../undo.js';
import type { SnapshotEntry } from '../../undo.js';
import { runUndoNavigator } from '../../tui/undo-navigator.js';
import { getConfig } from '../../config/index.js';

/**
 * Walks up from startDir until it finds a directory that appears as a snapshot
 * cwd. This lets `node9 undo` work from any subdirectory of a project, the same
 * way `git` finds .git by traversing up.
 */
function findMatchingCwd(startDir: string, history: SnapshotEntry[]): string | null {
  const cwds = new Set(history.map((e) => e.cwd));
  let dir = startDir;
  while (true) {
    if (cwds.has(dir)) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function formatAge(timestamp: number): string {
  const age = Math.round((Date.now() - timestamp) / 1000);
  if (age < 60) return `${age}s ago`;
  if (age < 3600) return `${Math.round(age / 60)}m ago`;
  if (age < 86400) return `${Math.round(age / 3600)}h ago`;
  return `${Math.round(age / 86400)}d ago`;
}

export function registerUndoCommand(program: Command): void {
  program
    .command('undo')
    .description(
      'Browse and restore pre-AI snapshots. Arrow keys to navigate, Enter to restore. ' +
        'Use --steps N to go back N actions non-interactively, --list to print history.'
    )
    .option('--steps <n>', 'Non-interactive: restore N steps back (default: 1)')
    .option('--list', 'Print snapshot history as a table and exit')
    .option('--all', 'Include snapshots from all directories, not just the current one')
    .action(async (options: { steps?: string; list?: boolean; all?: boolean }) => {
      // Distinguish "disabled" from "nothing captured yet": the old message
      // sent users hunting for a broken hook when the feature was simply off.
      if (getConfig().settings.enableUndo === false) {
        console.log(
          chalk.yellow('\nℹ️  Snapshots are disabled, so there is nothing to undo.\n') +
            chalk.gray(
              '    Enable with `"settings": { "enableUndo": true }` in ~/.node9/config.json.\n' +
                '    Off by default while the snapshot store is rebuilt with a size ceiling.\n'
            )
        );
        return;
      }

      const allHistory = getSnapshotHistory();
      const matchedCwd = options.all ? null : findMatchingCwd(process.cwd(), allHistory);
      const history = options.all ? allHistory : allHistory.filter((s) => s.cwd === matchedCwd);

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

      // ── --list mode ─────────────────────────────────────────────────────
      if (options.list) {
        console.log(chalk.magenta.bold('\n⏪  Snapshot History\n'));
        console.log(
          chalk.gray(
            `  ${'#'.padEnd(3)}  ${'File / Command'.padEnd(30)}  ${'Tool'.padEnd(8)}  ${'When'.padEnd(10)}  Dir`
          )
        );
        console.log(chalk.gray('  ' + '─'.repeat(80)));

        // Display newest first
        const display = [...history].reverse();
        let prevTs: number | null = null;
        for (let i = 0; i < display.length; i++) {
          const e = display[i];
          const isGap = prevTs !== null && prevTs - e.timestamp > 60_000;
          if (isGap) console.log(chalk.gray('  ── earlier ──'));
          const label = (e.argsSummary || e.files?.[0] || '—').slice(0, 30).padEnd(30);
          const tool = e.tool.slice(0, 8).padEnd(8);
          const when = formatAge(e.timestamp).padEnd(10);
          const dir = e.cwd.length > 30 ? '…' + e.cwd.slice(-29) : e.cwd;
          console.log(
            chalk.white(
              `  ${String(i + 1).padEnd(3)}  ${label}  ${chalk.cyan(tool)}  ${chalk.gray(when)}  ${chalk.gray(dir)}`
            )
          );
          prevTs = e.timestamp;
        }
        console.log('');
        return;
      }

      // ── --steps mode (non-interactive, backward compat) ─────────────────
      if (options.steps !== undefined) {
        const steps = Math.max(1, parseInt(options.steps, 10) || 1);
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
        const ageStr = formatAge(snapshot.timestamp);

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

        // Show diff: prefer stored diff, fall back to computed
        const diff = snapshot.diff ?? computeUndoDiff(snapshot.hash, snapshot.cwd);
        if (diff) {
          const lines = diff
            .split('\n')
            .filter((l) => !l.startsWith('diff --git') && !l.startsWith('index '));
          for (const line of lines) {
            if (line.startsWith('+++') || line.startsWith('---')) console.log(chalk.bold(line));
            else if (line.startsWith('+')) console.log(chalk.green(line));
            else if (line.startsWith('-')) console.log(chalk.red(line));
            else if (line.startsWith('@@')) console.log(chalk.cyan(line));
            else console.log(chalk.gray(line));
          }
          console.log('');
        } else {
          console.log(
            chalk.gray('    (no diff available — working tree may already match snapshot)\n')
          );
        }

        const { confirm } = await import('@inquirer/prompts');
        const proceed = await confirm({ message: `Revert to this snapshot?`, default: false });
        if (proceed) {
          if (applyUndo(snapshot.hash, snapshot.cwd)) {
            console.log(chalk.green('\n✅ Reverted successfully.\n'));
          } else {
            console.error(chalk.red('\n❌ Undo failed. Ensure you are in a Git repository.\n'));
          }
        } else {
          console.log(chalk.gray('\nCancelled.\n'));
        }
        return;
      }

      // ── Interactive navigator (default) ─────────────────────────────────
      await runUndoNavigator(history);
    });
}
