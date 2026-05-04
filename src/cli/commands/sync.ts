// src/cli/commands/sync.ts
// Registered as `node9 policy` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import { runCloudSync, getCloudSyncStatus, getCloudRules } from '../../daemon/sync';

export function registerSyncCommand(program: Command): void {
  const policy = program.command('policy').description('Manage cloud policy rules');

  policy
    .command('sync')
    .description('Sync cloud policy rules to local cache (~/.node9/rules-cache.json)')
    .action(async () => {
      process.stdout.write(chalk.cyan('Syncing cloud policy rules…'));
      const result = await runCloudSync();

      process.stdout.write('\n');
      if (!result.ok) {
        console.error(chalk.red(`✗ ${result.reason}`));
        process.exit(1);
      }

      // Differentiate 304 (server says "no changes since last sync, your
      // cache is fresh") from a real fetch. Without this, a user with a
      // hot cache who runs `policy sync` repeatedly sees "Synced 0 rules"
      // even when they have N rules cached — looks like a bug.
      if (result.unchanged) {
        console.log(
          chalk.green(
            `✓ Already up to date — ${result.rules} rule${result.rules === 1 ? '' : 's'} cached`
          )
        );
        console.log(chalk.gray(`  Cached at: ${result.fetchedAt}`));
        console.log(chalk.gray(`  Server returned 304 (no changes since last sync)`));
      } else {
        console.log(
          chalk.green(`✓ Synced ${result.rules} rule${result.rules === 1 ? '' : 's'} from cloud`)
        );
        console.log(chalk.gray(`  Cached at: ${result.fetchedAt}`));
        console.log(chalk.gray(`  File: ~/.node9/rules-cache.json`));
      }
    });

  policy
    .command('show')
    .description('List all cloud policy rules in the local cache')
    .action(() => {
      const status = getCloudSyncStatus();
      if (!status.cached) {
        console.log(chalk.yellow('\n  No cloud rules cached — run: node9 policy sync\n'));
        return;
      }

      const rules = getCloudRules() ?? [];
      const age = Math.round((Date.now() - new Date(status.fetchedAt).getTime()) / 60_000);
      console.log(
        chalk.bold(`\n  Cloud policy rules`) +
          chalk.gray(
            ` (${rules.length} rule${rules.length === 1 ? '' : 's'}, synced ${age}m ago)\n`
          )
      );

      if (rules.length === 0) {
        console.log(chalk.gray('  No rules defined in cloud policy.\n'));
        return;
      }

      for (const rule of rules) {
        const r = rule as Record<string, unknown>;
        const verdictColor =
          r.verdict === 'block' ? chalk.red : r.verdict === 'allow' ? chalk.green : chalk.yellow;
        console.log(
          `  ${verdictColor(
            String(r.verdict ?? 'unknown')
              .toUpperCase()
              .padEnd(6)
          )}  ${chalk.white(String(r.name ?? '(unnamed)'))}`
        );
        if (r.reason) console.log(chalk.gray(`           ${String(r.reason)}`));
      }
      console.log('');
    });

  policy
    .command('status')
    .description('Show current cloud policy cache status')
    .action(() => {
      const s = getCloudSyncStatus();
      if (!s.cached) {
        console.log(chalk.yellow('\n  No cache yet — run: node9 policy sync\n'));
        return;
      }
      const age = Math.round((Date.now() - new Date(s.fetchedAt).getTime()) / 60_000);
      console.log(`\n  Rules   : ${chalk.green(String(s.rules))} cloud rules loaded`);
      console.log(
        `  Synced  : ${chalk.gray(`${age} minute${age === 1 ? '' : 's'} ago`)} (${s.fetchedAt})`
      );
      if (s.workspaceId) {
        console.log(`  Workspace: ${chalk.gray(s.workspaceId)}`);
      }

      // ── Cloud-pushed runtime flags ──────────────────────────────────
      // Surface these prominently — when an admin flips panic mode or
      // shadow mode in the SaaS UI, the dev's `node9 policy status` is
      // the first place they'll see why their AI's behavior changed.
      if (s.panicMode) {
        console.log(
          `  ${chalk.red.bold('🚨 Panic mode  : ON')}  ` +
            chalk.dim('(every review-verdict becomes block)')
        );
      }
      if (s.shadowMode) {
        console.log(
          `  ${chalk.yellow.bold('👁  Shadow mode : ON')}  ` +
            chalk.dim('(blocks become would-block log entries)')
        );
      }
      if (s.syncIntervalHours) {
        console.log(
          chalk.gray(
            `  Polling : every ${s.syncIntervalHours} hour${s.syncIntervalHours === 1 ? '' : 's'}`
          )
        );
      }
      console.log('');
    });
}
