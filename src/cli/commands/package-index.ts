// src/cli/commands/package-index.ts
// Registered as `node9 package-index` by cli.ts.
//
// The local OSV malicious-package index behind the package check
// (src/supply-chain). The daemon keeps it fresh on its own; this command shows
// its state and runs a sync on demand (first install, or after a long offline
// stretch).
import type { Command } from 'commander';
import chalk from 'chalk';
import { readMeta } from '../../supply-chain/osv-index';
import { ECOSYSTEMS, syncOsvIndex } from '../../supply-chain/osv-sync';

export function registerPackageIndexCommand(program: Command): void {
  const cmd = program
    .command('package-index')
    .description('Local OSV malicious-package index used to check installs before they run');

  cmd
    .command('status')
    .description('Show when each ecosystem was last synced and how many records it holds')
    .action(() => {
      for (const eco of ECOSYSTEMS) {
        const meta = readMeta(eco);
        if (!meta) {
          console.log(`${eco.padEnd(5)}  ${chalk.yellow('not synced')}`);
          continue;
        }
        console.log(
          `${eco.padEnd(5)}  ${meta.records} records  synced ${meta.syncedAt} (${meta.mode})`
        );
      }
    });

  cmd
    .command('sync')
    .description('Download or update the index now')
    .option('--full', 'rebuild from the full archive instead of applying changes')
    .action(async (opts: { full?: boolean }) => {
      const results = await syncOsvIndex({ forceFull: opts.full === true });
      let failed = false;
      for (const r of results) {
        if (r.error) {
          failed = true;
          console.error(`${r.ecosystem.padEnd(5)}  ${chalk.red('failed')}: ${r.error}`);
        } else {
          console.log(`${r.ecosystem.padEnd(5)}  ${r.mode}: ${r.records} records`);
        }
      }
      process.exitCode = failed ? 1 : 0;
    });
}
