// node9 canary: plant / status / remove / rotate decoy credentials.
// Design: doc/roadmap/active/canary-design.md 4.5. Output never contains a
// decoy value; --json prints only the JSON document.
import type { Command } from 'commander';
import chalk from 'chalk';
import { plantKind, removeKind, statusAll, rotateKind } from '../../canary/plant';
import { ALL_KINDS, isKind } from '../../canary/sites';
import type { CanaryKind } from '../../canary/registry';

function kinds(opts: { kind?: string; all?: boolean }): CanaryKind[] {
  if (opts.kind) {
    if (!isKind(opts.kind))
      throw new Error(`unknown kind "${opts.kind}"; one of ${ALL_KINDS.join(', ')}`);
    return [opts.kind];
  }
  return [...ALL_KINDS];
}

export function registerCanaryCommand(program: Command): void {
  const canary = program
    .command('canary')
    .description(
      'Decoy credentials: a fake key that can only appear in a command if something read the file'
    );

  canary
    .command('plant')
    .description('Create decoy credential files (never modifies an existing file)')
    .option('--kind <kind>', `one of ${ALL_KINDS.join(', ')} (default: all)`)
    .option('--all', 'plant every kind (default)')
    .option('--json', 'machine-readable output')
    .action((opts: { kind?: string; all?: boolean; json?: boolean }) => {
      const results = kinds(opts).map((k) => plantKind(k));
      if (opts.json) {
        console.log(JSON.stringify({ results }, null, 2));
        return;
      }
      for (const r of results) {
        if (r.action === 'created') console.log(chalk.green(`✓ ${r.kind}: created ${r.path}`));
        else if (r.action === 'exists')
          console.log(chalk.dim(`= ${r.kind}: already planted at ${r.path}`));
        else console.log(chalk.yellow(`- ${r.kind}: skipped (${r.reason})`));
      }
      console.log(
        chalk.dim(
          '\nIf a decoy ever appears in an agent command, node9 blocks it and tells you which file was read.'
        )
      );
    });

  canary
    .command('status')
    .description('Show which decoys are planted and whether the files are still on disk')
    .option('--json', 'machine-readable output')
    .action((opts: { json?: boolean }) => {
      const sites = statusAll();
      if (opts.json) {
        console.log(JSON.stringify({ sites }, null, 2));
        return;
      }
      for (const s of sites) {
        const mark =
          s.state === 'planted'
            ? chalk.green('planted')
            : s.state === 'missing'
              ? chalk.red('missing')
              : chalk.dim('absent');
        console.log(`${s.kind.padEnd(12)} ${mark}${s.path ? '  ' + s.path : ''}`);
      }
    });

  canary
    .command('remove')
    .description('Delete decoy files node9 created (refuses if a file changed since)')
    .option('--kind <kind>', `one of ${ALL_KINDS.join(', ')} (default: all)`)
    .option('--all', 'remove every kind (default)')
    .option('--json', 'machine-readable output')
    .action((opts: { kind?: string; all?: boolean; json?: boolean }) => {
      const results = kinds(opts).map((k) => removeKind(k));
      const refused = results.some((r) => r.action === 'refused');
      if (opts.json) console.log(JSON.stringify({ results }, null, 2));
      else {
        for (const r of results) {
          if (r.action === 'removed')
            console.log(
              chalk.green(
                `✓ ${r.kind}: removed ${r.path}${r.dirRemoved ? ' (and its empty directory)' : ''}`
              )
            );
          else if (r.action === 'already-gone')
            console.log(chalk.dim(`= ${r.kind}: ${r.path} was already gone; record retired`));
          else if (r.action === 'refused') console.log(chalk.red(`✗ ${r.kind}: ${r.reason}`));
          else console.log(chalk.dim(`- ${r.kind}: nothing planted`));
        }
      }
      if (refused) process.exitCode = 1;
    });

  canary
    .command('rotate')
    .description('Remove and re-plant with new values (old values stay recognised as retired)')
    .option('--kind <kind>', `one of ${ALL_KINDS.join(', ')} (default: all)`)
    .option('--all', 'rotate every kind (default)')
    .option('--json', 'machine-readable output')
    .action((opts: { kind?: string; all?: boolean; json?: boolean }) => {
      const results = kinds(opts).map((k) => rotateKind(k));
      const refused = results.some((r) => r.removed.action === 'refused');
      if (opts.json) console.log(JSON.stringify({ results }, null, 2));
      else {
        for (const r of results) {
          if (r.planted)
            console.log(chalk.green(`✓ ${r.planted.kind}: rotated, now at ${r.planted.path}`));
          else console.log(chalk.red(`✗ ${r.removed.kind}: ${r.removed.reason}`));
        }
      }
      if (refused) process.exitCode = 1;
    });
}
