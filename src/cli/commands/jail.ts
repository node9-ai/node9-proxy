// src/cli/commands/jail.ts
// node9 jail add/list/remove — grow the credential jail in place. Thin actions
// over src/shields/jail.ts (store + user-jail shield regeneration).
import type { Command } from 'commander';
import chalk from 'chalk';
import { readJailPaths, addJailPath, removeJailPath, regenerateUserJail } from '../../shields/jail';
import { appendConfigAudit } from '../../audit';

// Built-in jail coverage (mirrors project-jail.json + the engine's
// SENSITIVE_PATH_RULES). Display-only — always on, not removable.
const BUILTIN_JAIL = [
  '~/.ssh — SSH private keys',
  '~/.aws — AWS credentials',
  '.env files',
  'credential files — credentials.json, .netrc, .npmrc, .docker, .kube, gcloud',
];

export function registerJailCommand(program: Command): void {
  const jail = program
    .command('jail')
    .description('Grow the credential jail — block/review reads of your sensitive paths');

  jail
    .command('add <path>')
    .description('Add a path to the jail (default: block reads; --review to soften)')
    .option('--review', 'Require human approval instead of hard-blocking reads')
    .action((p: string, opts: { review?: boolean }) => {
      const verdict = opts.review ? 'review' : 'block';
      try {
        const paths = addJailPath(p, verdict);
        regenerateUserJail(paths);
        appendConfigAudit({ event: 'jail-add', path: p.trim(), verdict });
      } catch (err) {
        console.error(chalk.red(`\n❌ ${(err as Error).message}\n`));
        process.exit(1);
        return;
      }
      console.log(chalk.green(`\n✅ Jailed ${p} (${verdict}).`));
      console.log(
        chalk.gray(
          `   AI reads of this path now ${verdict === 'block' ? 'BLOCK' : 'require approval'}.`
        )
      );
      console.log(chalk.gray(`   Preview: ${chalk.cyan(`node9 explain bash "cat ${p}"`)}\n`));
    });

  jail
    .command('remove <path>')
    .description('Remove a user-added jail path (built-in paths are not removable)')
    .action((p: string) => {
      let result: { removed: boolean; paths: ReturnType<typeof readJailPaths> };
      try {
        result = removeJailPath(p);
      } catch (err) {
        console.error(chalk.red(`\n❌ ${(err as Error).message}\n`));
        process.exit(1);
        return;
      }
      if (!result.removed) {
        console.error(chalk.yellow(`\nℹ️  "${p}" is not a user-added jail path.\n`));
        console.error(chalk.gray(`   Run ${chalk.cyan('node9 jail list')} to see your paths.\n`));
        process.exit(1);
        return;
      }
      try {
        regenerateUserJail(result.paths);
        appendConfigAudit({ event: 'jail-remove', path: p.trim() });
      } catch (err) {
        console.error(chalk.red(`\n❌ ${(err as Error).message}\n`));
        process.exit(1);
        return;
      }
      console.log(chalk.green(`\n✅ Removed ${p} from the jail.\n`));
    });

  jail
    .command('list')
    .description('Show built-in + user-added jail paths')
    .action(() => {
      console.log(chalk.bold('\n🔒 Credential Jail\n'));
      console.log(chalk.gray('  Built-in (always on, not removable):'));
      for (const b of BUILTIN_JAIL) console.log(`    ${chalk.gray('•')} ${b}`);
      console.log('');

      let user: ReturnType<typeof readJailPaths>;
      try {
        user = readJailPaths();
      } catch (err) {
        console.error(chalk.red(`  ✗ ${(err as Error).message}\n`));
        process.exit(1);
        return;
      }
      if (user.length === 0) {
        console.log(
          chalk.gray('  Your paths: (none) — add one with ') + chalk.cyan('node9 jail add <path>')
        );
      } else {
        console.log(chalk.gray('  Your paths (removable):'));
        for (const u of user) {
          const v = u.verdict === 'block' ? chalk.red('block ') : chalk.yellow('review');
          console.log(`    ${v}  ${chalk.cyan(u.path)}`);
        }
      }
      console.log('');
    });
}
