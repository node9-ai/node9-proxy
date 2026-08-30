// src/cli/commands/trust.ts
// node9 trust add/remove/list — manage the trusted-host allowlist.
// Trusted hosts reduce pipe-chain exfiltration decisions:
//   critical (block) → review   high (review) → allow
import { type Command } from 'commander';
import chalk from 'chalk';
import {
  readTrustedHosts,
  addTrustedHost,
  removeTrustedHost,
  normalizeHost,
} from '../../auth/trusted-hosts.js';
import { cliGuardPolicyWrite } from '../../config/keyed-guard';

/** Loose hostname validator: FQDN or wildcard glob (*.example.com). */
function isValidHost(host: string): boolean {
  return /^(\*\.)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(host);
}

export function registerTrustCommand(program: Command): void {
  const trustCmd = program
    .command('trust')
    .description('Manage trusted network hosts (reduces approval friction for known destinations)');

  // ── trust add ──────────────────────────────────────────────────────────────
  trustCmd
    .command('add <host>')
    .description('Add a trusted host — pipe-chain blocks targeting this host are downgraded')
    .action((host: string) => {
      if (!cliGuardPolicyWrite(`trust add ${host}`)) return;
      const normalized = normalizeHost(host.trim());
      if (!isValidHost(normalized)) {
        console.error(
          chalk.red(`\n❌ Invalid host: "${host}"\n`) +
            chalk.gray('   Use an FQDN like api.mycompany.com or *.mycompany.com\n')
        );
        process.exit(1);
      }
      addTrustedHost(normalized);
      console.log(chalk.green(`\n✅ ${normalized} added to trusted hosts.`));
      console.log(
        chalk.gray('   Pipe-chain blocks to this host: critical → review, high → allow\n')
      );
    });

  // ── trust remove ───────────────────────────────────────────────────────────
  trustCmd
    .command('remove <host>')
    .description('Remove a trusted host')
    .action((host: string) => {
      if (!cliGuardPolicyWrite(`trust remove ${host}`)) return;
      const normalized = normalizeHost(host.trim());
      const removed = removeTrustedHost(normalized);
      if (!removed) {
        console.error(chalk.yellow(`\n⚠️  "${normalized}" is not in the trusted hosts list.\n`));
        process.exit(1);
      }
      console.log(chalk.green(`\n✅ ${normalized} removed from trusted hosts.\n`));
    });

  // ── trust list ─────────────────────────────────────────────────────────────
  trustCmd
    .command('list')
    .description('Show all trusted hosts')
    .action(() => {
      const hosts = readTrustedHosts();
      if (hosts.length === 0) {
        console.log(chalk.gray('\n  No trusted hosts configured.\n'));
        console.log(`  Add one: ${chalk.cyan('node9 trust add api.mycompany.com')}\n`);
        return;
      }
      console.log(chalk.bold('\n🔓 Trusted Hosts\n'));
      for (const entry of hosts) {
        const date = new Date(entry.addedAt).toLocaleDateString();
        console.log(`  ${chalk.cyan(entry.host.padEnd(40))} ${chalk.gray(`added ${date}`)}`);
      }
      console.log('');
    });
}
