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
import {
  readTrustedRecipients,
  addTrustedRecipient,
  removeTrustedRecipient,
} from '../../auth/trusted-recipients.js';

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

  // ── trust recipient (fw#318) ───────────────────────────────────────────────
  // Destinations a send may reach after the session read outside content
  // without being held: an exact address, host or IBAN. A domain belongs in
  // policy.untrustedContent.orgDomains.
  const rec = trustCmd
    .command('recipient')
    .description(
      'Manage trusted recipients (sends to them after reading outside content are not held)'
    );

  rec
    .command('add <value>')
    .description('Trust an address, host or IBAN exactly (x@y.z, api.example, GB..)')
    .action((value: string) => {
      if (!cliGuardPolicyWrite(`trust recipient add ${value}`)) return;
      const stored = addTrustedRecipient(value, 'user');
      if (!stored) {
        console.error(
          chalk.red(`\n❌ Not a destination: "${value}"\n`) +
            chalk.gray('   Use an email address, a hostname or URL, or an IBAN.\n')
        );
        process.exit(1);
      }
      console.log(chalk.green(`\n✅ ${stored} added to trusted recipients.\n`));
    });

  rec
    .command('remove <value>')
    .description('Remove a trusted recipient')
    .action((value: string) => {
      if (!cliGuardPolicyWrite(`trust recipient remove ${value}`)) return;
      if (!removeTrustedRecipient(value)) {
        console.error(chalk.yellow(`\n⚠️  "${value}" is not in the trusted recipients list.\n`));
        process.exit(1);
      }
      console.log(chalk.green(`\n✅ ${value} removed from trusted recipients.\n`));
    });

  rec
    .command('list')
    .description('Show all trusted recipients')
    .action(() => {
      const entries = readTrustedRecipients();
      if (entries.length === 0) {
        console.log(chalk.gray('\n  No trusted recipients.\n'));
        console.log(`  Add one: ${chalk.cyan('node9 trust recipient add partner@example.com')}\n`);
        return;
      }
      console.log(chalk.bold('\n🔓 Trusted Recipients\n'));
      for (const e of entries) {
        const date = new Date(e.addedAt).toLocaleDateString();
        console.log(
          `  ${chalk.cyan(e.value.padEnd(44))} ${chalk.gray(`added ${date} (${e.addedBy})`)}`
        );
      }
      console.log('');
    });
}
