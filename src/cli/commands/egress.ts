// src/cli/commands/egress.ts
// Registered as `node9 egress` by cli.ts. The remediation on-ramp for the
// posture report's "Egress open" finding: a one-command way to turn on egress
// control (a policy, not a shield) and manage the allowlist.
//
// Routine traffic (LLM APIs, package registries, localhost) is allowed by the
// engine's DEFAULT_EGRESS_ALLOWLIST, so turning egress on doesn't break a
// normal agent — only genuinely-unknown hosts get prompted (watch) or blocked
// (lock). See doc/roadmap/active/posture-egress-onramp-design.md.

import type { Command } from 'commander';
import chalk from 'chalk';
import { getConfig } from '../../config';
import { DEFAULT_EGRESS_ALLOWLIST } from '@node9/policy-engine';
import { type EgressBlock, setEgress, addEgressHost } from '../../auth/egress-config';

// Re-exported so existing tests (egress.integration.test.ts) keep importing it
// from here; the implementation now lives in the shared egress-config module
// that the MCP egress tools also use.
export { applyEgress } from '../../auth/egress-config';

/** Run an egress mutation, surfacing a malformed-config refusal cleanly (exit 1). */
function guard(fn: () => void): boolean {
  try {
    fn();
    return true;
  } catch (err) {
    console.error(chalk.red(`\n  ✗ ${(err as Error).message}\n`));
    process.exitCode = 1;
    return false;
  }
}

function mutate(change: Partial<EgressBlock>): boolean {
  return guard(() => setEgress(change));
}

function addHost(list: 'allow' | 'deny', host: string): boolean {
  return guard(() => addEgressHost(list, host));
}

function showStatus(): void {
  const e = getConfig().policy.egress;
  const state = !e.enabled
    ? chalk.red('OFF — your agent can reach any host')
    : e.mode === 'block'
      ? chalk.green('LOCKED (block) — unknown hosts are denied')
      : chalk.yellow('WATCHING (review) — unknown hosts prompt you');
  console.log(chalk.cyan.bold('\n🌐 Egress control'));
  console.log('  State: ' + state);
  console.log(
    chalk.gray(
      `  ${DEFAULT_EGRESS_ALLOWLIST.length} common dev/LLM hosts are always allowed (github, npm, pypi, anthropic, …).`
    )
  );
  if (e.allow.length) console.log('  Your allow: ' + e.allow.join(', '));
  if (e.deny.length) console.log('  Your deny:  ' + e.deny.join(', '));
  if (!e.enabled) {
    console.log(chalk.gray('\n  Turn it on:  node9 egress watch   (prompt on unknown hosts)'));
    console.log(chalk.gray('               node9 egress lock    (hard-block unknown hosts)'));
  }
  console.log('');
}

export function registerEgressCommand(program: Command): void {
  const egress = program
    .command('egress')
    .description('Control where your agent can send data (egress allowlist)');

  egress
    .command('watch')
    .description('Prompt before the agent reaches an unknown host (review mode)')
    .action(() => {
      if (!mutate({ enabled: true, mode: 'review' })) return;
      console.log(chalk.green('\n✓ Egress is now watched (review mode).'));
      console.log(
        chalk.gray('  Routine hosts (LLM APIs, package registries, localhost) are allowed.')
      );
      console.log(
        chalk.gray('  An unknown host will prompt you — run `node9 egress lock` to hard-block.\n')
      );
    });

  egress
    .command('lock')
    .description('Block the agent from reaching unknown hosts (block mode)')
    .action(() => {
      if (!mutate({ enabled: true, mode: 'block' })) return;
      console.log(chalk.green('\n✓ Egress is now locked (block mode).'));
      console.log(chalk.gray('  Routine hosts are still allowed; unknown hosts are denied.'));
      console.log(chalk.gray('  Allow a specific host with `node9 egress allow <host>`.\n'));
    });

  egress
    .command('allow <host>')
    .description('Allow an extra host (glob, e.g. *.mycorp.com)')
    .action((host: string) => {
      if (!addHost('allow', host)) return;
      console.log(chalk.green(`\n✓ Allowed egress to ${host}.\n`));
    });

  egress
    .command('deny <host>')
    .description('Block an extra host (deny always wins)')
    .action((host: string) => {
      if (!addHost('deny', host)) return;
      console.log(chalk.green(`\n✓ Denied egress to ${host}.\n`));
    });

  egress
    .command('off')
    .description('Turn egress control off')
    .action(() => {
      if (!mutate({ enabled: false })) return;
      console.log(
        chalk.yellow('\n✓ Egress control is off — the agent can reach any host again.\n')
      );
    });

  // `node9 egress` with no subcommand → status.
  egress.action(showStatus);
}
