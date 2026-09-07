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
import { getConfig, type Config } from '../../config';
import { cliGuardPolicyWrite } from '../../config/keyed-guard';
import { DEFAULT_EGRESS_ALLOWLIST, classifySsrf, normalizeIpLiteral } from '@node9/policy-engine';
import {
  type EgressBlock,
  setEgress,
  addEgressHost,
  addSsrfExemption,
  isValidEgressHost,
  normalizeEgressHost,
} from '../../auth/egress-config';

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

function mutate(action: string, change: Partial<EgressBlock>): boolean {
  if (!cliGuardPolicyWrite(action)) return false;
  return guard(() => setEgress(change));
}

function addHost(list: 'allow' | 'deny', host: string): boolean {
  if (!cliGuardPolicyWrite(`egress ${list} ${host}`)) return false;
  return guard(() => addEgressHost(list, host));
}

function exempt(address: string): boolean {
  if (!cliGuardPolicyWrite(`egress exempt ${address}`)) return false;
  return guard(() => addSsrfExemption(address));
}

/**
 * The SSRF floor, stated before the allow/deny lists: strongest first. Until
 * this block existed the floor blocked and no screen said it was there, so a
 * user only met it as a surprise at the moment of a block.
 *
 * The exemption list printed here is the EFFECTIVE one (getConfig has already
 * dropped an entry that names a protected address), so a user who typed one
 * sees that it is not in force.
 */
function showFloor(e: Config['policy']['egress'], policySource: string): void {
  console.log(chalk.gray('\n  Protected addresses'));
  console.log(
    chalk.gray(
      '    always blocked: cloud metadata, link-local, multicast — no setting releases these'
    )
  );
  const strict = e.ssrfStrict === true;
  const by =
    policySource === 'workspace' ? 'workspace (app.node9.ai)' : 'this machine (config.json)';
  console.log(
    `    Internal addresses:  ${strict ? chalk.green('on') : chalk.yellow('off')}` +
      chalk.gray(
        strict
          ? '  loopback and 10/172.16/192.168 are blocked too'
          : '  loopback and 10/172.16/192.168 are reachable'
      )
  );
  console.log(chalk.gray(`    set by: ${by}`));
  const exemptions = e.ssrfAllow ?? [];
  console.log(chalk.gray(`    Exemptions: ${exemptions.length ? exemptions.join(', ') : 'none'}`));
}

function showStatus(): void {
  const cfg = getConfig();
  const e = cfg.policy.egress;
  const state = !e.enabled
    ? chalk.red('OFF — your agent can reach any host, except the protected ones below')
    : e.mode === 'block'
      ? chalk.green('LOCKED (block) — unknown hosts are denied')
      : chalk.yellow('WATCHING (review) — unknown hosts prompt you');
  console.log(chalk.cyan.bold('\n🌐 Egress control'));
  console.log('  State: ' + state);
  if (cfg.policySource === 'workspace') {
    console.log(
      chalk.gray('  Source: workspace config (app.node9.ai) — local egress settings are ignored')
    );
  }
  console.log(
    chalk.gray(
      `  ${DEFAULT_EGRESS_ALLOWLIST.length} common dev/LLM hosts are always allowed (github, npm, pypi, anthropic, …).`
    )
  );
  showFloor(e, cfg.policySource);
  if (e.allow.length) console.log('\n  Your allow: ' + e.allow.join(', '));
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
      if (!mutate('egress watch', { enabled: true, mode: 'review' })) return;
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
      if (!mutate('egress lock', { enabled: true, mode: 'block' })) return;
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
      if (!mutate('egress off', { enabled: false })) return;
      console.log(
        chalk.yellow('\n✓ Egress control is off — the agent can reach any host again.\n')
      );
    });

  // `node9 egress` with no subcommand → status.
  egress
    .command('strict <on|off>')
    .description('Also block loopback and private ranges (the strict SSRF tier)')
    .action((value: string) => {
      const v = value.trim().toLowerCase();
      if (v !== 'on' && v !== 'off') {
        console.error(chalk.red(`\n  ✗ Expected "on" or "off", got "${value}".\n`));
        process.exitCode = 1;
        return;
      }
      if (!mutate(`egress strict ${v}`, { ssrfStrict: v === 'on' })) return;
      console.log(
        v === 'on'
          ? chalk.green('\n  ✓ Strict tier on — loopback and private ranges are blocked.\n')
          : chalk.yellow('\n  ✓ Strict tier off — loopback and private ranges are reachable.\n')
      );
    });

  egress
    .command('exempt <address>')
    .description('Let one address through the floor (a mesh network or a VPN range)')
    .action((address: string) => {
      const a = normalizeEgressHost(address);
      // An exemption names an address or a host the floor can classify. Reject
      // anything that is neither, rather than writing a line that can never match.
      if (!normalizeIpLiteral(a) && !isValidEgressHost(a)) {
        console.error(chalk.red(`\n  ✗ "${address}" is not an address or a hostname.\n`));
        process.exitCode = 1;
        return;
      }
      if (!exempt(a)) return;
      const m = classifySsrf(a);
      console.log(chalk.green(`\n  ✓ ${a} is exempt from the floor.`));
      if (!m)
        console.log(
          chalk.gray('    Note: this address is not on the floor anyway — nothing changes.\n')
        );
      else console.log('');
    });

  // `node9 egress` alone shows status, but `status` is the word a user reaches
  // for, and without this it exited 1 with "too many arguments for 'egress'".
  egress.command('status').description('Show the current egress state').action(showStatus);

  egress.action(showStatus);
}
