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
import { getConfig, _resetConfigCache, type Config } from '../../config';
import { cliGuardPolicyWrite } from '../../config/keyed-guard';
import { DEFAULT_EGRESS_ALLOWLIST, classifySsrf, normalizeIpLiteral } from '@node9/policy-engine';
import {
  type EgressBlock,
  setEgress,
  addEgressHost,
  addSsrfExemption,
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
 * How internal addresses are treated. `allowPrivate` and `ssrfStrict` are one
 * axis in sequence — the floor answers first, the policy second — so they get
 * one verb and are ALWAYS written together. A stored pair that contradicts the
 * displayed state is how the next reader gets it wrong.
 *
 * Until B1, `allowPrivate` was the one egress setting with no CLI at all. The
 * cloud could set it (ManagedEgress.allowPrivate, lockable as
 * egressAllowPrivate) and the dashboard had a control, so the only user who
 * could not reach it was the one with nothing else.
 */
export type InternalState = 'allowed' | 'listed' | 'blocked';

const INTERNAL_FIELDS: Record<InternalState, { ssrfStrict: boolean; allowPrivate: boolean }> = {
  allowed: { ssrfStrict: false, allowPrivate: true },
  listed: { ssrfStrict: false, allowPrivate: false },
  blocked: { ssrfStrict: true, allowPrivate: false },
};

const INTERNAL_SAID: Record<InternalState, string> = {
  allowed: 'reachable without listing them',
  listed: 'reachable only if they are on your allowlist',
  blocked: 'blocked',
};

/** The one description per state, shared with the MCP status tool (fw#421 item 4). */
export function describeInternalState(state: InternalState): string {
  return INTERNAL_SAID[state];
}

/** The state a config is in. ssrfStrict wins: the floor answers before the policy. */
export function readInternalState(e: {
  ssrfStrict?: boolean;
  allowPrivate?: boolean;
}): InternalState {
  if (e.ssrfStrict === true) return 'blocked';
  return e.allowPrivate === false ? 'listed' : 'allowed';
}

function setInternal(value: string): void {
  const state = value.trim().toLowerCase() as InternalState;
  if (!(state in INTERNAL_FIELDS)) {
    console.error(
      chalk.red(`\n  ✗ Expected "allowed", "listed" or "blocked", got "${value}".`) +
        chalk.gray(
          '\n    allowed  loopback, 10/172.16/192.168 and CGNAT are reachable (default)\n' +
            '    listed   they are reachable only if you allowlist them\n' +
            '    blocked  they are blocked at the floor\n'
        )
    );
    process.exitCode = 1;
    return;
  }
  if (!mutate(`egress internal ${state}`, INTERNAL_FIELDS[state])) return;
  // The write landed in config.json, which is not the same as the value taking
  // effect: on an org-managed machine the merge replaces it. Read the EFFECTIVE
  // config back and report what is in force, rather than that a file was
  // written. Both fields can be locked independently, so the check covers the
  // resolved STATE, not one boolean.
  _resetConfigCache();
  const effective = readInternalState(getConfig().policy.egress);
  if (effective !== state) {
    console.log(
      chalk.yellow(
        `\n  ⚠ Saved, but not in effect: your workspace sets internal addresses to ` +
          `${effective.toUpperCase()} and that governs this machine.\n` +
          `    Change it in the dashboard, Enforcement → Network.\n`
      )
    );
    return;
  }
  const line = `\n  ✓ Internal addresses: ${state} — loopback, the private ranges and CGNAT are ${INTERNAL_SAID[state]}.\n`;
  console.log(state === 'allowed' ? chalk.yellow(line) : chalk.green(line));
}

/**
 * The SSRF floor, stated before the allow/deny lists: strongest first. Until
 * this block existed the floor blocked and no screen said it was there, so a
 * user only met it as a surprise at the moment of a block.
 *
 * Every line here was rewritten after a code review found three overclaims:
 * the floor only sees SHELL commands (a WebFetch or an MCP fetch tool reaches
 * the address unchecked), CGNAT is blocked by default and was named nowhere,
 * and `node9 pause` lifts the floor along with everything else. A status
 * screen that overstates protection is worse than none.
 *
 * Corrected again 2026-09-21, and this time the text was UNDERstating. Two of
 * those three claims stopped being true the same day they were written:
 *   - `438cd16` (the same date) taught the floor to read a declared URL, so
 *     WebFetch and the MCP fetch tools DO pass it. Measured: WebFetch to the
 *     metadata endpoint is denied.
 *   - CGNAT is NOT in the always-blocked set. It is `hit('cgnat', true)`,
 *     i.e. overridable, and it sits in STRICT_TIERS, i.e. reachable until
 *     `ssrfStrict` is on. Measured: `curl http://100.64.0.5/` is allowed on a
 *     default install, and an exemption releases it.
 * The same two errors were live on four surfaces at once (this one, the MCP
 * tool, the posture row, the dashboard caption), because the fix that made
 * them wrong never came back to the text. A claim that lives in four places
 * needs one wording; this is it, and the other three quote it.
 *
 * The exemption list printed is the EFFECTIVE one (getConfig has already
 * dropped an entry that names a protected address), so a user who typed one
 * sees that it is not in force.
 */
function showFloor(
  e: Config['policy']['egress'],
  ssrfStrictSource: Config['ssrfStrictSource']
): void {
  console.log(
    chalk.gray('\n  Protected addresses') + chalk.gray(' — in shell commands and declared URLs')
  );
  console.log(
    chalk.gray(
      '    always blocked: cloud metadata, link-local, multicast\n' +
        '    no setting releases these, though `node9 pause` suspends all enforcement'
    )
  );
  // The resolved STATE, not two booleans. `on/off` described one of the two
  // fields and left the other unnamed, so a user could not read back what
  // `egress internal` had set.
  const state = readInternalState(e);
  const by =
    ssrfStrictSource === 'workspace'
      ? 'workspace (app.node9.ai)'
      : ssrfStrictSource === 'local'
        ? 'this machine (config.json)'
        : 'the shipped default';
  const STATE_LABEL: Record<InternalState, string> = {
    allowed: 'allowed',
    listed: 'allowlist only',
    blocked: 'blocked',
  };
  console.log(
    `    Internal addresses:  ${
      state === 'blocked' ? chalk.green(STATE_LABEL[state]) : chalk.yellow(STATE_LABEL[state])
    }` + chalk.gray(`  loopback, 10/172.16/192.168 and CGNAT are ${INTERNAL_SAID[state]}`)
  );
  console.log(chalk.gray(`    set by: ${by}`));
  const exemptions = e.ssrfAllow ?? [];
  console.log(chalk.gray(`    Exemptions: ${exemptions.length ? exemptions.join(', ') : 'none'}`));
  console.log(
    chalk.gray(
      '    Covered: shell commands, and tools that declare a URL (WebFetch, an MCP\n' +
        '    fetch tool, browser navigate).\n' +
        '    Not covered: an interpreter one-liner (node -e, python3 -c) hides its\n' +
        '    destination inside a program and does not reach this gate.\n' +
        '    CGNAT (100.64/10) is NOT in the always-blocked set: it is reachable\n' +
        '    until Internal addresses is on, and an exemption can release it.'
    )
  );
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
  showFloor(e, cfg.ssrfStrictSource);
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
    .command('internal <allowed|listed|blocked>')
    .description(
      'How loopback, private ranges and CGNAT are treated: allowed (default), ' +
        'listed (must be on the allowlist), or blocked'
    )
    .action((value: string) => setInternal(value));

  egress
    .command('strict <on|off>')
    .description('Deprecated alias for `egress internal blocked|allowed`')
    .action((value: string) => {
      const v = value.trim().toLowerCase();
      if (v !== 'on' && v !== 'off') {
        console.error(chalk.red(`\n  ✗ Expected "on" or "off", got "${value}".\n`));
        process.exitCode = 1;
        return;
      }
      // `off` must not silently widen past what the user had: from `listed`,
      // turning the tier off means `listed`, not `allowed`. Turning a tier off
      // is not consent to stop requiring the allowlist.
      const state: InternalState =
        v === 'on'
          ? 'blocked'
          : getConfig().policy.egress.allowPrivate === false
            ? 'listed'
            : 'allowed';
      console.log(chalk.gray(`\n  (\`egress strict ${v}\` is now \`egress internal ${state}\`)`));
      setInternal(state);
    });

  egress
    .command('exempt <address>')
    .description('Let an address or a CIDR range through the floor (e.g. 100.64.0.0/10)')
    .action((address: string) => {
      const a = normalizeEgressHost(address);
      // An exemption is compared against a NORMALIZED IP LITERAL, so only an
      // address or a range of them can ever match: an FQDN entry is written
      // dead. The first version accepted one and printed a note, which also
      // put this command at odds with the dashboard editor, where it is
      // refused. The range form was added with B2 so an operator can exempt
      // the mesh-VPN range they use instead of listing peers one at a time.
      const slash = a.indexOf('/');
      const base = slash === -1 ? a : a.slice(0, slash);
      const prefixText = slash === -1 ? null : a.slice(slash + 1);
      if (!normalizeIpLiteral(base) || (prefixText !== null && !/^\d{1,3}$/.test(prefixText))) {
        console.error(
          chalk.red(`\n  ✗ "${address}" is not an address or a range.`) +
            chalk.gray(
              '\n    Exemptions are matched as an address (10.0.0.5) or a CIDR\n' +
                '    range (100.64.0.0/10), never a name.\n'
            )
        );
        process.exitCode = 1;
        return;
      }
      // Refused at the keystroke, for the same reason a bare protected address
      // is: an entry that can never release anything would be listed as in
      // force on every machine and do nothing. A range is judged by its base,
      // the same rule sanitizeSsrfAllow applies at load.
      const m = classifySsrf(base);
      if (m && !m.overridable) {
        console.error(
          chalk.red(`\n  ✗ ${a} cannot be exempted.`) +
            chalk.gray(
              `\n    ${slash === -1 ? 'That address is' : 'That range covers only'} protected ` +
                `addresses (${m.tier}), which no setting releases.\n`
            )
        );
        process.exitCode = 1;
        return;
      }
      if (!exempt(a)) return;
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
