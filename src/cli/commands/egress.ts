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
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getConfig } from '../../config';
import { DEFAULT_EGRESS_ALLOWLIST } from '@node9/policy-engine';

type EgressMode = 'off' | 'review' | 'block';
interface EgressBlock {
  enabled: boolean;
  mode: EgressMode;
  allow: string[];
  deny: string[];
  allowPrivate: boolean;
}

const DEFAULT_EGRESS: EgressBlock = {
  enabled: false,
  mode: 'review',
  allow: [],
  deny: [],
  allowPrivate: true,
};

// The on-disk config is an arbitrary JSON bag; we only touch policy.egress.
type RawConfig = { policy?: Record<string, unknown>; [key: string]: unknown };

function configPath(): string {
  return path.join(os.homedir(), '.node9', 'config.json');
}

/**
 * Read the raw config. A MISSING file → fresh `{}` (fine). A file that EXISTS
 * but isn't valid JSON → throw — we must never overwrite a config we couldn't
 * parse (that would silently destroy the user's other settings).
 */
function readRawConfig(): RawConfig {
  let text: string;
  try {
    text = fs.readFileSync(configPath(), 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw err; // permission/other read error — don't silently clobber
  }
  try {
    return JSON.parse(text) as RawConfig;
  } catch {
    throw new Error(
      `${configPath()} is not valid JSON — fix it before changing egress (refusing to overwrite).`
    );
  }
}

function writeRawConfig(config: RawConfig): void {
  const p = configPath();
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
}

/**
 * Pure: apply a change to the egress block of a raw config (read-merge-write
 * semantics — never clobbers other config). Exported for tests.
 */
export function applyEgress(config: RawConfig, change: Partial<EgressBlock>): RawConfig {
  const policy = (config.policy = config.policy ?? {});
  const existing = (policy.egress ?? {}) as Partial<EgressBlock>;
  policy.egress = { ...DEFAULT_EGRESS, ...existing, ...change };
  return config;
}

/** Run a config write, surfacing a malformed-config refusal cleanly (exit 1). */
function withConfig(fn: (config: RawConfig) => void): boolean {
  let config: RawConfig;
  try {
    config = readRawConfig();
  } catch (err) {
    console.error(chalk.red(`\n  ✗ ${(err as Error).message}\n`));
    process.exitCode = 1;
    return false;
  }
  fn(config);
  writeRawConfig(config);
  return true;
}

function mutate(change: Partial<EgressBlock>): boolean {
  return withConfig((config) => applyEgress(config, change));
}

function addHost(list: 'allow' | 'deny', host: string): boolean {
  return withConfig((config) => {
    const existing = (config.policy?.egress ?? {}) as Partial<EgressBlock>;
    const current: EgressBlock = { ...DEFAULT_EGRESS, ...existing };
    const updated = current[list].includes(host) ? current[list] : [...current[list], host];
    applyEgress(config, { [list]: updated });
  });
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
