// src/cli/commands/status.ts
// Registered as `node9 status` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { getCredentials, getConfig, checkPause } from '../../core';
import { isDaemonRunning, DAEMON_PORT } from '../../auth/daemon';

export function registerStatusCommand(program: Command): void {
  program
    .command('status')
    .description('Show current Node9 mode, policy source, and persistent decisions')
    .action(() => {
      const creds = getCredentials();
      const daemonRunning = isDaemonRunning();

      // Grab the fully resolved waterfall config!
      const mergedConfig = getConfig();
      const settings = mergedConfig.settings;

      console.log('');

      // ── Policy authority ────────────────────────────────────────────────────
      if (creds && settings.approvers.cloud) {
        console.log(chalk.green('  ● Agent mode') + chalk.gray(' — cloud team policy enforced'));
      } else if (creds && !settings.approvers.cloud) {
        console.log(
          chalk.blue('  ● Privacy mode 🛡️') + chalk.gray(' — all decisions stay on this machine')
        );
      } else {
        console.log(
          chalk.yellow('  ○ Privacy mode 🛡️') + chalk.gray(' — no API key (Local rules only)')
        );
      }

      // ── Daemon & Architecture ────────────────────────────────────────────────
      console.log('');
      if (daemonRunning) {
        console.log(
          chalk.green('  ● Daemon running') + chalk.gray(` → http://127.0.0.1:${DAEMON_PORT}/`)
        );
      } else {
        console.log(chalk.gray('  ○ Daemon stopped'));
      }

      if (settings.enableUndo) {
        console.log(
          chalk.magenta('  ● Undo Engine') +
            chalk.gray(`    → Auto-snapshotting Git repos on AI change`)
        );
      }

      // ── Configuration State ──────────────────────────────────────────────────
      console.log('');
      const modeLabel =
        settings.mode === 'audit'
          ? chalk.blue('audit')
          : settings.mode === 'strict'
            ? chalk.red('strict')
            : chalk.white('standard');
      console.log(`  Mode:    ${modeLabel}`);

      const projectConfig = path.join(process.cwd(), 'node9.config.json');
      const globalConfig = path.join(os.homedir(), '.node9', 'config.json');
      console.log(
        `  Local:   ${fs.existsSync(projectConfig) ? chalk.green('Active (node9.config.json)') : chalk.gray('Not present')}`
      );
      console.log(
        `  Global:  ${fs.existsSync(globalConfig) ? chalk.green('Active (~/.node9/config.json)') : chalk.gray('Not present')}`
      );

      if (mergedConfig.policy.sandboxPaths.length > 0) {
        console.log(
          `  Sandbox: ${chalk.green(`${mergedConfig.policy.sandboxPaths.length} safe zones active`)}`
        );
      }

      // ── Pause state ──────────────────────────────────────────────────────────
      const pauseState = checkPause();
      if (pauseState.paused) {
        const expiresAt = pauseState.expiresAt
          ? new Date(pauseState.expiresAt).toLocaleTimeString()
          : 'indefinitely';
        console.log('');
        console.log(
          chalk.yellow(`  ⏸  PAUSED until ${expiresAt}`) + chalk.gray(' — all tool calls allowed')
        );
      }

      console.log('');
    });
}
