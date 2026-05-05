// src/cli/commands/daemon-cmd.ts
// Registered as `node9 daemon` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import { spawn } from 'child_process';
import {
  startDaemon,
  stopDaemon,
  daemonStatus,
  installDaemonService,
  uninstallDaemonService,
} from '../../daemon/index';
const VALID_ACTIONS = 'start | stop | restart | status | install | uninstall';

export function registerDaemonCommand(program: Command): void {
  program
    .command('daemon')
    .description('Manage the local approval daemon')
    .argument('[action]', `${VALID_ACTIONS} (default: start)`)
    .option('-b, --background', 'Start the daemon in the background (detached)')
    .option(
      '-w, --watch',
      'Start daemon in foreground, stay alive permanently (Flight Recorder mode for tail)'
    )
    .action(
      async (action: string | undefined, options: { background?: boolean; watch?: boolean }) => {
        const cmd = (action ?? 'start').toLowerCase();

        // ── install ──────────────────────────────────────────────────────────
        if (cmd === 'install') {
          const result = installDaemonService();
          if (!result.ok) {
            console.error(chalk.red(`✗ ${result.reason}`));
            process.exit(1);
          }
          if (result.alreadyInstalled) {
            console.log(chalk.green(`✓ Daemon service reinstalled (${result.platform})`));
          } else {
            console.log(chalk.green(`✓ Daemon installed as login service (${result.platform})`));
            console.log(chalk.gray('  The daemon will now start automatically on login.'));
          }
          process.exit(0);
        }

        // ── uninstall ─────────────────────────────────────────────────────────
        if (cmd === 'uninstall') {
          const result = uninstallDaemonService();
          if (!result.ok) {
            console.error(chalk.red(`✗ ${result.reason}`));
            process.exit(1);
          }
          console.log(chalk.green(`✓ Daemon service removed (${result.platform})`));
          console.log(chalk.gray('  The daemon will no longer start automatically on login.'));
          console.log(chalk.gray('  To stop the running daemon: node9 daemon stop'));
          process.exit(0);
        }

        // ── stop ──────────────────────────────────────────────────────────────
        if (cmd === 'stop') return stopDaemon();

        // ── restart ───────────────────────────────────────────────────────────
        if (cmd === 'restart') {
          stopDaemon();
          await new Promise((r) => setTimeout(r, 500));
          const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
            detached: true,
            stdio: 'ignore',
            env: { ...process.env, NODE9_AUTO_STARTED: '1' },
          });
          child.unref();
          if (child.pid) {
            console.log(chalk.green(`✓ Daemon restarted (PID ${child.pid})`));
          } else {
            console.error(chalk.red('✗ Failed to restart daemon — spawn returned no PID'));
            process.exit(1);
          }
          process.exit(0);
        }

        // ── status ────────────────────────────────────────────────────────────
        if (cmd === 'status') return daemonStatus();

        if (cmd !== 'start' && action !== undefined) {
          console.error(chalk.red(`Unknown daemon action: "${action}". Use: ${VALID_ACTIONS}`));
          process.exit(1);
        }

        // ── start (default) ───────────────────────────────────────────────────
        if (options.watch) {
          process.env.NODE9_WATCH_MODE = '1';
          setTimeout(() => {
            console.log(
              chalk.cyan(`🛰️  Flight Recorder running. Open another terminal and run:`) +
                chalk.bold(' node9 tail')
            );
          }, 600);
          startDaemon(); // foreground — keeps process alive
          return;
        }

        if (options.background) {
          const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
            detached: true,
            stdio: 'ignore',
          });
          child.unref();
          console.log(chalk.green(`\n🛡️  Node9 daemon started in background  (PID ${child.pid})`));
          process.exit(0);
        }

        startDaemon();
      }
    );
}
