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
import { isDaemonRunning, DAEMON_PORT, DAEMON_HOST } from '../../auth/daemon';
import { openBrowserLocal } from '../daemon-starter';

const VALID_ACTIONS = 'start | stop | restart | status | install | uninstall';

export function registerDaemonCommand(program: Command): void {
  program
    .command('daemon')
    .description('Manage the local approval daemon')
    .argument('[action]', `${VALID_ACTIONS} (default: start)`)
    .option('-b, --background', 'Start the daemon in the background (detached)')
    .option('-o, --openui', 'Start in background and open browser')
    .option(
      '-w, --watch',
      'Start daemon + open browser, stay alive permanently (Flight Recorder mode)'
    )
    .action(
      async (
        action: string | undefined,
        options: { background?: boolean; openui?: boolean; watch?: boolean }
      ) => {
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
            env: { ...process.env, NODE9_AUTO_STARTED: '1', NODE9_BROWSER_OPENED: '1' },
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
            openBrowserLocal();
            console.log(chalk.cyan(`🛰️  Flight Recorder: http://${DAEMON_HOST}:${DAEMON_PORT}/`));
          }, 600);
          startDaemon(); // foreground — keeps process alive
          return;
        }

        if (options.openui) {
          if (isDaemonRunning()) {
            openBrowserLocal();
            console.log(chalk.green(`🌐  Opened browser: http://${DAEMON_HOST}:${DAEMON_PORT}/`));
            process.exit(0);
          }
          const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
            detached: true,
            stdio: 'ignore',
          });
          child.unref();
          for (let i = 0; i < 12; i++) {
            await new Promise((r) => setTimeout(r, 250));
            if (isDaemonRunning()) break;
          }
          openBrowserLocal();
          console.log(chalk.green(`\n🛡️  Node9 daemon started + browser opened`));
          process.exit(0);
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
