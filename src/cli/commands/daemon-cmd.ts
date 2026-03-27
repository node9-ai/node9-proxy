// src/cli/commands/daemon-cmd.ts
// Registered as `node9 daemon` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import { spawn } from 'child_process';
import { startDaemon, stopDaemon, daemonStatus } from '../../daemon/index';
import { isDaemonRunning, DAEMON_PORT, DAEMON_HOST } from '../../auth/daemon';
import { openBrowserLocal } from '../daemon-starter';

export function registerDaemonCommand(program: Command): void {
  program
    .command('daemon')
    .description('Run the local approval server')
    .argument('[action]', 'start | stop | status (default: start)')
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
        if (cmd === 'stop') return stopDaemon();
        if (cmd === 'status') return daemonStatus();
        if (cmd !== 'start' && action !== undefined) {
          console.error(
            chalk.red(`Unknown daemon action: "${action}". Use: start | stop | status`)
          );
          process.exit(1);
        }

        if (options.watch) {
          process.env.NODE9_WATCH_MODE = '1';
          // Open browser shortly after daemon binds to its port
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
