// src/cli/commands/daemon-cmd.ts
// Registered as `node9 daemon` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import { spawn } from 'child_process';
import { isDaemonReachable } from '../../auth/daemon';
import fs from 'fs';
import { openStartupLogFd, recordStartupState } from '../../daemon/startup-log';
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
          // Task #18: wait for the port to actually free (bounded ~3s), not a
          // fixed 500ms — else the fresh daemon can hit EADDRINUSE on the dying
          // holder, adopt it, exit… and the holder then dies: zero daemons.
          for (let i = 0; i < 15; i++) {
            if (!(await isDaemonReachable(300))) break;
            await new Promise((r) => setTimeout(r, 200));
          }
          // Same spawner contract as --background: capture the child's stderr, mark
          // the attempt, and ALWAYS attach an 'error' listener (an 'error' event with
          // no listener is an uncaught exception).
          const restartFd = openStartupLogFd();
          recordStartupState('starting');
          const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
            detached: true,
            stdio: ['ignore', 'ignore', restartFd ?? 'ignore'],
            env: { ...process.env, NODE9_AUTO_STARTED: '1' },
          });
          child.on('error', (err: Error) =>
            recordStartupState('failed', 'spawn-failed', err.message)
          );
          child.unref();
          if (restartFd !== undefined) {
            try {
              fs.closeSync(restartFd);
            } catch {
              /* non-fatal */
            }
          }
          if (child.pid) {
            // Same caveat as --background: the child may not survive startup.
            console.log(chalk.green(`✓ Daemon relaunching (PID ${child.pid})`));
            console.log(chalk.gray('   Confirm with: node9 status'));
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
          // This is the command `doctor` tells users to run, so it must follow the
          // same contract as the other two spawners — otherwise the fix we recommend
          // fails silently and doctor keeps showing the PREVIOUS cause, i.e. the tool
          // appears to lie about a repair it just suggested.
          const startupFd = openStartupLogFd();
          try {
            recordStartupState('starting');
            const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
              detached: true,
              // Capture the child's stderr: a module-load crash prints its stack there
              // and dies before it can record anything itself.
              stdio: ['ignore', 'ignore', startupFd ?? 'ignore'],
            });
            // An 'error' event with NO listener is an uncaught exception. It may not
            // fire before the exit below — that is fine, the 'starting' marker is the
            // backstop and doctor reports it — but it must never crash this command.
            child.on('error', (err: Error) =>
              recordStartupState('failed', 'spawn-failed', err.message)
            );
            child.unref();
            // "started" would assert something we cannot know here: the child may
            // still exit during startup (import crash, or a port held by a foreign
            // process). Say what actually happened — it was launched — and point at
            // the command that reports the truth.
            console.log(
              chalk.green(`\n🛡️  Node9 daemon launching in background  (PID ${child.pid})`)
            );
            console.log(chalk.gray('   Confirm with: node9 status'));
          } finally {
            if (startupFd !== undefined) {
              try {
                fs.closeSync(startupFd);
              } catch {
                /* non-fatal */
              }
            }
          }
          process.exit(0);
        }

        startDaemon();
      }
    );
}
