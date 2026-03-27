// src/cli/commands/watch.ts
// Registered as `node9 watch` by cli.ts.
import type { Command } from 'commander';
import chalk from 'chalk';
import { spawn, spawnSync } from 'child_process';
import { DAEMON_PORT } from '../../auth/daemon';

export function registerWatchCommand(program: Command): void {
  program
    .command('watch')
    .description('Run a command under Node9 watch mode (daemon stays alive for the session)')
    .argument('<command>', 'Command to run')
    .argument('[args...]', 'Arguments for the command')
    .action(async (cmd: string, args: string[]) => {
      // Ensure daemon is running in watch mode (never idle-exits)
      let port = DAEMON_PORT;
      try {
        const res = await fetch(`http://127.0.0.1:${DAEMON_PORT}/settings`, {
          signal: AbortSignal.timeout(500),
        });
        if (res.ok) {
          const data = (await res.json()) as { port?: number };
          if (typeof data.port === 'number') port = data.port;
        } else {
          throw new Error('not running');
        }
      } catch {
        // Not running — start it with watch mode enabled
        console.error(chalk.dim('🛡️  Starting Node9 daemon (watch mode)...'));
        const child = spawn(process.execPath, [process.argv[1], 'daemon'], {
          detached: true,
          stdio: 'ignore',
          env: { ...process.env, NODE9_AUTO_STARTED: '1', NODE9_WATCH_MODE: '1' },
        });
        child.unref();
        // Wait up to 5s
        let ready = false;
        for (let i = 0; i < 20; i++) {
          await new Promise((r) => setTimeout(r, 250));
          try {
            const r = await fetch(`http://127.0.0.1:${DAEMON_PORT}/settings`, {
              signal: AbortSignal.timeout(500),
            });
            if (r.ok) {
              ready = true;
              break;
            }
          } catch {}
        }
        if (!ready) {
          console.error(chalk.red('❌ Daemon failed to start. Try: node9 daemon start'));
          process.exit(1);
        }
      }

      console.error(
        chalk.cyan.bold('🛡️  Node9 watch') +
          chalk.dim(` → localhost:${port}`) +
          chalk.dim(
            '\n   Tip: run `node9 tail` in another terminal to review and approve AI actions.\n'
          )
      );

      const result = spawnSync(cmd, args, {
        stdio: 'inherit',
        env: { ...process.env, NODE9_WATCH_MODE: '1' },
      });
      if (result.error) {
        console.error(chalk.red(`❌ Failed to run command: ${result.error.message}`));
        process.exit(1);
      }
      process.exit(result.status ?? 0);
    });
}
