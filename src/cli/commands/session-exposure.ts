// src/cli/commands/session-exposure.ts
// Registered as `node9 session-exposure` by cli.ts.
//
// Inspect and clear session exposure (fw#318). A session that read outside
// content (an email, a web page, an issue) is exposed: its next call that
// sends to a destination that is not known is held for review. This command
// shows what each session read and lets a user release a session early.
//
// Exposure lives in the daemon's memory: a stopped daemon has none.

import type { Command } from 'commander';
import chalk from 'chalk';
import { listSessionExposures, clearSessionExposure } from '../../auth/daemon';
import type { SessionExposureRecord } from '../../daemon/exposure-store';
import { resolveSessionId } from './session-taint';
import { clearSessionMarkers } from '../../exposure/marker';

function fmtRemaining(expiresAt: number): string {
  const ms = expiresAt - Date.now();
  if (ms <= 0) return 'expiring';
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${Math.max(1, mins)}m`;
  return `${Math.floor(mins / 60)}h${mins % 60 ? ` ${mins % 60}m` : ''}`;
}

function describeSources(r: SessionExposureRecord): string {
  const tools = [...new Set(r.sources.map((s) => s.server ?? s.tool))];
  return tools.slice(0, 4).join(', ') + (tools.length > 4 ? ` +${tools.length - 4}` : '');
}

export function registerSessionExposureCommand(program: Command): void {
  const cmd = program
    .command('session-exposure')
    .description('Inspect and clear session exposure (sessions that read outside content)');

  cmd
    .command('list')
    .description('List sessions that read outside content and what they read')
    .action(async () => {
      const records = await listSessionExposures();
      console.log('');
      if (records.length === 0) {
        console.log(chalk.dim('  No exposed sessions.'));
        console.log(
          chalk.dim('  (Exposure lives in the daemon — a stopped daemon has none.)') + '\n'
        );
        return;
      }
      console.log(
        '  ' +
          chalk.bold(String(records.length)) +
          chalk.dim(` exposed session${records.length !== 1 ? 's' : ''}`)
      );
      console.log('');
      for (const r of records) {
        console.log(
          '  ' +
            chalk.yellow(r.sessionId.slice(0, 8).padEnd(10)) +
            chalk.cyan(`${r.sources.length} read${r.sources.length !== 1 ? 's' : ''}`) +
            chalk.dim(` via ${describeSources(r)}, `) +
            chalk.dim(
              `${r.destinations.length} destination${r.destinations.length !== 1 ? 's' : ''} seen, `
            ) +
            chalk.dim('clears in ' + fmtRemaining(r.expiresAt))
        );
      }
      console.log('');
      console.log(
        chalk.dim('  Run ') +
          chalk.cyan('node9 session-exposure clear <id>') +
          chalk.dim(' to release one, or ') +
          chalk.cyan('--all') +
          chalk.dim(' for every session.') +
          '\n'
      );
    });

  cmd
    .command('clear')
    .description("Clear a session's exposure so its next send is not held for review")
    .argument('[sessionId]', 'Session id to clear (the 8-char prefix from `list` is accepted)')
    .option('--all', 'Clear every session exposure')
    .action(async (sessionId: string | undefined, opts: { all?: boolean }) => {
      console.log('');
      if (opts.all) {
        const res = await clearSessionExposure({ all: true });
        clearSessionMarkers();
        if (res.daemonUnavailable) {
          console.log(chalk.dim('  node9 daemon not running — nothing to clear.') + '\n');
          return;
        }
        console.log(
          chalk.green('  ✓ ') +
            `Cleared ${chalk.bold(String(res.cleared))} session exposure${res.cleared !== 1 ? 's' : ''}.\n`
        );
        return;
      }
      if (!sessionId) {
        console.log(chalk.red('  Provide a session id or --all.'));
        console.log(
          chalk.dim('  Run `node9 session-exposure list` to see exposed sessions.') + '\n'
        );
        return;
      }
      const records = await listSessionExposures();
      if (records.length === 0) {
        console.log(chalk.dim('  No exposed sessions — nothing to clear.') + '\n');
        return;
      }
      const resolved = resolveSessionId(records, sessionId);
      if ('error' in resolved) {
        if (resolved.error === 'not-found') {
          console.log(chalk.red(`  No exposed session matches "${sessionId}".`));
        } else {
          console.log(chalk.red(`  "${sessionId}" is ambiguous — matches:`));
          for (const m of resolved.matches) console.log(chalk.dim('    ' + m));
        }
        console.log('');
        return;
      }
      const res = await clearSessionExposure({ sessionId: resolved.record.sessionId });
      clearSessionMarkers(resolved.record.sessionId);
      console.log(
        res.cleared > 0
          ? chalk.green('  ✓ ') +
              `Cleared exposure for ${chalk.yellow(resolved.record.sessionId.slice(0, 8))}.\n`
          : chalk.dim(`  Session ${resolved.record.sessionId.slice(0, 8)} was already clear.`) +
              '\n'
      );
    });
}
