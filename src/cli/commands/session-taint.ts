// src/cli/commands/session-taint.ts
// Registered as `node9 session-taint` by cli.ts.
//
// Inspect and clear gap1 session taints. When a tool's OUTPUT is flagged (a
// secret surfaced, or an injected instruction was detected) on an observe-only
// agent, node9 can't redact it post-hoc — instead it taints the session so the
// next high-risk action (network/write) is held for review until the taint
// expires (~30m). This command lets a user who has resolved the issue release
// the session early, or just see what's currently held.
//
// Taint lives in the daemon's memory: a stopped daemon means there are no
// active taints (nothing to list or clear).

import type { Command } from 'commander';
import chalk from 'chalk';
import { listSessionTaints, clearSessionTaint } from '../../auth/daemon';
import type { SessionTaintRecord } from '../../daemon/taint-store';

/**
 * Resolve a user-supplied id (exact or a prefix, e.g. the 8-char form shown by
 * `list`) to a single tainted session. Pure so the prefix/ambiguity logic is
 * unit-testable without a daemon.
 *   - exact match wins outright (even if it's also a prefix of others)
 *   - otherwise a unique prefix match resolves
 *   - 0 matches → { error: 'not-found' }; >1 → { error: 'ambiguous', matches }
 */
export function resolveSessionId(
  records: SessionTaintRecord[],
  query: string
):
  | { record: SessionTaintRecord }
  | { error: 'not-found' }
  | { error: 'ambiguous'; matches: string[] } {
  const exact = records.find((r) => r.sessionId === query);
  if (exact) return { record: exact };
  const prefixed = records.filter((r) => r.sessionId.startsWith(query));
  if (prefixed.length === 0) return { error: 'not-found' };
  if (prefixed.length > 1) return { error: 'ambiguous', matches: prefixed.map((r) => r.sessionId) };
  return { record: prefixed[0] };
}

function fmtRemaining(expiresAt: number): string {
  const ms = expiresAt - Date.now();
  if (ms <= 0) return 'expiring';
  const mins = Math.round(ms / 60000);
  if (mins < 1) return '<1m';
  return `${mins}m`;
}

export function registerSessionTaintCommand(program: Command): void {
  const cmd = program
    .command('session-taint')
    .description('Inspect and clear gap1 session taints (output-flagged sessions held for review)');

  cmd
    .command('list')
    .description('List sessions currently tainted by flagged tool output')
    .action(async () => {
      const records = await listSessionTaints();
      console.log('');
      if (records.length === 0) {
        console.log(chalk.dim('  No tainted sessions.'));
        console.log(chalk.dim('  (Taint lives in the daemon — a stopped daemon has none.)') + '\n');
        return;
      }
      console.log(
        '  ' +
          chalk.bold(String(records.length)) +
          chalk.dim(` tainted session${records.length !== 1 ? 's' : ''}`)
      );
      console.log('');
      for (const r of records) {
        console.log(
          '  ' +
            chalk.yellow(r.sessionId.slice(0, 8).padEnd(10)) +
            chalk.red(r.source.padEnd(28)) +
            chalk.dim('clears in ' + fmtRemaining(r.expiresAt))
        );
      }
      console.log('');
      console.log(
        chalk.dim('  Run ') +
          chalk.cyan('node9 session-taint clear <id>') +
          chalk.dim(' to release one, or ') +
          chalk.cyan('--all') +
          chalk.dim(' for every session.') +
          '\n'
      );
    });

  cmd
    .command('clear')
    .description("Clear a session's taint so its next network/write action isn't held for review")
    .argument('[sessionId]', 'Session id to clear (the 8-char prefix from `list` is accepted)')
    .option('--all', 'Clear every session taint')
    .action(async (sessionId: string | undefined, opts: { all?: boolean }) => {
      console.log('');
      if (opts.all) {
        const res = await clearSessionTaint({ all: true });
        if (res.daemonUnavailable) {
          console.log(chalk.dim('  node9 daemon not running — no active taints to clear.') + '\n');
          return;
        }
        console.log(
          chalk.green('  ✓ ') +
            `Cleared ${chalk.bold(String(res.cleared))} session taint${res.cleared !== 1 ? 's' : ''}.\n`
        );
        return;
      }

      if (!sessionId) {
        console.log(chalk.red('  Provide a session id or --all.'));
        console.log(chalk.dim('  Run `node9 session-taint list` to see tainted sessions.') + '\n');
        return;
      }

      // Resolve the (possibly partial) id against the live list so prefixes work
      // and we can show the user exactly what they're releasing.
      const records = await listSessionTaints();
      if (records.length === 0) {
        console.log(chalk.dim('  No tainted sessions — nothing to clear.') + '\n');
        return;
      }
      const resolved = resolveSessionId(records, sessionId);
      if ('error' in resolved) {
        if (resolved.error === 'not-found') {
          console.log(chalk.red(`  No tainted session matches "${sessionId}".`));
        } else {
          console.log(chalk.red(`  "${sessionId}" is ambiguous — matches:`));
          for (const m of resolved.matches) console.log(chalk.dim('    ' + m));
        }
        console.log('');
        return;
      }

      const res = await clearSessionTaint({ sessionId: resolved.record.sessionId });
      if (res.cleared > 0) {
        console.log(
          chalk.green('  ✓ ') +
            `Cleared taint for ${chalk.yellow(resolved.record.sessionId.slice(0, 8))} ` +
            chalk.dim(`(was flagged by ${resolved.record.source}).`) +
            '\n'
        );
      } else {
        // Raced with TTL expiry between list and clear — already gone.
        console.log(
          chalk.dim(`  Session ${resolved.record.sessionId.slice(0, 8)} was already clear.`) + '\n'
        );
      }
    });
}
