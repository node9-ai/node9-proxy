// src/cli/commands/posture.ts
// Registered as `node9 posture` by cli.ts.
//
// Prints a security scorecard for the agent on this host: secrets exposure,
// open egress, and the destructive-command gate self-test. Read-only /
// classification-only — nothing here executes a payload or mutates state.

import type { Command } from 'commander';
import chalk from 'chalk';
import { runPosture } from '../../posture';
import { renderPosture } from '../../posture/render';
import { shipPosture } from '../../posture/ship';
import { readCredentials } from '../../daemon/sync';

export function registerPostureCommand(program: Command): void {
  program
    .command('posture')
    .description('Security scorecard for the agent on this host (secrets, egress, gate)')
    .option('--agent <name>', 'label / policy scope for the agent being graded')
    .option('--json', 'emit the raw result as JSON instead of the scorecard')
    .option('--ship', 'send a redacted snapshot to your node9 dashboard')
    .action(async (opts: { agent?: string; json?: boolean; ship?: boolean }) => {
      const result = await runPosture({ agent: opts.agent });
      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(renderPosture(result));
      }

      // --ship is best-effort: it never fails the command. Status goes to
      // stderr so --json stdout stays a clean, parseable document.
      if (opts.ship) {
        const creds = readCredentials();
        if (!creds) {
          console.error(chalk.gray('  Run `node9 login` to ship this to your dashboard.'));
        } else {
          const ok = await shipPosture(result, creds);
          console.error(
            ok
              ? chalk.gray('  ✓ Shipped to your node9 dashboard.')
              : chalk.gray('  Could not reach the dashboard — saved locally only.')
          );
        }
      }

      // Non-zero exit when the posture is critical, so CI / scripts can gate on it.
      if (result.tier === 'critical') process.exitCode = 2;
    });
}
