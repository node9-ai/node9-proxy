// src/cli/commands/posture.ts
// Registered as `node9 posture` by cli.ts.
//
// Prints a security scorecard for the agent on this host: secrets exposure,
// open egress, and the destructive-command gate self-test. Read-only /
// classification-only — nothing here executes a payload or mutates state.

import type { Command } from 'commander';
import { runPosture } from '../../posture';
import { renderPosture } from '../../posture/render';

export function registerPostureCommand(program: Command): void {
  program
    .command('posture')
    .description('Security scorecard for the agent on this host (secrets, egress, gate)')
    .option('--agent <name>', 'label / policy scope for the agent being graded')
    .option('--json', 'emit the raw result as JSON instead of the scorecard')
    .action(async (opts: { agent?: string; json?: boolean }) => {
      const result = await runPosture({ agent: opts.agent });
      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(renderPosture(result));
      }
      // Non-zero exit when the posture is critical, so CI / scripts can gate on it.
      if (result.tier === 'critical') process.exitCode = 2;
    });
}
