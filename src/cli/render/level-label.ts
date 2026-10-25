// The protection level as `node9 status` and `node9 shield` print it.
// F5: Audit is the level where node9 stops NOTHING (every block becomes a
// would-block), and a keyed machine applies a cloud Audit verbatim, so the
// label says so; an unknown value must never read as standard.
import chalk from 'chalk';
import { levelOf } from '@node9/policy-engine';

export function levelLabel(mode: string | undefined): string {
  switch (levelOf(mode)) {
    case 'audit':
      return chalk.magenta('audit (nothing is stopped)');
    case 'soft':
      return chalk.cyan('soft');
    case 'strict':
      return chalk.yellow('strict');
    case 'block-all':
      return chalk.red('block-all (every unrecognised call asks)');
    default:
      return chalk.white('standard');
  }
}
