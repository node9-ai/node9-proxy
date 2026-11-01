// The hook bundle (fw#425): `node9 check` and `node9 log` only.
//
// Every tool call an agent makes runs one of these two. The full CLI
// registers 36 commands and pulls in modules no hook needs (the proxy and MCP
// gateway's process spawning, the onboarding prompts, the scan renderer, the
// supply-chain registry client); loading them cost each call a few hundred
// milliseconds before it judged anything. `launch.ts` sends `check` and `log`
// here; the command definitions are the same functions the full CLI
// registers, so behaviour cannot drift between the two.

import { Command } from 'commander';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { registerCheckCommand } from './cli/commands/check';
import { registerLogCommand } from './cli/commands/log';
import { getConfig } from './config';

const program = new Command();
program.name('node9');
registerCheckCommand(program);
registerLogCommand(program);

// The same last-resort handler the full CLI installs for these commands: a
// hook must never surface an unhandled rejection to the agent; `check` fails
// open (exit 0) as it always has, `log` reports and exits 1.
process.on('unhandledRejection', (reason) => {
  if (process.argv[2] === 'check') {
    if (process.env.NODE9_DEBUG === '1' || getConfig().settings.enableHookLogDebug) {
      const logPath = path.join(os.homedir(), '.node9', 'hook-debug.log');
      const msg = reason instanceof Error ? reason.message : String(reason);
      fs.appendFileSync(logPath, `[${new Date().toISOString()}] UNHANDLED: ${msg}\n`);
    }
    process.exit(0);
  } else {
    console.error('[Node9] Unhandled error:', reason);
    process.exit(1);
  }
});

void program.parseAsync();
