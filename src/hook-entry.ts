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
import path from 'path';
import { failCurrentCheck, registerCheckCommand } from './cli/commands/check';
import { registerLogCommand } from './cli/commands/log';

const { version } = JSON.parse(
  fs.readFileSync(path.join(__dirname, '../package.json'), 'utf-8')
) as { version: string };

const program = new Command();
// Same name and version as the full CLI, so `node9 check --version` answers too.
program.name('node9').description('The Sudo Command for AI Agents').version(version);
registerCheckCommand(program);
registerLogCommand(program);

// The same last-resort handlers the full CLI installs for these commands: a
// hook must never surface an unhandled error to the agent. `check` records
// that the call was not checked and follows the machine's fail policy
// (node9Firewall#383); `log` reports and exits 1.
process.on('unhandledRejection', (reason) => {
  if (process.argv[2] === 'check') failCurrentCheck(reason);
  console.error('[Node9] Unhandled error:', reason);
  process.exit(1);
});
// Without this, an exception in an event handler ends `check` with Node's own
// stack trace and exit 1, which an agent reads as a broken hook: the call runs
// and nothing records it.
process.on('uncaughtException', (err) => {
  if (process.argv[2] === 'check') failCurrentCheck(err);
  console.error('[Node9] Unhandled error:', err);
  process.exit(1);
});

void program.parseAsync();
