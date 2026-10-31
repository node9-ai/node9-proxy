// src/cli-hook.ts -> dist/cli-hook.js, loaded by dist/cli.js for `check` and `log`.
//
// The hook commands run on every agent tool call, so this entry registers only
// them and imports nothing else: the full CLI (src/cli.ts) drags in the TUI,
// setup, scan, prompts and process libraries, which cost hundreds of ms to
// load and are never used on the hook path. src/cli.ts still registers both
// commands, so a hook invoked with leading options still works there.
import { Command } from 'commander';
import { registerCheckCommand } from './cli/commands/check';
import { registerLogCommand } from './cli/commands/log';
import { registerUnhandledRejectionHandler } from './cli/unhandled-rejection';

registerUnhandledRejectionHandler();

const program = new Command();
program.name('node9');
registerCheckCommand(program);
registerLogCommand(program);

void program.parseAsync();
