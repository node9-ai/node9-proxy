// src/cli/unhandled-rejection.ts
// Process-wide unhandledRejection policy, shared by the full CLI (cli-main)
// and the lean hook entry (cli-hook) so both entry points fail the same way.
import fs from 'fs';
import path from 'path';
import os from 'os';
import { getConfig } from '../config';

/**
 * `check` fails open with exit 0 (a crashing PreToolUse hook must not wedge
 * the agent) and logs to hook-debug.log only when debugging; every other
 * command reports the rejection and exits 1.
 *
 * Not for `daemon`: it registers its own keep-alive handler in startDaemon().
 */
export function registerUnhandledRejectionHandler(): void {
  process.on('unhandledRejection', (reason) => {
    const isCheckHook = process.argv[2] === 'check';
    if (isCheckHook) {
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
}
