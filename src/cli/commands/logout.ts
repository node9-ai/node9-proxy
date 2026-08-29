import type { Command } from 'commander';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import chalk from 'chalk';
import { postJson } from '../../utils/post-json';

// node9 logout (login-v2 §5, phase C.2) — the machine end of Disconnect.
// Revokes this machine's key in the cloud (best-effort) and removes it
// locally. Deliberately does NOT touch config.json and does NOT stop the
// daemon: local enforcement is not tied to the cloud connection, and logging
// out must never mean "unprotected".

/**
 * Revoke the given key against its own cloud. Exported so `node9 uninstall`
 * runs the same step before tearing down. Never throws.
 *  - revoked: the cloud confirmed (returns the machine name when it says)
 *  - already: 401 — the key was revoked before (dashboard Disconnect, an
 *    admin removing the member, or a prior logout)
 *  - unreachable: network/server trouble; the caller decides what that means
 */
export async function revokeSelf(creds: {
  apiKey: string;
  apiUrl: string;
}): Promise<
  | { outcome: 'revoked'; name?: string }
  | { outcome: 'already' }
  | { outcome: 'unreachable'; detail: string }
> {
  // credentials.json stores the intercept BASE (…/api/v1/intercept); the
  // self-disconnect endpoint is its child.
  const url = creds.apiUrl.replace(/\/$/, '') + '/machines/self/disconnect';
  try {
    const r = await postJson<{ ok: boolean; name?: string }>(url, {}, creds.apiKey);
    return { outcome: 'revoked', name: r.name };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/HTTP 401/.test(msg)) return { outcome: 'already' };
    return { outcome: 'unreachable', detail: msg };
  }
}

export function registerLogoutCommand(program: Command): void {
  program
    .command('logout')
    .description(
      'Disconnect this machine from the cloud (revokes its key; local enforcement keeps running)'
    )
    .action(async () => {
      const profile = process.env.NODE9_PROFILE || 'default';
      const credPath = path.join(os.homedir(), '.node9', 'credentials.json');

      let all: Record<string, { apiKey?: string; apiUrl?: string }> = {};
      try {
        all = JSON.parse(fs.readFileSync(credPath, 'utf-8'));
      } catch {
        /* missing or unreadable → not logged in */
      }
      const entry = all[profile];
      if (!entry?.apiKey) {
        console.log(chalk.gray('Not logged in — nothing to disconnect.'));
        return;
      }

      // 1. Cloud first, while we still hold the key. Best-effort: an offline
      //    logout still logs out locally, but says so honestly.
      const res = await revokeSelf({
        apiKey: entry.apiKey,
        apiUrl: entry.apiUrl || 'https://api.node9.ai/api/v1/intercept',
      });
      if (res.outcome === 'revoked') {
        console.log(
          chalk.green(
            `✓ Cloud: key revoked${res.name ? ` (${res.name})` : ''} — this machine left the workspace.`
          )
        );
      } else if (res.outcome === 'already') {
        console.log(chalk.gray('✓ Cloud: this machine was already disconnected.'));
      } else {
        console.log(chalk.yellow(`⚠ Could not reach the cloud (${res.detail}).`));
        console.log(
          chalk.yellow('  The key was removed locally, but is still listed in the dashboard —')
        );
        console.log(chalk.yellow('  disconnect it there: Enforcement › Devices › Disconnect.'));
      }

      // 2. Local removal — the profile only; other profiles stay.
      delete all[profile];
      if (Object.keys(all).length === 0) {
        try {
          fs.unlinkSync(credPath);
        } catch {
          /* already gone */
        }
      } else {
        fs.writeFileSync(credPath, JSON.stringify(all, null, 2), { mode: 0o600 });
      }
      console.log(chalk.green('✓ Local: credentials removed.'));
      console.log(
        chalk.gray('  Local enforcement keeps running. Reconnect any time with: node9 login')
      );
    });
}
