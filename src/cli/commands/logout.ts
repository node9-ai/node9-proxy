import type { Command } from 'commander';
import { readConfigFileView, writeConfigFile } from '../../config/write';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import chalk from 'chalk';
import { atomicWriteSync } from '../../utils/atomic-write';
import { _resetConfigCache } from '../../config';
import { invalidConfig, SetupError } from '../interactive';
import { postJson } from '../../utils/post-json';
import { safeMessage } from '../../utils/safe-text';
import { safeApiUrl, HOST_ALLOW_ENV } from '../../auth/api-url';

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
  /** As read off disk. Absent or rejected values fall back to the default host. */
  apiUrl?: string;
}): Promise<
  | { outcome: 'revoked'; name?: string }
  | { outcome: 'already' }
  | { outcome: 'unreachable'; detail: string }
> {
  // credentials.json stores the intercept BASE (…/api/v1/intercept); the
  // self-disconnect endpoint is its child.
  //
  // Both callers (`logout`, `uninstall`) read apiUrl straight off disk, so the
  // pin is applied here, once: the key must not follow a rewritten file to a
  // remote host on its way out either.
  let rejected: string | null = null;
  const base = safeApiUrl(creds.apiUrl, (raw) => {
    rejected = String(raw).slice(0, 200);
  }).replace(/\/$/, '');
  const url = base + '/machines/self/disconnect';
  try {
    const r = await postJson<{ ok: boolean; name?: string }>(url, {}, creds.apiKey);
    return { outcome: 'revoked', name: r.name };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/HTTP 401/.test(msg)) {
      // A 401 from the DEFAULT host after the pin swapped the stored host out
      // is not "already disconnected": the key may still be live wherever the
      // file pointed (a self-hosted server without NODE9_API_HOST_ALLOW in
      // this shell). Say what happened instead of reporting success.
      if (rejected) {
        return {
          outcome: 'unreachable',
          detail: `stored apiUrl ${rejected} is not an allowed host (set ${HOST_ALLOW_ENV} for self-hosted); the revoke went to ${base} and was refused`,
        };
      }
      return { outcome: 'already' };
    }
    return { outcome: 'unreachable', detail: msg };
  }
}

export interface DisconnectResult {
  outcome: 'revoked' | 'already' | 'unreachable' | 'unreadable' | 'not-logged-in';
  localRemoved: boolean;
  detail?: string;
  name?: string;
  /** Where an unreadable credentials file was moved (outcome 'unreadable'). */
  movedTo?: string;
}

/** Parse credentials.json; undefined when it exists but cannot be read as a profile map. */
function readCredentialFile(
  credPath: string
): Record<string, { apiKey?: string; apiUrl?: string }> | undefined {
  try {
    const all = JSON.parse(fs.readFileSync(credPath, 'utf8'));
    return all && typeof all === 'object' && !Array.isArray(all) ? all : undefined;
  } catch {
    return undefined;
  }
}

export async function disconnectMachine(opts: {
  resetCloudApprover: boolean;
  profile?: string;
}): Promise<DisconnectResult> {
  if (opts.resetCloudApprover && process.env.NODE9_API_KEY) {
    throw new SetupError(
      'NODE9_API_KEY is still set. Remove it from the environment before switching to local protection.'
    );
  }
  const profile = opts.profile ?? (process.env.NODE9_PROFILE || 'default');
  const credPath = path.join(os.homedir(), '.node9', 'credentials.json');
  const configPath = path.join(os.homedir(), '.node9', 'config.json');
  // Validate the config before revoking anything: malformed settings must not
  // silently be replaced just to make the wizard finish.
  if (opts.resetCloudApprover) {
    try {
      readConfigFileView(configPath);
    } catch {
      throw invalidConfig();
    }
  }
  let remote: Omit<DisconnectResult, 'localRemoved'> = { outcome: 'not-logged-in' };
  let localRemoved = false;
  const all = fs.existsSync(credPath) ? readCredentialFile(credPath) : {};
  if (!all) {
    // The key cannot be read, so it cannot be revoked. Disconnect locally by
    // moving the file aside (never deleting it: it may hold other profiles)
    // and let the caller point the user at the dashboard.
    const movedTo = `${credPath}.corrupt-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    fs.renameSync(credPath, movedTo);
    remote = { outcome: 'unreadable', movedTo };
    localRemoved = true;
  } else {
    const entry = all[profile];
    if (entry?.apiKey) {
      remote = await revokeSelf({ apiKey: entry.apiKey, apiUrl: entry.apiUrl });
      delete all[profile];
      if (Object.keys(all).length === 0) {
        try {
          fs.unlinkSync(credPath);
        } catch {
          /* already gone */
        }
      } else {
        atomicWriteSync(credPath, JSON.stringify(all, null, 2) + '\n', { mode: 0o600 });
      }
      localRemoved = true;
    }
  }
  if (opts.resetCloudApprover) {
    writeConfigFile(configPath, (config) => {
      const settings = (config.settings ??= {});
      settings.approvers = { ...(settings.approvers ?? {}), cloud: false };
    });
  }
  _resetConfigCache();
  return { ...remote, localRemoved };
}

export function registerLogoutCommand(program: Command): void {
  program
    .command('logout')
    .description(
      'Disconnect this machine from the cloud (revokes its key; local enforcement keeps running)'
    )
    .action(async () => {
      const res = await disconnectMachine({ resetCloudApprover: false });
      if (res.outcome === 'not-logged-in') {
        console.log(chalk.gray('Not logged in — nothing to disconnect.'));
        return;
      }
      if (res.outcome === 'unreadable') {
        console.log(
          chalk.yellow(
            '⚠ ~/.node9/credentials.json could not be read, so the cloud key was not revoked.'
          )
        );
        console.log(
          chalk.green(
            `✓ Local: moved it to ${path.basename(res.movedTo ?? '')}. This machine is disconnected here.`
          )
        );
        console.log(
          chalk.yellow('  Remove it from the dashboard too: Enforcement › Devices › Disconnect.')
        );
        console.log(
          chalk.gray('  Local enforcement keeps running. Reconnect any time with: node9 login')
        );
        return;
      }
      if (res.outcome === 'revoked') {
        console.log(
          chalk.green(
            `✓ Cloud: key revoked${res.name ? ` (${res.name})` : ''} — this machine left the workspace.`
          )
        );
      } else if (res.outcome === 'already') {
        console.log(chalk.gray('✓ Cloud: this machine was already disconnected.'));
      } else {
        console.log(chalk.yellow(`⚠ Could not reach the cloud (${safeMessage(res.detail)}).`));
        console.log(
          chalk.yellow('  The key was removed locally, but is still listed in the dashboard —')
        );
        console.log(chalk.yellow('  disconnect it there: Enforcement › Devices › Disconnect.'));
      }
      console.log(chalk.green('✓ Local: credentials removed.'));
      console.log(
        chalk.gray('  Local enforcement keeps running. Reconnect any time with: node9 login')
      );
    });
}
