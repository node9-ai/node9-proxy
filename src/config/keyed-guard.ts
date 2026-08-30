// src/config/keyed-guard.ts
// PR-2 write-guard: on a machine keyed for policy (config.policySource ===
// 'workspace') the local policy stores are INERT — getConfig builds policy
// from DEFAULT_CONFIG + the cloud only. A local policy write (shield enable,
// egress lock, trust add, jail add…) would succeed on disk and then silently
// do nothing, which is worse than a refusal: the user believes they changed
// enforcement. So every local policy-write surface refuses with a pointer to
// the dashboard and a NON-ZERO exit (a script that thinks it hardened a keyed
// machine must fail loudly, not no-op green).
//
// What this does NOT guard: operational commands (init, logout, daemon…),
// incident commands (dlp resolve, sandbox, undo), and reads. Logout / `node9
// login --local` are the paved paths back to local policy control.

import chalk from 'chalk';
import { getConfig } from './index';

/** True when this machine follows the workspace configuration for POLICY.
 *  Delegates to the one truth (config.policySource) — never re-derive
 *  keyedness from credentials here. A config-load failure counts as NOT
 *  keyed: the write itself will surface the real error, and blocking a
 *  local machine's writes on a corrupt config would strand it. */
export function isKeyedForPolicy(): boolean {
  try {
    return getConfig().policySource === 'workspace';
  } catch {
    return false;
  }
}

/** One sentence, shared verbatim by the CLI and the MCP refusals so the
 *  gauntlet can assert on it. */
export const KEYED_POLICY_WRITE_REASON =
  'This machine follows the workspace configuration — policy is edited in the dashboard, not on this machine.';

export function keyedPolicyWriteMessage(action: string): string {
  return (
    `${KEYED_POLICY_WRITE_REASON}\n` +
    `  Edit policy at https://app.node9.ai → Enforcement (change: ${action}).\n` +
    `  For local policy control, disconnect this machine (node9 logout) or reconnect with node9 login --local.`
  );
}

/**
 * CLI seam: call first in every policy-writing command action.
 * Returns true when the write may proceed; otherwise prints the refusal,
 * sets a non-zero exit code, and returns false.
 */
export function cliGuardPolicyWrite(action: string): boolean {
  if (!isKeyedForPolicy()) return true;
  console.error(chalk.yellow(`\n⛔ ${keyedPolicyWriteMessage(action)}\n`));
  process.exitCode = 1;
  return false;
}
