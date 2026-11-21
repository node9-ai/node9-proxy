// src/posture/remedy.ts
// Where a setting is changed ON THIS MACHINE, in the words a fix line uses.
//
// One rule for every posture row: a fix may only name a step that changes the
// row here. On a machine governed by the workspace policy the local commands
// and config file are ignored (`node9 shield list` and `node9 jail list` say
// so), so a row that offered `node9 jail add` or `node9 egress lock` sent the
// reader to a command that changes nothing (founder's machine, 2026-11-21).
//
// Page names are the dashboard's after fw#390: one Protection page, budgets on
// Usage. Check titles ("Jailed path", "Unknown host") come from the catalog,
// which the CLI and the dashboard share. No path in any string: fix lines ship.

import { getConfig } from '../config';

export type PolicySource = 'workspace' | 'local';

const PROTECTION = 'the Protection page of the dashboard (app.node9.ai)';
const USAGE = 'the Usage page of the dashboard (app.node9.ai)';
const CONFIG_FILE = '~/.node9/config.json';

/** Which layer governs policy for this run. Never throws: a stranger's machine
 *  with no config is local. */
export function policySourceOf(cwd?: string): PolicySource {
  try {
    return getConfig(cwd).policySource === 'workspace' ? 'workspace' : 'local';
  } catch {
    return 'local';
  }
}

/** Upper-case the first letter, for a step that opens a sentence. */
export function cap(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export const remedy = {
  /** Leave a record-only mode. Reads on as "... to stop them". */
  mode(source: PolicySource): string {
    return source === 'workspace'
      ? `set the mode to Standard (or Strict) on ${PROTECTION}`
      : `set mode to \`standard\` (or \`strict\`) in ${CONFIG_FILE}`;
  },

  /** Jail files; `which` names them without a path ("each file above"). */
  jailAdd(source: PolicySource, which: string): string {
    return source === 'workspace'
      ? `add ${which} under the Jailed path check on ${PROTECTION}`
      : `run \`node9 jail add <file>\` for ${which}`;
  },

  /** Restrict where the agent can send. */
  egress(source: PolicySource): string {
    return source === 'workspace'
      ? `set the Unknown host check to review (or block to hard-block) on ${PROTECTION}`
      : 'run `node9 egress watch` (or `node9 egress lock` to hard-block)';
  },

  /** The hard-block step alone, as a bare line for a bullet list. */
  egressLockLine(source: PolicySource): string {
    return source === 'workspace'
      ? `set the Unknown host check to block on ${PROTECTION}`
      : 'node9 egress lock';
  },

  /** Turn a shield on. */
  shield(source: PolicySource, name: string): string {
    return source === 'workspace'
      ? `turn on the ${name} shield on ${PROTECTION}`
      : `run \`node9 shield enable ${name}\``;
  },

  /** The same step as a bare line for a bullet list. */
  shieldLine(source: PolicySource, name: string): string {
    return source === 'workspace'
      ? `turn on the ${name} shield on ${PROTECTION}`
      : `node9 shield enable ${name}`;
  },

  /** Where one catalog check is set, as the parenthesis after "Set <id> to <value>". */
  checkWhere(source: PolicySource, id: string): string {
    return source === 'workspace' ? `on ${PROTECTION}` : `\`checks.${id}\` in the config file`;
  },

  /** A check named by its catalog title, for a reader who has no id to look up. */
  checkByTitle(source: PolicySource, title: string, value: string, localCommand: string): string {
    return source === 'workspace'
      ? `set the ${title} check to ${value} on ${PROTECTION}`
      : `\`${localCommand}\``;
  },

  /** The spend ceiling of behavior.cost-budget. */
  budget(source: PolicySource): string {
    return source === 'workspace'
      ? `the Runaway guard on ${USAGE}`
      : `tuning sessionUSD or dayUSD in ${CONFIG_FILE}`;
  },

  /** The page where tools are marked and shields live, for rows that only point at it. */
  protectionPage: PROTECTION,
};

/** One line under the first section of the report, on a workspace-governed machine. */
export const WORKSPACE_NOTE =
  'This machine follows the workspace policy: a local command or config file is ignored. ' +
  'A workspace admin makes these changes on the dashboard.';
