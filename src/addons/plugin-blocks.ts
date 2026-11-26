// src/addons/plugin-blocks.ts
// A Claude Code plugin the workspace blocked is turned off on the machine
// (node9Firewall#376 item 6). Blocking a plugin on the approved list stops its
// skills at each load, but its hooks and commands run with no tool call node9
// could stop; Claude Code's own switch (`enabledPlugins` in
// ~/.claude/settings.json) stops all of it from the agent's next session.
//
// Only an explicit block turns a plugin off: a plugin nobody decided on is
// left alone, whatever the rule for unapproved add-ons. What node9 changed is
// recorded (~/.node9/addons-disabled-plugins.json, with the value the setting
// had before), so when the block is lifted, or the list stops arriving (a
// downgrade, a logout), exactly that is put back, unless the person changed
// the setting in between. A settings file that does not parse is never
// rewritten. Best effort: any failure leaves both files as they were.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { atomicWriteSync } from '../utils/atomic-write';
import { installedPlugins } from './installed-plugins';
import type { AddonPolicy } from './policy';

type Previous = boolean | null; // null: the key was not set

interface DisabledRecord {
  plugins: Record<string, Previous>;
}

function settingsPath(home: string): string {
  return path.join(home, '.claude', 'settings.json');
}

function recordPath(home: string): string {
  return path.join(home, '.node9', 'addons-disabled-plugins.json');
}

function readRecord(home: string): DisabledRecord {
  try {
    const raw = JSON.parse(fs.readFileSync(recordPath(home), 'utf8')) as { plugins?: unknown };
    if (raw.plugins && typeof raw.plugins === 'object' && !Array.isArray(raw.plugins)) {
      const out: Record<string, Previous> = {};
      for (const [k, v] of Object.entries(raw.plugins as Record<string, unknown>))
        if (v === true || v === false || v === null) out[k] = v;
      return { plugins: out };
    }
  } catch {
    /* none yet */
  }
  return { plugins: {} };
}

/** What changed this time, for the daemon log and the tests. */
export interface PluginBlockChange {
  turnedOff: string[];
  restored: string[];
}

/**
 * Bring `enabledPlugins` in line with the blocks on the workspace's list.
 * `policy` undefined (no list) restores everything node9 turned off.
 */
export function applyPluginBlocks(
  policy: AddonPolicy | undefined,
  home: string = os.homedir()
): PluginBlockChange {
  const none: PluginBlockChange = { turnedOff: [], restored: [] };
  const record = readRecord(home);
  const blocked = new Set(
    Object.entries(policy?.plugins ?? {})
      .filter(([, d]) => d.decision === 'blocked')
      .map(([k]) => k)
  );
  const installed = new Set(installedPlugins(home, 5000).map((p) => p.key));
  const toTurnOff = [...blocked].filter((k) => installed.has(k));
  const toRestore = Object.keys(record.plugins).filter((k) => !blocked.has(k));
  if (toTurnOff.length === 0 && toRestore.length === 0) return none;

  let settings: Record<string, unknown>;
  let text: string | null = null;
  let mode: number | undefined;
  try {
    text = fs.readFileSync(settingsPath(home), 'utf8');
    mode = fs.statSync(settingsPath(home)).mode & 0o777;
  } catch {
    /* no settings file: start one */
  }
  try {
    const parsed: unknown = text === null ? {} : JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return none;
    settings = parsed as Record<string, unknown>;
  } catch {
    return none; // never rewrite a file we cannot read
  }
  const enabled: Record<string, unknown> =
    settings.enabledPlugins &&
    typeof settings.enabledPlugins === 'object' &&
    !Array.isArray(settings.enabledPlugins)
      ? { ...(settings.enabledPlugins as Record<string, unknown>) }
      : {};

  const change: PluginBlockChange = { turnedOff: [], restored: [] };
  for (const key of toTurnOff) {
    if (enabled[key] === false) continue;
    if (!(key in record.plugins))
      record.plugins[key] = typeof enabled[key] === 'boolean' ? (enabled[key] as boolean) : null;
    enabled[key] = false;
    change.turnedOff.push(key);
  }
  for (const key of toRestore) {
    const previous = record.plugins[key];
    delete record.plugins[key];
    if (enabled[key] !== false) continue; // the person changed it since: theirs
    if (previous === null) delete enabled[key];
    else enabled[key] = previous;
    change.restored.push(key);
  }

  try {
    if (change.turnedOff.length || change.restored.length) {
      fs.mkdirSync(path.dirname(settingsPath(home)), { recursive: true });
      atomicWriteSync(
        settingsPath(home),
        JSON.stringify({ ...settings, enabledPlugins: enabled }, null, 2) + '\n',
        // The file keeps the permissions it had.
        mode === undefined ? undefined : { mode }
      );
    }
    atomicWriteSync(recordPath(home), JSON.stringify(record), { mode: 0o600 });
  } catch {
    return none;
  }
  return change;
}
