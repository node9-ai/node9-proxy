// src/daemon/addons-index.ts
// Keeps ~/.node9/addons-index.json current (node9Firewall#376 item 6). The
// agent hook judges a call to an MCP server outside the gateway by the
// server's identity from that index, and the snapshot push that writes it
// runs hours apart: a server added or renamed since was not judged. The
// daemon now watches the agents' MCP config files (one stat each, every
// REFRESH_MS) and rebuilds the index when one changed: config reads only, no
// skill hashing.

import fs from 'fs';
import os from 'os';
import { AGENT_SPECS } from '../agent-wiring';
import { collectMcpDetail, collectMcpLists, type AddonMcp } from '../addons/collect';
import { claudeProjectMcpPackages } from '../addons/claude-mcp';
import { refreshPackageStanding } from '../addons/package-standing';
import { writeMcpIndex } from '../addons/index-file';
import { refreshMcpSeen } from '../addons/mcp-seen';
import { applyPluginBlocks } from '../addons/plugin-blocks';
import { _resetConfigCache, getConfig } from '../config';
import { pushPolicySnapshotSoon } from './sync';

export const REFRESH_MS = 30_000;

/** The MCP config files node9 reads, one per agent that has one. */
function mcpConfigFiles(home: string): string[] {
  const out: string[] = [];
  for (const spec of AGENT_SPECS) {
    if (!spec.mcpFile || spec.mcpInventory === false) continue;
    try {
      out.push(spec.mcpFile(home));
    } catch {
      /* a spec that cannot name its file has nothing to watch */
    }
  }
  return out;
}

/** What changes when any of those files is written, created or removed. */
export function mcpConfigSignature(home: string = os.homedir()): string {
  return mcpConfigFiles(home)
    .map((f) => {
      try {
        const st = fs.statSync(f);
        return `${f}:${st.size}:${st.mtimeMs}`;
      } catch {
        return `${f}:-`;
      }
    })
    .join('|');
}

/** The MCP list of the add-ons report as of the last rebuild, per home
 *  folder: what makes a rebuild news for the dashboard. In memory only. */
const lastReported = new Map<string, string>();

/** What the dashboard shows of a list: the servers, where each runs and for
 *  which agents. Not the day of a seen server's newest call. */
function listSummary(report: AddonMcp[]): string {
  return report
    .map((m) => `${m.name}\0${m.identity}\0${m.state}\0${[...m.agents].sort().join(',')}`)
    .sort()
    .join('\n');
}

/**
 * Rebuild the index when the agents' MCP configs changed since `last` (or
 * always, when `last` is undefined). Returns the signature to compare next
 * time. Never throws: a failure leaves the previous index.
 *
 * `onListChange` runs when the rebuild found a different list of servers
 * than the one before it (a server added, removed, re-pointed, or moved
 * behind the gateway). The config files' signature cannot say that:
 * ~/.claude.json holds prompt history and changes on every prompt. The first
 * rebuild after start only sets what to compare with; the sync at start
 * sends a snapshot anyway.
 */
export function refreshAddonsIndex(
  last: string | undefined,
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env,
  onListChange: () => void = () => {}
): string | undefined {
  let sig: string;
  try {
    sig = mcpConfigSignature(home);
  } catch {
    return last;
  }
  if (sig === last) return last;
  let summary: string;
  try {
    const lists = collectMcpLists(home, env);
    writeMcpIndex(
      lists.index.map((m) => ({
        name: m.name,
        identity: m.identity,
        state: m.state,
        agents: m.agents,
      })),
      home
    );
    summary = listSummary(lists.report);
  } catch {
    return last; // try again on the next tick
  }
  const before = lastReported.get(home);
  lastReported.set(home, summary);
  if (before !== undefined && before !== summary) {
    try {
      onListChange();
    } catch {
      /* a failed request for a push must not undo the rebuild */
    }
  }
  return sig;
}

/**
 * One round of the index: the servers no config names are brought up to
 * date from the audit log (mcp-seen.ts), then the index is rebuilt when an
 * agent config changed or that list did (a new server, a connector that just
 * got its name). `readAudit: false` skips the audit log: its first read can
 * be megabytes, and nothing the daemon does at start should wait on it.
 * `onListChange` runs once when either list changed (a server seen for the
 * first time, or one added to an agent's config): the daemon sends the
 * add-ons report soon instead of at the next policy sync, hours away.
 */
export function refreshIndexRound(
  last: string | undefined,
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env,
  readAudit = true,
  onListChange: () => void = () => {}
): string | undefined {
  let changed = readAudit && refreshMcpSeen(home);
  const next = refreshAddonsIndex(changed ? undefined : last, home, env, () => {
    changed = true;
  });
  if (changed) onListChange();
  return next;
}

/** One round: the index, and the plugins the workspace blocked turned off
 *  in Claude Code (addons/plugin-blocks.ts). */
function tick(last: string | undefined, readAudit: boolean): string | undefined {
  const next = refreshIndexRound(last, undefined, undefined, readAudit, pushPolicySnapshotSoon);
  try {
    // Fresh: the daemon's config cache is reset only when a check arrives,
    // and an idle machine must still pick up a new block from policy sync.
    _resetConfigCache();
    applyPluginBlocks(getConfig().policy.addons);
  } catch {
    /* never crash the daemon over a settings file */
  }
  return next;
}

/** The package check looks again at least this often: a stored result goes
 *  stale by its own clock (package-standing.ts), not by a config change. */
export const STANDING_EVERY_MS = 10 * 60_000;
const FIRST_STANDING_DELAY_MS = 60_000;

let standingRunning = false;

/**
 * The package check for the configured MCP servers (phase 4, check D). It asks
 * registries, so it runs here and never in a hook; a user who switched the
 * package check off gets no lookups. One run at a time; never throws.
 */
export async function refreshStandingOnce(
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env,
  run: typeof refreshPackageStanding = refreshPackageStanding
): Promise<void> {
  if (standingRunning) return;
  standingRunning = true;
  try {
    if (getConfig().policy.packageCheck?.enabled === false) return;
    const targets = collectMcpDetail(home, env).flatMap(({ entry, pkg }) =>
      pkg ? [{ identity: entry.identity, pkg }] : []
    );
    // And the servers Claude Code projects configure: the hook stops those
    // too, so their packages must be checked (release review 2026-11-27).
    const known = new Set(targets.map((t) => t.identity));
    for (const t of claudeProjectMcpPackages(home)) if (!known.has(t.identity)) targets.push(t);
    await run(targets, home);
  } catch {
    /* the next round tries again */
  } finally {
    standingRunning = false;
  }
}

/** Write the index now, then keep it (and the plugin blocks) current. */
export function startAddonsIndexRefresh(): void {
  let last: string | undefined;
  // The first package check waits a minute: nothing the daemon does at start
  // should wait on a registry. After that: on a config change (a server
  // added or re-pinned), and on its own clock.
  let standingAt = Date.now() - STANDING_EVERY_MS + FIRST_STANDING_DELAY_MS;
  let started = false;
  const round = () => {
    const before = last;
    // The round at start leaves the audit log for the next one.
    last = tick(last, started);
    const changed = started && last !== before;
    started = true;
    if (changed || Date.now() - standingAt >= STANDING_EVERY_MS) {
      standingAt = Date.now();
      void refreshStandingOnce();
    }
  };
  setImmediate(round);
  setInterval(round, REFRESH_MS).unref();
}
