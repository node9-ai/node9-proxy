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
import { collectMcpDetail, collectMcpOnly } from '../addons/collect';
import { refreshPackageStanding } from '../addons/package-standing';
import { writeMcpIndex } from '../addons/index-file';
import { applyPluginBlocks } from '../addons/plugin-blocks';
import { _resetConfigCache, getConfig } from '../config';

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

/**
 * Rebuild the index when the agents' MCP configs changed since `last` (or
 * always, when `last` is undefined). Returns the signature to compare next
 * time. Never throws: a failure leaves the previous index.
 */
export function refreshAddonsIndex(
  last: string | undefined,
  home: string = os.homedir(),
  env: NodeJS.ProcessEnv = process.env
): string | undefined {
  let sig: string;
  try {
    sig = mcpConfigSignature(home);
  } catch {
    return last;
  }
  if (sig === last) return last;
  try {
    writeMcpIndex(
      collectMcpOnly(home, env).map((m) => ({
        name: m.name,
        identity: m.identity,
        state: m.state,
        agents: m.agents,
      })),
      home
    );
  } catch {
    return last; // try again on the next tick
  }
  return sig;
}

/** One round: the index, and the plugins the workspace blocked turned off
 *  in Claude Code (addons/plugin-blocks.ts). */
function tick(last: string | undefined): string | undefined {
  const next = refreshAddonsIndex(last);
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
  let standingAt = 0;
  const round = () => {
    const before = last;
    last = tick(last);
    // On a config change (a server added or re-pinned), and on its own clock.
    if (last !== before || Date.now() - standingAt >= STANDING_EVERY_MS) {
      standingAt = Date.now();
      void refreshStandingOnce();
    }
  };
  setImmediate(round);
  setInterval(round, REFRESH_MS).unref();
}
