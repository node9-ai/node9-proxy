// src/addons/index-file.ts
// The MCP part of the add-ons inventory, kept on the machine for the agent
// hook (node9Firewall#376 item 6, phase 3). The hook judges a call to
// `mcp__<server>__<tool>` by the server's identity, and the agents' configs
// it would need to read for that reach the CLI setup code, which the hook
// bundle must not carry. So whoever collects the inventory (the daemon on
// each snapshot push, `node9 policy push`) writes this small file, and the
// hook reads it.
//
// What it holds is what the snapshot already sends: config names, identities,
// whether the server runs through node9, and which agents load it. No
// argument, path or env value.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { atomicWriteSync } from '../utils/atomic-write';

export interface McpIndexEntry {
  /** The name in the agent's config, as written there. */
  name: string;
  identity: string;
  state: 'governed' | 'outside' | 'remote';
  /** Agent ids (`claude`, `codex`...). */
  agents: string[];
}

const MAX_ENTRIES = 200;

export function addonsIndexPath(home: string = os.homedir()): string {
  return path.join(home, '.node9', 'addons-index.json');
}

/** Write the index. Best effort: a failure leaves the previous one. */
export function writeMcpIndex(entries: McpIndexEntry[], home: string = os.homedir()): void {
  try {
    const mcp = entries.slice(0, MAX_ENTRIES).map((e) => ({
      name: e.name,
      identity: e.identity,
      state: e.state,
      agents: e.agents,
    }));
    const data = JSON.stringify({ v: 1, mcp });
    // The daemon refreshes often (Claude Code rewrites its config all the
    // time): an unchanged index is not written again.
    try {
      if (fs.readFileSync(addonsIndexPath(home), 'utf8') === data) return;
    } catch {
      /* none yet */
    }
    atomicWriteSync(addonsIndexPath(home), data, { mode: 0o600 });
  } catch {
    /* the hook then judges no MCP server outside the gateway until the next write */
  }
}

/** The index, or none when it was never written or cannot be read. */
export function readMcpIndex(home: string = os.homedir()): McpIndexEntry[] {
  try {
    const raw = JSON.parse(fs.readFileSync(addonsIndexPath(home), 'utf8')) as { mcp?: unknown };
    if (!Array.isArray(raw.mcp)) return [];
    const out: McpIndexEntry[] = [];
    for (const e of raw.mcp.slice(0, MAX_ENTRIES)) {
      const r = e as Partial<McpIndexEntry> | null;
      if (
        typeof r?.name === 'string' &&
        typeof r.identity === 'string' &&
        (r.state === 'governed' || r.state === 'outside' || r.state === 'remote') &&
        Array.isArray(r.agents)
      )
        out.push({
          name: r.name,
          identity: r.identity,
          state: r.state,
          agents: r.agents.filter((a): a is string => typeof a === 'string'),
        });
    }
    return out;
  } catch {
    return [];
  }
}
