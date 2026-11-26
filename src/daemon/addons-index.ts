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
import { collectMcpOnly } from '../addons/collect';
import { writeMcpIndex } from '../addons/index-file';

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

/** Write the index now, then keep it current. */
export function startAddonsIndexRefresh(): void {
  let last: string | undefined;
  setImmediate(() => {
    last = refreshAddonsIndex(last);
  });
  setInterval(() => {
    last = refreshAddonsIndex(last);
  }, REFRESH_MS).unref();
}
