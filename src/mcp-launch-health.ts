// src/mcp-launch-health.ts
// What can be read, without starting anything, about whether node9's MCP
// entries start: which entries still depend on the Node the agent's PATH
// holds, whether the launcher points anywhere, and whether node9 has already
// refused to run on an old Node from one of them.
//
// Read by `node9 doctor` and by the daemon's reconcile pass. The failure
// itself is silent for the user: the agent reports "failed to connect" and
// nothing else, for node9's own server and for every server node9 wrapped.
import fs from 'fs';
import os from 'os';
import path from 'path';
import { AGENT_SPECS, readMcpServers, type McpFormat } from './agent-wiring';
import { parseNode9Launch, gatewayUpstream } from './mcp-entry';
import { shimPath, isShimTargetStale, resolvesToJsFile } from './node9-shim';

export const MCP_NODE_FAILURE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

// hook-debug.log has no size cap, and with NODE9_DEBUG on it grows by a line
// per tool call (136 MB on the machine this was measured on). The tail is
// what a status check may read.
const LOG_TAIL_BYTES = 8 * 1024 * 1024;

// The line launch.ts writes when node9 refuses to run. Anchored at the start
// of the line on purpose: the same log holds hook payloads, and a payload can
// quote this text (a session that discusses the failure does).
const NODE_FAILURE_LINE =
  /^\[(\d{4}-\d\d-\d\dT[\d:.]+Z)\] UNSUPPORTED NODE \((?:mcp-server|mcp-gateway|mcp)\): node9: Node\.js (\S+) \(([^)]*)\)/;

export interface McpNodeFailures {
  /** Refusals inside the window, in the part of the log that was read. */
  count: number;
  /** Time of the newest one, ms since epoch. */
  lastAt: number;
  /** The Node that was refused, from the newest line: `v18.19.1`. */
  version: string;
  /** Its path: `/usr/bin/node`. */
  execPath: string;
  /** True when the log is longer than the tail read, so `count` is a floor. */
  partial: boolean;
}

/**
 * node9's refusals to start an MCP entry on an old Node, in the last 7 days.
 * null when there are none, or the log cannot be read.
 */
export function readMcpNodeFailures(
  home: string = os.homedir(),
  now: number = Date.now()
): McpNodeFailures | null {
  let text: string;
  let partial = false;
  try {
    const file = path.join(home, '.node9', 'hook-debug.log');
    const fd = fs.openSync(file, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      const start = Math.max(0, size - LOG_TAIL_BYTES);
      const buf = Buffer.alloc(size - start);
      fs.readSync(fd, buf, 0, buf.length, start);
      text = buf.toString('utf-8');
      if (start > 0) {
        partial = true;
        // The read began mid-line: drop what is left of that line.
        text = text.slice(text.indexOf('\n') + 1);
      }
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
  let found: McpNodeFailures | null = null;
  for (const line of text.split('\n')) {
    if (!line.startsWith('[')) continue;
    const m = NODE_FAILURE_LINE.exec(line);
    if (!m) continue;
    const at = Date.parse(m[1]);
    if (Number.isNaN(at) || now - at > MCP_NODE_FAILURE_WINDOW_MS || at > now + 60_000) continue;
    if (!found) found = { count: 0, lastAt: at, version: m[2], execPath: m[3], partial };
    found.count++;
    if (at >= found.lastAt) {
      found.lastAt = at;
      found.version = m[2];
      found.execPath = m[3];
    }
  }
  return found;
}

export interface McpEntryGroup {
  agent: string; // AgentSpec.id
  agentLabel: string;
  setupCommand: string;
  names: string[];
}

export interface McpLaunchHealth {
  /** node9's own server and wraps, in every agent config node9 knows. */
  total: number;
  /** Entries that start through ~/.node9/bin/node9. */
  onLauncher: number;
  /** Entries a person pinned: a Node in front of the script, or the hook shim. */
  pinnedByHand: number;
  /** Entries that start on whatever Node the agent's PATH holds, per agent. */
  pathDependent: McpEntryGroup[];
  /** The newest change to a config file that holds a node9 entry (mtime, ms). */
  newestConfigChange: number;
}

/**
 * True when the entry starts on the first `node` of the agent's PATH: the
 * bare name or a path to the JavaScript bin (both go through `#!/usr/bin/env
 * node`), or a bare `node` in front of the script.
 */
function dependsOnPathNode(form: string, launcher: string[]): boolean {
  const hasSeparator = /[\\/]/.test(launcher[0]);
  if (form === 'runtime') return !hasSeparator;
  if (form !== 'bin') return false;
  return !hasSeparator || resolvesToJsFile(launcher[0]);
}

/**
 * How node9's MCP entries start, across every agent config, including the
 * agents the inventory leaves out (Windsurf, VS Code, Claude Desktop).
 * Config inspection only.
 */
export function mcpLaunchHealth(home: string = os.homedir()): McpLaunchHealth {
  const health: McpLaunchHealth = {
    total: 0,
    onLauncher: 0,
    pinnedByHand: 0,
    pathDependent: [],
    newestConfigChange: 0,
  };
  for (const spec of AGENT_SPECS) {
    if (!spec.mcpFile) continue;
    const mcpFile = spec.mcpFile(home);
    const format: McpFormat = spec.mcpFormat ?? 'json';
    const names: string[] = [];
    let holdsNode9Entry = false;
    for (const [name, server] of Object.entries(readMcpServers(mcpFile, format))) {
      if (!server || typeof server !== 'object') continue;
      const launch = parseNode9Launch(server);
      if (!launch) continue;
      const isWrap = gatewayUpstream(launch) !== null;
      if (!isWrap && launch.subcommand !== 'mcp-server') continue;
      holdsNode9Entry = true;
      health.total++;
      if (launch.form === 'launcher') health.onLauncher++;
      else if (dependsOnPathNode(launch.form, launch.launcher)) names.push(name);
      else if (launch.form === 'runtime' || launch.form === 'hook-shim') health.pinnedByHand++;
    }
    if (holdsNode9Entry) {
      try {
        health.newestConfigChange = Math.max(
          health.newestConfigChange,
          fs.statSync(mcpFile).mtimeMs
        );
      } catch {
        /* removed between the read and the stat: nothing to add */
      }
    }
    if (names.length > 0) {
      health.pathDependent.push({
        agent: String(spec.id),
        agentLabel: spec.label,
        setupCommand: spec.setupCommand,
        names,
      });
    }
  }
  return health;
}

export interface LauncherState {
  state: 'missing' | 'ok' | 'stale';
  path: string;
  /** The Node the launcher pins, when its body says. */
  node?: string;
}

/** The launcher as it is on disk. `stale`: its Node or its node9 is gone. */
export function launcherState(home: string = os.homedir()): LauncherState {
  const file = shimPath('node9', home);
  let body: string;
  try {
    body = fs.readFileSync(file, 'utf-8');
  } catch {
    return { state: 'missing', path: file };
  }
  const node = /^node="([^"]+)"$/m.exec(body)?.[1];
  return { state: isShimTargetStale(file) ? 'stale' : 'ok', path: file, node };
}
