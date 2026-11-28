// src/addons/claude-mcp.ts
// Claude Code's MCP servers, read straight from its config files on each
// hook call that needs them (node9Firewall#376 item 6, phase 3). The daemon's
// index (index-file.ts) can be hours old; read here, a server renamed or added
// since the last report is still judged by its identity, and a project's own
// `.mcp.json` is covered too. Only JSON, only the files Claude Code itself
// reads, and nothing from them leaves this function but names, identities and
// whether the server runs through node9.

import os from 'os';
import path from 'path';
import { MCP_WRAP_SUBCOMMAND, gatewayUpstream, parseNode9Launch } from '../mcp-entry';
import { tokenize } from '../mcp-cmd';
import { readSmallFile } from '../utils/read-small-file';
import {
  mcpIdentityFromCommand,
  mcpIdentityFromUrl,
  mcpPackageFromCommand,
  type McpPackage,
} from './identity';
import type { McpIndexEntry } from './index-file';

/** ~/.claude.json carries prompt history too; past this it is not read. */
const MAX_BYTES = 8 * 1024 * 1024;

function readJson(file: string): Record<string, unknown> | null {
  try {
    // One descriptor checks and reads (a link is followed: dotfile managers
    // link ~/.claude.json).
    const text = readSmallFile(file, MAX_BYTES);
    if (text === null) return null;
    const v = JSON.parse(text) as unknown;
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function serversOf(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

/** One config entry as an index entry; null for node9's own server. */
function entryOf(name: string, raw: unknown): McpIndexEntry | null {
  if (!raw || typeof raw !== 'object') return null;
  const s = raw as { command?: unknown; args?: unknown; url?: unknown };
  const launch = parseNode9Launch(s);
  if (launch) {
    const upstream =
      launch.subcommand === MCP_WRAP_SUBCOMMAND || gatewayUpstream(launch) !== null
        ? gatewayUpstream(launch)
        : null;
    if (!upstream) return null; // node9's own server, or a wrap it cannot read
    const [command, ...args] = tokenize(upstream);
    return {
      name,
      identity: mcpIdentityFromCommand(command ?? '', args),
      state: 'governed',
      agents: ['claude'],
    };
  }
  if (typeof s.command !== 'string' || s.command.trim() === '')
    return { name, identity: mcpIdentityFromUrl(s.url), state: 'remote', agents: ['claude'] };
  const args = Array.isArray(s.args)
    ? s.args.filter((a): a is string => typeof a === 'string')
    : [];
  return {
    name,
    identity: mcpIdentityFromCommand(s.command, args),
    state: 'outside',
    agents: ['claude'],
  };
}

/**
 * The servers Claude Code may load in `cwd`: user scope (`mcpServers` in
 * ~/.claude.json), local scope (`projects[<dir>].mcpServers` there) and
 * project scope (`<dir>/.mcp.json`), for the working directory and its parents.
 */
export function claudeMcpEntries(
  cwd: string | undefined,
  home: string = os.homedir()
): McpIndexEntry[] {
  const out: McpIndexEntry[] = [];
  const add = (servers: Record<string, unknown>) => {
    for (const [name, raw] of Object.entries(servers).slice(0, 200)) {
      const e = entryOf(name, raw);
      if (e) out.push(e);
    }
  };
  const user = readJson(path.join(home, '.claude.json'));
  add(serversOf(user?.mcpServers));
  if (cwd && path.isAbsolute(cwd)) {
    const projects = serversOf(user?.projects);
    let dir = path.resolve(cwd);
    for (let i = 0; i < 32; i++) {
      add(serversOf((projects[dir] as { mcpServers?: unknown } | undefined)?.mcpServers));
      if (dir !== home) add(serversOf(readJson(path.join(dir, '.mcp.json'))?.mcpServers));
      const up = path.dirname(dir);
      if (up === dir) break;
      dir = up;
    }
  }
  return out;
}

/** Project folders read for their MCP servers, at most. */
const MAX_PROJECTS = 200;

/** The command a config entry launches (the upstream, for a gateway wrap);
 *  null for a remote server or node9's own. */
function launchOf(raw: unknown): { command: string; args: string[] } | null {
  if (!raw || typeof raw !== 'object') return null;
  const s = raw as { command?: unknown; args?: unknown };
  const launch = parseNode9Launch(s);
  if (launch) {
    const upstream =
      launch.subcommand === MCP_WRAP_SUBCOMMAND || gatewayUpstream(launch) !== null
        ? gatewayUpstream(launch)
        : null;
    if (!upstream) return null;
    const [command, ...args] = tokenize(upstream);
    return command ? { command, args } : null;
  }
  if (typeof s.command !== 'string' || s.command.trim() === '') return null;
  const args = Array.isArray(s.args)
    ? s.args.filter((a): a is string => typeof a === 'string')
    : [];
  return { command: s.command, args };
}

/**
 * The names Claude Code's projects give their MCP servers (`projects[dir]
 * .mcpServers` in ~/.claude.json and each folder's `.mcp.json`), node9's own
 * included. The hook judges a call to such a server by what its config runs
 * (claudeMcpEntries), so the list of servers seen only in calls
 * (mcp-seen.ts) must leave these names out. Daemon and CLI only.
 */
export function claudeProjectMcpNames(home: string = os.homedir()): string[] {
  const out = new Set<string>();
  const add = (servers: Record<string, unknown>) => {
    for (const name of Object.keys(servers).slice(0, 200)) out.add(name);
  };
  const projects = serversOf(readJson(path.join(home, '.claude.json'))?.projects);
  for (const [dir, p] of Object.entries(projects).slice(0, MAX_PROJECTS)) {
    add(serversOf((p as { mcpServers?: unknown } | null)?.mcpServers));
    if (path.isAbsolute(dir) && path.resolve(dir) !== path.resolve(home))
      add(serversOf(readJson(path.join(dir, '.mcp.json'))?.mcpServers));
  }
  return [...out];
}

/**
 * The registry packages the MCP servers of Claude Code's projects run: the
 * servers each project in ~/.claude.json configures (`projects[dir]
 * .mcpServers`) and the ones in that folder's `.mcp.json`. The hook stops a
 * call to such a server when its package is malicious (resolve.ts), so the
 * daemon's package check must know about them as it knows the user-level ones
 * (release review 2026-11-27). Daemon only: it reads a file per project.
 */
export function claudeProjectMcpPackages(
  home: string = os.homedir()
): Array<{ identity: string; pkg: McpPackage }> {
  const out = new Map<string, McpPackage>();
  const add = (servers: Record<string, unknown>) => {
    for (const raw of Object.values(servers).slice(0, 200)) {
      const l = launchOf(raw);
      const pkg = l ? mcpPackageFromCommand(l.command, l.args) : null;
      if (l && pkg) {
        const identity = mcpIdentityFromCommand(l.command, l.args);
        if (!out.has(identity)) out.set(identity, pkg);
      }
    }
  };
  const projects = serversOf(readJson(path.join(home, '.claude.json'))?.projects);
  for (const [dir, p] of Object.entries(projects).slice(0, MAX_PROJECTS)) {
    add(serversOf((p as { mcpServers?: unknown } | null)?.mcpServers));
    if (path.isAbsolute(dir) && path.resolve(dir) !== path.resolve(home))
      add(serversOf(readJson(path.join(dir, '.mcp.json'))?.mcpServers));
  }
  return [...out].map(([identity, pkg]) => ({ identity, pkg }));
}
