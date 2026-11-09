// src/posture/agent-to-agent.ts
// Check: Agent-to-agent (OWASP ASI07, node9Firewall#428 item 3).
//
// An MCP server that is itself an agent (it spawns, delegates, runs tasks)
// returns another agent's words, written by whatever that agent read. node9
// holds a send after outside content only for servers with the source role,
// so such a server without the role is a gap. Config inspection only: the
// MCP inventory the agents have, the tools the gateway recorded for each
// server (~/.node9/mcp-tools.json), and the roles the user set.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { inventoryMcp } from '../mcp-wrap';
import type { McpToolsConfig } from '../daemon/mcp-tools';
import { getConfig } from '../config';
import type { CheckContext, Finding } from './types';

export const CATEGORY = 'Agent-to-agent';

/** A server name that says it runs agents. */
const AGENT_NAME_RE = /(^|[-_.])(agent|agents|a2a|crew|swarm|autogen|langgraph)([-_.]|$)/i;
/** A tool that hands work to another agent. */
const DELEGATION_TOOL_RE =
  /^(a2a[_-]|spawn_agent$|run_agent$|create_agent$|delegate|send_task$|create_task$|run_task$|submit_task$)/i;

export interface AgentServer {
  server: string;
  agents: string[];
  how: 'tools' | 'name';
  tools: string[];
}

type Roles = Record<string, Record<string, 'source' | 'action' | 'read'>>;

/** The tools the gateway recorded, read from the given home (tests use one). */
export function readToolsFor(home: string): McpToolsConfig {
  try {
    const raw = fs.readFileSync(path.join(home, '.node9', 'mcp-tools.json'), 'utf-8');
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? (parsed as McpToolsConfig) : {};
  } catch {
    return {};
  }
}

/** MCP servers on this machine that run other agents and carry no source
 *  role. Exported for tests. */
export function agentServers(home: string, roles: Roles, tools: McpToolsConfig): AgentServer[] {
  const byName = new Map<string, AgentServer>();
  for (const e of inventoryMcp(home)) {
    if (e.state === 'node9-self') continue;
    const role = roles[e.name] ?? roles[e.name.toLowerCase()];
    if (role && Object.values(role).some((r) => r === 'source')) continue; // covered
    const recorded = Object.entries(tools).find(
      ([key, cfg]) =>
        key.toLowerCase() === e.name.toLowerCase() ||
        (cfg?.name ?? '').toLowerCase() === e.name.toLowerCase()
    )?.[1];
    const delegating = (recorded?.tools ?? [])
      .map((t) => t.name)
      .filter((n) => DELEGATION_TOOL_RE.test(n));
    const how: AgentServer['how'] | null =
      delegating.length > 0 ? 'tools' : AGENT_NAME_RE.test(e.name) ? 'name' : null;
    if (!how) continue;
    const cur = byName.get(e.name);
    if (cur) {
      if (!cur.agents.includes(e.agentLabel)) cur.agents.push(e.agentLabel);
    } else byName.set(e.name, { server: e.name, agents: [e.agentLabel], how, tools: delegating });
  }
  return [...byName.values()];
}

export function checkAgentToAgent(ctx: CheckContext): Finding[] {
  const home = ctx.home || os.homedir();
  const config = getConfig(ctx.cwd);
  const roles = (config.policy.untrustedContent?.roles ?? {}) as Roles;
  const servers = agentServers(home, roles, readToolsFor(home));
  if (servers.length === 0) return [];
  const n = servers.length;
  return [
    {
      category: CATEGORY,
      severity: 'medium',
      title: `${n} MCP server${n === 1 ? '' : 's'} run${n === 1 ? 's' : ''} other agents, and what ${n === 1 ? 'it returns' : 'they return'} is not treated as outside content`,
      what: "A server here hands work to other agents: what it returns is another agent's words, written from whatever that agent read.",
      why: 'None of these servers carries the "Brings outside content" role, so the hold after exposure does not apply to what they return.',
      who: 'An agent on the other side reads a poisoned page; its answer comes back as a tool result, and this agent acts on it.',
      detail: servers
        .slice(0, 8)
        .map(
          (s) =>
            `${s.server} (${s.agents.join(', ')}, by ${s.how === 'tools' ? `tools: ${s.tools.slice(0, 4).join(', ')}` : 'name'})`
        ),
      owner: 'node9',
      fix: 'On the Apps page, mark these servers\' tools "Brings outside content" so a send after their results is held; keep behavior.untrusted-content on.',
    },
  ];
}
