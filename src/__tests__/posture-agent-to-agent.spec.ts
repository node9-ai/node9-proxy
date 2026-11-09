import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { agentServers, checkAgentToAgent, readToolsFor } from '../posture/agent-to-agent';

// Posture: an MCP server that runs other agents (node9Firewall#428 item 3).
// The inventory comes from the agents' MCP files under HOME; the tools from
// the gateway's record; the roles from the policy.

let home: string;
const write = (rel: string, obj: unknown) => {
  const p = path.join(home, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj));
};

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-a2a-'));
  write('.claude.json', {
    mcpServers: {
      'crew-runner': { command: 'npx', args: ['-y', 'crew-mcp'] },
      tasks: { command: 'npx', args: ['-y', 'tasks-mcp'] },
      filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] },
    },
  });
  write('.node9/mcp-tools.json', {
    tasks: {
      name: 'tasks',
      status: 'approved',
      disabled: [],
      tools: [{ name: 'list_tasks' }, { name: 'spawn_agent' }, { name: 'send_task' }],
    },
    filesystem: {
      name: 'filesystem',
      status: 'approved',
      disabled: [],
      tools: [{ name: 'read_file' }, { name: 'write_file' }],
    },
  });
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

describe('posture: agent-to-agent', () => {
  it('names a server by its delegation tools, and one by its name; a plain server is not one', () => {
    const found = agentServers(home, {}, readToolsFor(home));
    const byName = Object.fromEntries(found.map((s) => [s.server, s]));
    expect(byName['tasks']?.how).toBe('tools');
    expect(byName['tasks']?.tools).toEqual(['spawn_agent', 'send_task']);
    expect(byName['crew-runner']?.how).toBe('name');
    expect(byName['filesystem']).toBeUndefined();
  });

  it('a server whose role already says "brings outside content" is covered', () => {
    const found = agentServers(home, { tasks: { spawn_agent: 'source' } }, readToolsFor(home));
    expect(found.map((s) => s.server)).toEqual(['crew-runner']);
  });

  it('the finding names the servers and how, and an empty home yields none', () => {
    const [f] = checkAgentToAgent({ home, cwd: home } as never);
    expect(f.category).toBe('Agent-to-agent');
    expect(f.severity).toBe('medium');
    expect(f.detail.join(' ')).toContain('tasks');
    expect(f.detail.join(' ')).toContain('spawn_agent');
    expect(f.owner).toBe('node9');
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-a2a-empty-'));
    expect(checkAgentToAgent({ home: empty, cwd: empty } as never)).toEqual([]);
    fs.rmSync(empty, { recursive: true, force: true });
  });

  it('a missing or broken tools record reads as no tools', () => {
    expect(readToolsFor(path.join(home, 'nope'))).toEqual({});
    fs.writeFileSync(path.join(home, '.node9', 'mcp-tools.json'), 'not-json{{{');
    expect(readToolsFor(home)).toEqual({});
  });
});
