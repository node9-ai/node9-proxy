/**
 * Unit tests for the shared agent-wiring registry (used by `node9 doctor`).
 * Verifies each agent's wire-state detection against a synthetic home dir —
 * the contract doctor relies on to report all supported agents, not just 3.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { getAgentWiring, AGENT_SPECS } from '../agent-wiring';

const NODE9_HOOK = { command: 'node9 check' };
const matcher = { matcher: '*', hooks: [NODE9_HOOK] };

let home: string;
const writeJson = (rel: string, obj: unknown) => {
  const p = path.join(home, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj));
};
const stateOf = (id: string) => getAgentWiring(home).find((a) => a.id === id)?.wireState;

describe('agent-wiring registry', () => {
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-wiring-'));
    delete process.env.HERMES_HOME; // deterministic Hermes path under `home`
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('covers all seven hook-wired agents', () => {
    expect(AGENT_SPECS.map((s) => s.id).sort()).toEqual(
      ['antigravity', 'claude', 'codex', 'copilot', 'cursor', 'gemini', 'hermes'].sort()
    );
  });

  it('reports every agent as absent on an empty home', () => {
    for (const a of getAgentWiring(home)) {
      expect(a.wireState).toBe('absent');
    }
  });

  it('detects a wired Claude (matcher-format PreToolUse)', () => {
    writeJson('.claude/settings.json', { hooks: { PreToolUse: [matcher] } });
    expect(stateOf('claude')).toBe('wired');
  });

  it('detects a wired Codex (matcher-format) and Copilot (flat-format)', () => {
    writeJson('.codex/hooks.json', { hooks: { PreToolUse: [matcher] } });
    writeJson('.copilot/hooks/node9.json', { hooks: { PreToolUse: [NODE9_HOOK] } });
    expect(stateOf('codex')).toBe('wired');
    expect(stateOf('copilot')).toBe('wired');
  });

  it('treats Cursor as MCP-only — no hook file, protection comes from MCP', () => {
    // Even if a stray hooks.json exists, Cursor is not hook-wired by node9.
    writeJson('.cursor/hooks.json', { hooks: { preToolUse: [NODE9_HOOK] } });
    const cursor = getAgentWiring(home).find((a) => a.id === 'cursor');
    expect(cursor?.wireState).toBe('absent'); // hooks ignored
    expect(cursor?.hooks).toEqual([]);
    expect(cursor?.isProtected).toBe(false); // no node9 MCP server present
  });

  it('reports unwired when the settings file exists but has no node9 hook', () => {
    writeJson('.gemini/settings.json', { hooks: { BeforeTool: [] } });
    expect(stateOf('gemini')).toBe('unwired');
  });

  it('reports invalid for a corrupt settings file', () => {
    const p = path.join(home, '.claude', 'settings.json');
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, '{ not json');
    expect(stateOf('claude')).toBe('invalid');
  });

  it('marks an agent installed when its config dir exists', () => {
    writeJson('.claude/settings.json', { hooks: { PreToolUse: [matcher] } });
    const claude = getAgentWiring(home).find((a) => a.id === 'claude');
    expect(claude?.installed).toBe(true);
  });

  // ── Multi-hook (workstream A) ────────────────────────────────────────────
  it('reports each hook event independently (pre wired, post not)', () => {
    const noNode9 = { matcher: '*', hooks: [{ command: 'other-tool' }] };
    writeJson('.claude/settings.json', {
      hooks: { PreToolUse: [matcher], PostToolUse: [noNode9] },
    });
    const claude = getAgentWiring(home).find((a) => a.id === 'claude');
    expect(claude?.hooks).toEqual([
      { label: 'PreToolUse (node9 check)', wired: true },
      { label: 'PostToolUse (node9 log)', wired: false },
    ]);
    expect(claude?.isProtected).toBe(true);
  });

  // ── MCP surface (workstream A) ───────────────────────────────────────────
  it('detects node9 MCP wrapping and marks the agent protected', () => {
    writeJson('.cursor/mcp.json', {
      mcpServers: {
        node9: { command: 'node9', args: ['mcp-server'] },
        github: { command: 'node9', args: ['npx', '-y', '@mcp/github'] },
      },
    });
    const cursor = getAgentWiring(home).find((a) => a.id === 'cursor');
    // No hooks.json → legacy hook state absent…
    expect(cursor?.wireState).toBe('absent');
    // …but node9 IS protecting Cursor via MCP — the correctness win.
    expect(cursor?.mcpProtected).toBe(true);
    expect(cursor?.mcpServers).toContain('github → npx -y @mcp/github');
    expect(cursor?.isProtected).toBe(true);
  });

  it('exposes mcpServers=[] for an MCP-capable agent with no config, null for one without a surface', () => {
    const rows = getAgentWiring(home); // empty home
    expect(rows.find((a) => a.id === 'cursor')?.mcpServers).toEqual([]); // has surface, no file
    expect(rows.find((a) => a.id === 'cursor')?.mcpProtected).toBe(false);
    expect(rows.find((a) => a.id === 'hermes')?.mcpServers).toBeNull(); // no MCP surface
  });

  it('isProtected is false for a fully unconfigured agent', () => {
    const claude = getAgentWiring(home).find((a) => a.id === 'claude');
    expect(claude?.isProtected).toBe(false);
  });
});
