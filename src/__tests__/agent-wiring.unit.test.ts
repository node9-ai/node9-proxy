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
import { claudeDesktopConfigPath } from '../setup';

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
    delete process.env.XDG_CONFIG_HOME; // deterministic opencode config path
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('covers all twelve supported agents', () => {
    expect(AGENT_SPECS.map((s) => s.id).sort()).toEqual(
      [
        'antigravity',
        'claude',
        'codex',
        'copilot',
        'cursor',
        'gemini',
        'hermes',
        'opencode',
        'pi',
        'claudeDesktop',
        'vscode',
        'windsurf',
      ].sort()
    );
  });

  // ── MCP-only agents the old getAgentsStatus knew and this registry lacked (fw#421 P3) ──
  it('wires Windsurf, VSCode and Claude Desktop through their MCP config', () => {
    const node9 = { mcpServers: { node9: { command: 'node9', args: ['mcp-server'] } } };
    writeJson('.codeium/windsurf/mcp_config.json', node9);
    // VSCode keys its MCP config under `servers`, not `mcpServers`.
    writeJson('.vscode/mcp.json', { servers: node9.mcpServers });
    const desktop = claudeDesktopConfigPath(home);
    if (desktop) {
      fs.mkdirSync(path.dirname(desktop), { recursive: true });
      fs.writeFileSync(desktop, JSON.stringify(node9));
    }
    const rows = getAgentWiring(home);
    for (const id of ['windsurf', 'vscode', ...(desktop ? ['claudeDesktop'] : [])]) {
      const row = rows.find((a) => a.id === id);
      expect(row?.installed, id).toBe(true);
      expect(row?.mcpProtected, id).toBe(true);
      expect(row?.isProtected, id).toBe(true);
      expect(row?.hooks, id).toEqual([]);
    }
  });

  it('an installed Windsurf without node9 on its servers is not protected', () => {
    writeJson('.codeium/windsurf/mcp_config.json', { mcpServers: { github: { command: 'npx' } } });
    const row = getAgentWiring(home).find((a) => a.id === 'windsurf');
    expect(row?.installed).toBe(true);
    expect(row?.isProtected).toBe(false);
  });

  // ── Codex MCP via TOML (#3) ──────────────────────────────────────────────
  it('detects node9 in Codex config.toml (mcp_servers, TOML)', () => {
    const p = path.join(home, '.codex', 'config.toml');
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, '[mcp_servers.node9]\ncommand = "node9"\nargs = ["mcp-server"]\n');
    const codex = getAgentWiring(home).find((a) => a.id === 'codex');
    expect(codex?.mcpProtected).toBe(true);
    expect(codex?.mcpServers).toContain('node9 → mcp-server');
    expect(codex?.isProtected).toBe(true); // protected via MCP even with no hooks
  });

  it('reports no Codex MCP when config.toml lacks a node9 entry', () => {
    const p = path.join(home, '.codex', 'config.toml');
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, '[mcp_servers.github]\ncommand = "npx"\n');
    const codex = getAgentWiring(home).find((a) => a.id === 'codex');
    expect(codex?.mcpProtected).toBe(false);
  });

  // ── Shim agents: OpenCode + Pi (#3) ──────────────────────────────────────
  it('wires OpenCode/Pi by the presence of the node9 plugin/extension file', () => {
    fs.mkdirSync(path.join(home, '.config', 'opencode', 'plugins'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.config', 'opencode', 'plugins', 'node9.js'),
      '// node9 shim'
    );
    fs.mkdirSync(path.join(home, '.pi', 'agent', 'extensions'), { recursive: true });
    fs.writeFileSync(path.join(home, '.pi', 'agent', 'extensions', 'node9.js'), '// node9 shim');

    const oc = getAgentWiring(home).find((a) => a.id === 'opencode');
    expect(oc?.isProtected).toBe(true);
    expect(oc?.hooks).toEqual([{ label: 'node9 plugin (node9 check)', wired: true }]);
    expect(oc?.mcpServers).toBeNull(); // no MCP surface

    const pi = getAgentWiring(home).find((a) => a.id === 'pi');
    expect(pi?.isProtected).toBe(true);
  });

  it('reports a shim agent unwired when its config dir exists but the shim is missing', () => {
    fs.mkdirSync(path.join(home, '.config', 'opencode'), { recursive: true });
    const oc = getAgentWiring(home).find((a) => a.id === 'opencode');
    expect(oc?.present).toBe(true);
    expect(oc?.wireState).toBe('unwired');
    expect(oc?.isProtected).toBe(false);
  });

  // Issue #186 (still open for custom XDG): opencode honors $XDG_CONFIG_HOME,
  // so its config dir is $XDG_CONFIG_HOME/opencode. doctor's present() must
  // respect XDG or it reports opencode absent on a custom-XDG machine.
  it('detects opencode present under a custom $XDG_CONFIG_HOME (issue #186)', () => {
    const xdg = path.join(home, 'custom-xdg');
    fs.mkdirSync(path.join(xdg, 'opencode'), { recursive: true });
    process.env.XDG_CONFIG_HOME = xdg;
    try {
      const oc = getAgentWiring(home).find((a) => a.id === 'opencode');
      expect(oc?.present).toBe(true);
    } finally {
      delete process.env.XDG_CONFIG_HOME;
    }
  });

  // Write/remove path: the opencode shim is written to (setupOpencode) and
  // removed from (teardownOpencode) shimFile(home). It MUST resolve under a
  // custom $XDG_CONFIG_HOME too, or detection (present) and the write path
  // would disagree — node9 would detect opencode under XDG but write the hook
  // to ~/.config (detected-but-not-protected). Closes the #186 loop.
  it('locates the opencode shim under a custom $XDG_CONFIG_HOME (write path, #186)', () => {
    const xdg = path.join(home, 'custom-xdg');
    process.env.XDG_CONFIG_HOME = xdg;
    try {
      const spec = AGENT_SPECS.find((s) => s.id === 'opencode');
      expect(spec?.shimFile?.(home)).toBe(path.join(xdg, 'opencode', 'plugins', 'node9.js'));
    } finally {
      delete process.env.XDG_CONFIG_HOME;
    }
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

  it('lists Codex PostToolUse (node9 log) and reads it from hooks.json (node9Firewall#428)', () => {
    writeJson('.codex/hooks.json', {
      hooks: {
        PreToolUse: [matcher],
        PostToolUse: [{ matcher: '.*', hooks: [{ command: 'node9 log' }] }],
      },
    });
    const codex = getAgentWiring(home).find((a) => a.id === 'codex')!;
    const post = codex.hooks.find((h) => h.label.startsWith('PostToolUse'));
    expect(post?.wired).toBe(true);
    // Without it in the file, the row shows and is not wired.
    writeJson('.codex/hooks.json', { hooks: { PreToolUse: [matcher] } });
    const again = getAgentWiring(home).find((a) => a.id === 'codex')!;
    expect(again.hooks.find((h) => h.label.startsWith('PostToolUse'))?.wired).toBe(false);
    expect(again.wireState).toBe('wired'); // the primary hook decides the state
  });

  it('lists Codex SessionStart (the session notice) so a missing one shows', () => {
    writeJson('.codex/hooks.json', {
      hooks: {
        PreToolUse: [matcher],
        SessionStart: [{ hooks: [{ command: 'node9 check --agent codex' }] }],
      },
    });
    const codex = getAgentWiring(home).find((a) => a.id === 'codex')!;
    expect(codex.hooks.find((h) => h.label.startsWith('SessionStart'))?.wired).toBe(true);
    // An install that predates it: the row shows, not wired; the state holds.
    writeJson('.codex/hooks.json', { hooks: { PreToolUse: [matcher] } });
    const again = getAgentWiring(home).find((a) => a.id === 'codex')!;
    expect(again.hooks.find((h) => h.label.startsWith('SessionStart'))?.wired).toBe(false);
    expect(again.wireState).toBe('wired');
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
  it('S2 reports each hook event independently (pre wired, post not, prompt absent)', () => {
    const noNode9 = { matcher: '*', hooks: [{ command: 'other-tool' }] };
    writeJson('.claude/settings.json', {
      hooks: { PreToolUse: [matcher], PostToolUse: [noNode9] },
    });
    const claude = getAgentWiring(home).find((a) => a.id === 'claude');
    // The spec must list UserPromptSubmit for Claude: setup.ts has written that
    // hook since prompt DLP shipped, but the spec did not name it, so status and
    // doctor never showed the row and could not report it missing.
    expect(claude?.hooks).toEqual([
      { label: 'PreToolUse  (node9 check)', wired: true }, // status-aligned label
      { label: 'PostToolUse (node9 log)', wired: false },
      { label: 'UserPromptSubmit (node9 check)', wired: false },
    ]);
    expect(claude?.hooks?.[0]?.wired).toBe(true); // known-true: primary row unchanged
    expect(claude?.isProtected).toBe(true);
  });

  it('S1 all three Claude hooks report wired when settings.json carries them', () => {
    const logMatcher = { matcher: '*', hooks: [{ command: 'node9 log' }] };
    writeJson('.claude/settings.json', {
      hooks: { PreToolUse: [matcher], PostToolUse: [logMatcher], UserPromptSubmit: [matcher] },
    });
    const claude = getAgentWiring(home).find((a) => a.id === 'claude');
    expect(claude?.hooks).toEqual([
      { label: 'PreToolUse  (node9 check)', wired: true },
      { label: 'PostToolUse (node9 log)', wired: true },
      { label: 'UserPromptSubmit (node9 check)', wired: true },
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
