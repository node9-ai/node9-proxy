/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';
import {
  setupClaude,
  setupGemini,
  setupCursor,
  setupCodex,
  teardownClaude,
  teardownGemini,
  teardownCursor,
  teardownCodex,
  detectAgents,
} from '../setup.js';

vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));

vi.spyOn(fs, 'existsSync').mockReturnValue(false);
vi.spyOn(fs, 'readFileSync');
vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');

async function getConfirm() {
  return vi.mocked((await import('@inquirer/prompts')).confirm);
}

// Returns the parsed JSON of the LAST write to a given file path
// (Gemini writes the same file twice: hooks first, then MCP servers)
function writtenTo(filePath: string): any {
  const calls = vi.mocked(fs.writeFileSync).mock.calls.filter(([p]) => String(p) === filePath);
  if (calls.length === 0) return null;
  return JSON.parse(String(calls[calls.length - 1][1]));
}

function withExistingFile(filePath: string, content: object) {
  vi.mocked(fs.existsSync).mockImplementation((p) => String(p) === filePath);
  vi.mocked(fs.readFileSync).mockImplementation((p) => {
    if (String(p) === filePath) return JSON.stringify(content);
    throw new Error('not found');
  });
}

function withExistingFiles(files: Record<string, object>) {
  vi.mocked(fs.existsSync).mockImplementation((p) => String(p) in files);
  vi.mocked(fs.readFileSync).mockImplementation((p) => {
    const content = files[String(p)];
    if (content !== undefined) return JSON.stringify(content);
    throw new Error('not found');
  });
}

function withExistingTomlFile(filePath: string, content: object) {
  vi.mocked(fs.existsSync).mockImplementation((p) => String(p) === filePath);
  vi.mocked(fs.readFileSync).mockImplementation((p) => {
    if (String(p) === filePath) return stringifyToml(content as Record<string, unknown>);
    throw new Error('not found');
  });
}

// Returns the parsed TOML of the LAST write to a given file path
function writtenTomlTo(filePath: string): any {
  const calls = vi.mocked(fs.writeFileSync).mock.calls.filter(([p]) => String(p) === filePath);
  if (calls.length === 0) return null;
  return parseToml(String(calls[calls.length - 1][1]));
}

/** The node9 MCP server entry that setup.ts auto-injects. */
const NODE9_MCP_ENTRY = { command: 'node9', args: ['mcp-server'] };

beforeEach(() => {
  vi.mocked(fs.existsSync).mockReturnValue(false);
  vi.mocked(fs.writeFileSync).mockClear();
});

// ── setupClaude ──────────────────────────────────────────────────────────────

describe('setupClaude', () => {
  const hooksPath = path.join(os.homedir(), '.claude', 'settings.json');
  const mcpPath = path.join(os.homedir(), '.claude.json');

  it('adds both hooks immediately on a fresh install — no prompt', async () => {
    const confirm = await getConfirm();
    await setupClaude();

    expect(confirm).not.toHaveBeenCalled();
    const written = writtenTo(hooksPath);
    expect(written.hooks.PreToolUse[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.PostToolUse[0].hooks[0].command).toBe('node9 log');
  });

  it('does not add hooks that already exist', async () => {
    withExistingFiles({
      [hooksPath]: {
        hooks: {
          PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
        },
      },
      [mcpPath]: { mcpServers: { node9: NODE9_MCP_ENTRY } },
    });

    await setupClaude();
    expect(writtenTo(hooksPath)).toBeNull();
  });

  it('prompts before wrapping existing MCP servers', async () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] },
      },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);

    await setupClaude();
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('wraps MCP servers when user confirms', async () => {
    withExistingFile(mcpPath, {
      mcpServers: { github: { command: 'npx', args: ['-y', 'server-github'] } },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);

    await setupClaude();

    const written = writtenTo(mcpPath);
    expect(written.mcpServers.github.command).toBe('node9');
    // args are the full original command parts — no 'proxy' indirection
    expect(written.mcpServers.github.args).toEqual(['npx', '-y', 'server-github']);
  });

  it('skips MCP wrapping when user denies', async () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        github: { command: 'npx', args: ['-y', 'server-github'] },
        node9: NODE9_MCP_ENTRY,
      },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(false);

    await setupClaude();
    expect(writtenTo(mcpPath)).toBeNull();
  });

  it('skips MCP servers that are already wrapped', async () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        github: { command: 'node9', args: ['npx', 'server-github'] },
        node9: NODE9_MCP_ENTRY,
      },
    });
    const confirm = await getConfirm();

    await setupClaude();
    expect(confirm).not.toHaveBeenCalled();
    expect(writtenTo(mcpPath)).toBeNull();
  });

  it('prints "already configured" when everything is in place', async () => {
    withExistingFiles({
      [hooksPath]: {
        hooks: {
          PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
        },
      },
      [mcpPath]: { mcpServers: { node9: NODE9_MCP_ENTRY } },
    });

    const consoleSpy = vi.spyOn(console, 'log');
    await setupClaude();
    expect(consoleSpy.mock.calls.some(([msg]) => String(msg).includes('already'))).toBe(true);
    consoleSpy.mockRestore();
  });
});

// ── setupGemini ──────────────────────────────────────────────────────────────

describe('setupGemini', () => {
  const settingsPath = path.join(os.homedir(), '.gemini', 'settings.json');

  it('adds both hooks immediately on a fresh install — no prompt', async () => {
    const confirm = await getConfirm();
    await setupGemini();

    expect(confirm).not.toHaveBeenCalled();
    const written = writtenTo(settingsPath);
    expect(written.hooks.BeforeTool[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.AfterTool[0].hooks[0].command).toBe('node9 log');
  });

  it('does not overwrite hooks that already point to node9', async () => {
    withExistingFile(settingsPath, {
      hooks: {
        BeforeTool: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
        AfterTool: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
      },
      mcpServers: { node9: NODE9_MCP_ENTRY },
    });

    await setupGemini();
    expect(writtenTo(settingsPath)).toBeNull();
  });

  it('prompts before wrapping existing MCP servers', async () => {
    withExistingFile(settingsPath, {
      mcpServers: { aws: { command: 'npx', args: ['server-aws'] } },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);

    await setupGemini();
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('wraps MCP servers when user confirms', async () => {
    withExistingFile(settingsPath, {
      mcpServers: { aws: { command: 'npx', args: ['server-aws'] } },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);

    await setupGemini();

    const written = writtenTo(settingsPath);
    expect(written?.mcpServers.aws.command).toBe('node9');
  });
});

// ── setupCursor ───────────────────────────────────────────────────────────────

describe('setupCursor', () => {
  const mcpPath = path.join(os.homedir(), '.cursor', 'mcp.json');

  it('does not write hooks.json — Cursor does not support native hooks', async () => {
    const confirm = await getConfirm();
    await setupCursor();

    expect(confirm).not.toHaveBeenCalled();
    // hooks.json must never be written
    expect(writtenTo(path.join(os.homedir(), '.cursor', 'hooks.json'))).toBeNull();
  });

  it('prompts before wrapping existing MCP servers', async () => {
    withExistingFile(mcpPath, {
      mcpServers: { brave: { command: 'npx', args: ['server-brave'] } },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);

    await setupCursor();
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('wraps MCP servers when user confirms', async () => {
    withExistingFile(mcpPath, {
      mcpServers: { brave: { command: 'npx', args: ['server-brave'] } },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);

    await setupCursor();

    const written = writtenTo(mcpPath);
    expect(written.mcpServers.brave.command).toBe('node9');
    expect(written.mcpServers.brave.args).toEqual(['npx', 'server-brave']);
  });

  it('skips MCP wrapping when user denies', async () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        brave: { command: 'npx', args: ['server-brave'] },
        node9: NODE9_MCP_ENTRY,
      },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(false);

    await setupCursor();
    expect(writtenTo(mcpPath)).toBeNull();
  });
});

// ── teardownClaude ────────────────────────────────────────────────────────────

describe('teardownClaude', () => {
  const hooksPath = path.join(os.homedir(), '.claude', 'settings.json');
  const mcpPath = path.join(os.homedir(), '.claude.json');

  it('removes node9 PreToolUse and PostToolUse hook matchers', () => {
    withExistingFile(hooksPath, {
      hooks: {
        PreToolUse: [
          { matcher: '.*', hooks: [{ type: 'command', command: '/usr/bin/node9 check' }] },
          { matcher: '.*', hooks: [{ type: 'command', command: '/other/tool run' }] },
        ],
        PostToolUse: [
          { matcher: '.*', hooks: [{ type: 'command', command: '/usr/bin/node9 log' }] },
        ],
      },
    });

    teardownClaude();

    const written = writtenTo(hooksPath);
    // node9 check matcher removed; other tool preserved
    expect(written.hooks.PreToolUse).toHaveLength(1);
    expect(written.hooks.PreToolUse[0].hooks[0].command).toBe('/other/tool run');
    // PostToolUse fully removed — key deleted
    expect(written.hooks.PostToolUse).toBeUndefined();
  });

  it('also matches legacy double-node hook format', () => {
    withExistingFile(hooksPath, {
      hooks: {
        PreToolUse: [
          {
            matcher: '.*',
            hooks: [
              { type: 'command', command: '/usr/bin/node /usr/bin/node9 check', timeout: 60 },
            ],
          },
        ],
      },
    });

    teardownClaude();

    const written = writtenTo(hooksPath);
    expect(written.hooks.PreToolUse).toBeUndefined();
  });

  it('unwraps node9-wrapped MCP servers in .claude.json', () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        myServer: { command: 'node9', args: ['npx', '-y', 'some-mcp'] },
        other: { command: 'python', args: ['server.py'] },
      },
    });

    teardownClaude();

    const written = writtenTo(mcpPath);
    expect(written.mcpServers.myServer.command).toBe('npx');
    expect(written.mcpServers.myServer.args).toEqual(['-y', 'some-mcp']);
    // Non-node9 server untouched
    expect(written.mcpServers.other.command).toBe('python');
  });

  it('unwraps MCP server with no original args (args: undefined, not [])', () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        solo: { command: 'node9', args: ['my-binary'] },
      },
    });

    teardownClaude();

    const written = writtenTo(mcpPath);
    expect(written.mcpServers.solo.command).toBe('my-binary');
    // No original args — should be omitted, not set to []
    expect(written.mcpServers.solo.args).toBeUndefined();
  });

  it('skips MCP servers where args is empty (cannot determine original command)', () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        broken: { command: 'node9', args: [] },
      },
    });

    teardownClaude();
    // args: [] has no original command to restore — leave it untouched
    expect(writtenTo(mcpPath)).toBeNull();
  });

  it('does nothing when settings.json has no node9 hooks', () => {
    withExistingFile(hooksPath, {
      hooks: {
        PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: '/other/tool run' }] }],
      },
    });

    teardownClaude();
    // No write — nothing changed
    expect(writtenTo(hooksPath)).toBeNull();
  });

  it('does nothing when settings.json does not exist', () => {
    // existsSync returns false (default beforeEach state) — no files present
    teardownClaude();
    expect(writtenTo(hooksPath)).toBeNull();
    expect(writtenTo(mcpPath)).toBeNull();
  });

  it('does not throw when settings.json contains malformed JSON', () => {
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p) === hooksPath);
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      if (String(p) === hooksPath) return 'not valid json {{{';
      throw new Error('not found');
    });

    // readJson catches the parse error and returns null — teardown is a no-op
    expect(() => teardownClaude()).not.toThrow();
    expect(writtenTo(hooksPath)).toBeNull();
  });

  it('does nothing when settings.json exists but hooks key is absent', () => {
    // File exists but has no hooks section (e.g. only mcpServers configured)
    withExistingFile(hooksPath, { someOtherKey: true });

    teardownClaude();
    expect(writtenTo(hooksPath)).toBeNull();
  });
});

// ── teardownGemini ────────────────────────────────────────────────────────────

describe('teardownGemini', () => {
  const settingsPath = path.join(os.homedir(), '.gemini', 'settings.json');

  it('removes node9 BeforeTool and AfterTool hook matchers', () => {
    withExistingFile(settingsPath, {
      hooks: {
        BeforeTool: [{ matcher: '.*', hooks: [{ command: '/usr/bin/node9 check' }] }],
        AfterTool: [{ matcher: '.*', hooks: [{ command: '/usr/bin/node9 log' }] }],
      },
    });

    teardownGemini();

    const written = writtenTo(settingsPath);
    expect(written.hooks.BeforeTool).toBeUndefined();
    expect(written.hooks.AfterTool).toBeUndefined();
  });

  it('does nothing when file does not exist', () => {
    // existsSync returns false (default beforeEach state)
    teardownGemini();
    expect(writtenTo(settingsPath)).toBeNull();
  });

  it('does nothing when settings.json has hooks but none belong to node9', () => {
    withExistingFile(settingsPath, {
      hooks: {
        BeforeTool: [{ matcher: '.*', hooks: [{ command: '/other/tool run' }] }],
      },
    });

    teardownGemini();
    expect(writtenTo(settingsPath)).toBeNull();
  });

  it('also matches legacy double-node hook format', () => {
    withExistingFile(settingsPath, {
      hooks: {
        BeforeTool: [{ matcher: '.*', hooks: [{ command: '/usr/bin/node /usr/bin/node9 check' }] }],
      },
    });

    teardownGemini();

    const written = writtenTo(settingsPath);
    expect(written.hooks.BeforeTool).toBeUndefined();
  });

  it('removes only node9 matchers and preserves non-node9 matchers in the same event', () => {
    withExistingFile(settingsPath, {
      hooks: {
        BeforeTool: [
          { matcher: '.*', hooks: [{ command: '/usr/bin/node9 check' }] },
          { matcher: '.*', hooks: [{ command: '/other/tool run' }] },
        ],
      },
    });

    teardownGemini();

    const written = writtenTo(settingsPath);
    expect(written.hooks.BeforeTool).toHaveLength(1);
    expect(written.hooks.BeforeTool[0].hooks[0].command).toBe('/other/tool run');
  });
});

// ── detectAgents ─────────────────────────────────────────────────────────────

describe('detectAgents', () => {
  // Normalize to forward slashes so comparisons work on Windows too
  const home = '/mock/home';
  const p = (name: string) => path.join(home, name).replace(/\\/g, '/');

  it('returns all false when no agent directories exist', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    expect(detectAgents(home)).toEqual({
      claude: false,
      gemini: false,
      cursor: false,
      codex: false,
    });
  });

  it('detects Claude via ~/.claude directory', () => {
    vi.mocked(fs.existsSync).mockImplementation(
      (q) => String(q).replace(/\\/g, '/') === p('.claude')
    );
    const result = detectAgents(home);
    expect(result.claude).toBe(true);
    expect(result.gemini).toBe(false);
    expect(result.cursor).toBe(false);
  });

  it('detects Claude via ~/.claude.json (no directory)', () => {
    vi.mocked(fs.existsSync).mockImplementation(
      (q) => String(q).replace(/\\/g, '/') === p('.claude.json')
    );
    expect(detectAgents(home).claude).toBe(true);
  });

  it('detects Gemini via ~/.gemini directory', () => {
    vi.mocked(fs.existsSync).mockImplementation(
      (q) => String(q).replace(/\\/g, '/') === p('.gemini')
    );
    expect(detectAgents(home).gemini).toBe(true);
  });

  it('detects Cursor via ~/.cursor directory', () => {
    vi.mocked(fs.existsSync).mockImplementation(
      (q) => String(q).replace(/\\/g, '/') === p('.cursor')
    );
    expect(detectAgents(home).cursor).toBe(true);
  });

  it('detects Codex via ~/.codex directory', () => {
    vi.mocked(fs.existsSync).mockImplementation(
      (q) => String(q).replace(/\\/g, '/') === p('.codex')
    );
    expect(detectAgents(home).codex).toBe(true);
  });

  it('detects all four agents simultaneously', () => {
    vi.mocked(fs.existsSync).mockImplementation((q) => {
      const s = String(q).replace(/\\/g, '/');
      return s === p('.claude') || s === p('.gemini') || s === p('.cursor') || s === p('.codex');
    });
    expect(detectAgents(home)).toEqual({ claude: true, gemini: true, cursor: true, codex: true });
  });

  it('returns all false when existsSync throws (e.g. permission denied)', () => {
    vi.mocked(fs.existsSync).mockImplementation(() => {
      throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
    });
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    expect(detectAgents(home)).toEqual({
      claude: false,
      gemini: false,
      cursor: false,
      codex: false,
    });
    // Should warn to stderr for non-ENOENT errors so misconfigured systems surface
    expect(stderrSpy).toHaveBeenCalled();
    expect(String(stderrSpy.mock.calls[0][0])).toContain('EACCES');
    stderrSpy.mockRestore();
  });

  it('ENOENT is silently treated as false — no stderr warning', () => {
    // ENOENT just means the file/dir does not exist; it must not produce noise on stderr.
    vi.mocked(fs.existsSync).mockImplementation(() => {
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    expect(detectAgents(home)).toEqual({
      claude: false,
      gemini: false,
      cursor: false,
      codex: false,
    });
    expect(stderrSpy).not.toHaveBeenCalled();
    stderrSpy.mockRestore();
  });

  it('returns partial results when only some paths throw (second check throws)', () => {
    // .claude exists, .claude.json throws EACCES — claude should still be true
    // because the first exists() call short-circuits via ||.
    vi.mocked(fs.existsSync).mockImplementation((q) => {
      const s = String(q).replace(/\\/g, '/');
      if (s === p('.claude.json')) {
        throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
      }
      return s === p('.claude');
    });
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const result = detectAgents(home);
    // Short-circuit: .claude is true so .claude.json is never called
    expect(result.claude).toBe(true);
    expect(result.gemini).toBe(false);
    expect(result.codex).toBe(false);
    stderrSpy.mockRestore();
  });

  it('returns true for claude when first check throws but second check succeeds', () => {
    // .claude throws EACCES, .claude.json exists — claude should still be true
    vi.mocked(fs.existsSync).mockImplementation((q) => {
      const s = String(q).replace(/\\/g, '/');
      if (s === p('.claude')) {
        throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
      }
      return s === p('.claude.json');
    });
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    expect(detectAgents(home).claude).toBe(true);
    // EACCES on the first check should still warn
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('EACCES'));
    stderrSpy.mockRestore();
  });
});

// ── teardownCursor ────────────────────────────────────────────────────────────

describe('teardownCursor', () => {
  const mcpPath = path.join(os.homedir(), '.cursor', 'mcp.json');

  it('unwraps node9-wrapped MCP servers', () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        brave: { command: 'node9', args: ['npx', 'server-brave'] },
      },
    });

    teardownCursor();

    const written = writtenTo(mcpPath);
    expect(written.mcpServers.brave.command).toBe('npx');
    expect(written.mcpServers.brave.args).toEqual(['server-brave']);
  });

  it('does nothing when file does not exist', () => {
    teardownCursor();
    expect(writtenTo(mcpPath)).toBeNull();
  });
});

// ── setupCodex ────────────────────────────────────────────────────────────────

describe('setupCodex', () => {
  const configPath = path.join(os.homedir(), '.codex', 'config.toml');

  it('does not write hooks — Codex does not support native hooks', async () => {
    const confirm = await getConfirm();
    await setupCodex();

    expect(confirm).not.toHaveBeenCalled();
    // hooks file must never be written
    expect(writtenTomlTo(path.join(os.homedir(), '.codex', 'hooks.toml'))).toBeNull();
  });

  it('injects node9 MCP server on a fresh install — no prompt', async () => {
    const confirm = await getConfirm();
    await setupCodex();

    expect(confirm).not.toHaveBeenCalled();
    const written = writtenTomlTo(configPath);
    expect(written.mcp_servers.node9.command).toBe('node9');
    expect(written.mcp_servers.node9.args).toEqual(['mcp-server']);
  });

  it('does not re-inject node9 MCP server if already present', async () => {
    withExistingTomlFile(configPath, {
      mcp_servers: { node9: { command: 'node9', args: ['mcp-server'] } },
    });

    await setupCodex();
    // No wrappable servers and node9 already present → no write
    expect(writtenTomlTo(configPath)).toBeNull();
  });

  it('prompts before wrapping existing MCP servers', async () => {
    withExistingTomlFile(configPath, {
      mcp_servers: { brave: { command: 'npx', args: ['server-brave'] } },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);

    await setupCodex();
    expect(confirm).toHaveBeenCalledTimes(1);
  });

  it('wraps MCP servers when user confirms', async () => {
    withExistingTomlFile(configPath, {
      mcp_servers: { brave: { command: 'npx', args: ['server-brave'] } },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(true);

    await setupCodex();

    const written = writtenTomlTo(configPath);
    expect(written.mcp_servers.brave.command).toBe('node9');
    expect(written.mcp_servers.brave.args).toEqual(['npx', 'server-brave']);
  });

  it('skips MCP wrapping when user denies', async () => {
    withExistingTomlFile(configPath, {
      mcp_servers: {
        brave: { command: 'npx', args: ['server-brave'] },
        node9: { command: 'node9', args: ['mcp-server'] },
      },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(false);

    await setupCodex();
    expect(writtenTomlTo(configPath)).toBeNull();
  });
});

// ── teardownCodex ─────────────────────────────────────────────────────────────

describe('teardownCodex', () => {
  const configPath = path.join(os.homedir(), '.codex', 'config.toml');

  it('removes node9 MCP server entry', () => {
    withExistingTomlFile(configPath, {
      mcp_servers: {
        node9: { command: 'node9', args: ['mcp-server'] },
        brave: { command: 'npx', args: ['server-brave'] },
      },
    });

    teardownCodex();

    const written = writtenTomlTo(configPath);
    expect(written.mcp_servers.node9).toBeUndefined();
    // Non-node9 server untouched
    expect(written.mcp_servers.brave.command).toBe('npx');
  });

  it('unwraps node9-wrapped MCP servers', () => {
    withExistingTomlFile(configPath, {
      mcp_servers: {
        brave: { command: 'node9', args: ['npx', 'server-brave'] },
      },
    });

    teardownCodex();

    const written = writtenTomlTo(configPath);
    expect(written.mcp_servers.brave.command).toBe('npx');
    expect(written.mcp_servers.brave.args).toEqual(['server-brave']);
  });

  it('does nothing when file does not exist', () => {
    teardownCodex();
    expect(writtenTomlTo(configPath)).toBeNull();
  });
});
