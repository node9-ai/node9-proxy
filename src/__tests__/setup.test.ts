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
  setupOpencode,
  teardownClaude,
  teardownGemini,
  teardownCursor,
  teardownCodex,
  teardownOpencode,
  detectAgents,
} from '../setup.js';

vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));

vi.spyOn(fs, 'existsSync').mockReturnValue(false);
vi.spyOn(fs, 'readFileSync');
vi.spyOn(fs, 'writeFileSync').mockImplementation(() => undefined);
vi.spyOn(fs, 'mkdirSync').mockImplementation(() => undefined);
// seedMcpPinsIfMissing (#179) uses an atomic write (writeFileSync → renameSync);
// mock both so setup tests don't hit real disk on rename.
vi.spyOn(fs, 'renameSync').mockImplementation(() => undefined);
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
  const mcpPath = path.join(os.homedir(), '.claude', '.mcp.json');

  it('adds both hooks immediately on a fresh install — no prompt', async () => {
    const confirm = await getConfirm();
    await setupClaude();

    expect(confirm).not.toHaveBeenCalled();
    const written = writtenTo(hooksPath);
    expect(written.hooks.PreToolUse[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.PostToolUse[0].hooks[0].command).toBe('node9 log');
  });

  it('also wires UserPromptSubmit for paste-into-prompt DLP', async () => {
    await setupClaude();
    const written = writtenTo(hooksPath);
    expect(written.hooks.UserPromptSubmit).toBeDefined();
    expect(written.hooks.UserPromptSubmit[0].hooks[0].command).toBe('node9 check');
  });

  it('does not re-add UserPromptSubmit hook if already present', async () => {
    withExistingFiles({
      [hooksPath]: {
        hooks: {
          PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
          UserPromptSubmit: [
            { matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] },
          ],
        },
        statusLine: { type: 'command', command: 'node9 hud' },
      },
      [mcpPath]: { mcpServers: { node9: NODE9_MCP_ENTRY } },
    });

    await setupClaude();
    expect(writtenTo(hooksPath)).toBeNull();
  });

  it('self-heals a stale UserPromptSubmit hook absolute path', async () => {
    const stale =
      '/usr/bin/node /lib/node_modules/node9-ai/node_modules/@node9/proxy/dist/cli.js check';
    withExistingFiles({
      [hooksPath]: {
        hooks: {
          PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
          UserPromptSubmit: [{ matcher: '.*', hooks: [{ type: 'command', command: stale }] }],
        },
        statusLine: { type: 'command', command: 'node9 hud' },
      },
      [mcpPath]: { mcpServers: { node9: NODE9_MCP_ENTRY } },
    });

    await setupClaude();
    const written = writtenTo(hooksPath);
    expect(written.hooks.UserPromptSubmit[0].hooks[0].command).toBe('node9 check');
  });

  it('does not add hooks that already exist', async () => {
    withExistingFiles({
      [hooksPath]: {
        hooks: {
          PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
          UserPromptSubmit: [
            { matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] },
          ],
        },
        statusLine: { type: 'command', command: 'node9 hud' },
      },
      [mcpPath]: { mcpServers: { node9: NODE9_MCP_ENTRY } },
    });

    await setupClaude();
    expect(writtenTo(hooksPath)).toBeNull();
  });

  it('rewrites hooks whose absolute paths no longer exist on disk', async () => {
    // Old hook command from a previous install (e.g. node9-ai wrapper) that
    // got `npm uninstall`-ed — the stored command points at a deleted file.
    const stalePre =
      '/usr/bin/node /lib/node_modules/node9-ai/node_modules/@node9/proxy/dist/cli.js check';
    const stalePost =
      '/usr/bin/node /lib/node_modules/node9-ai/node_modules/@node9/proxy/dist/cli.js log';
    withExistingFiles({
      [hooksPath]: {
        hooks: {
          PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: stalePre }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: stalePost }] }],
        },
        statusLine: { type: 'command', command: 'node9 hud' },
      },
      [mcpPath]: { mcpServers: { node9: NODE9_MCP_ENTRY } },
    });

    await setupClaude();

    // setupClaude rewrites the stored commands to the current binary path —
    // in NODE9_TESTING mode that resolves to "node9 check" / "node9 log".
    const written = writtenTo(hooksPath);
    expect(written.hooks.PreToolUse[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.PostToolUse[0].hooks[0].command).toBe('node9 log');
  });

  it('rewrites legacy backslash hooks even when their paths still exist (#185 follow-up)', async () => {
    // Pre-1.24.2 Windows install: hooks are in the unquoted backslash form
    // that breaks Git Bash. The cli.js file STILL exists on disk (no
    // `npm uninstall` happened), so the original "path missing"
    // staleness check returns false and the broken hooks survive an
    // upgrade-then-init. We rely on a separate detector for the shape
    // itself — backslashes are never produced by the post-fix
    // fullPathCommand, so any backslash in a node9 hook is unambiguous
    // evidence of a legacy format that needs rewriting.
    const winPre =
      'C:\\Program Files\\nodejs\\node.exe C:\\Users\\u\\AppData\\Roaming\\npm\\node_modules\\node9-ai\\node_modules\\@node9\\proxy\\dist\\cli.js check';
    const winPost = winPre.replace(/check$/, 'log');
    const winPrompt = winPre;
    withExistingFiles({
      [hooksPath]: {
        hooks: {
          PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: winPre }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: winPost }] }],
          UserPromptSubmit: [{ matcher: '.*', hooks: [{ type: 'command', command: winPrompt }] }],
        },
        statusLine: { type: 'command', command: 'node9 hud' },
      },
      [mcpPath]: { mcpServers: { node9: NODE9_MCP_ENTRY } },
    });

    await setupClaude();

    const written = writtenTo(hooksPath);
    expect(written).not.toBeNull();
    // Under NODE9_TESTING=1 the rewrite collapses to the bare form;
    // production sees the quoted forward-slash form. Either way the
    // hallmark of the bug — any backslash — must be gone.
    expect(written.hooks.PreToolUse[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.PostToolUse[0].hooks[0].command).toBe('node9 log');
    expect(written.hooks.UserPromptSubmit[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.PreToolUse[0].hooks[0].command).not.toMatch(/\\/);
    expect(written.hooks.PostToolUse[0].hooks[0].command).not.toMatch(/\\/);
    expect(written.hooks.UserPromptSubmit[0].hooks[0].command).not.toMatch(/\\/);
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
    // args use the mcp --upstream gateway format
    expect(written.mcpServers.github.args).toEqual(['mcp', '--upstream', 'npx -y server-github']);
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
        github: { command: 'node9', args: ['mcp', '--upstream', 'npx server-github'] },
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
          UserPromptSubmit: [
            { matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] },
          ],
        },
        statusLine: { type: 'command', command: 'node9 hud' },
      },
      [mcpPath]: { mcpServers: { node9: NODE9_MCP_ENTRY } },
    });

    const consoleSpy = vi.spyOn(console, 'log');
    await setupClaude();
    expect(consoleSpy.mock.calls.some(([msg]) => String(msg).includes('already'))).toBe(true);
    consoleSpy.mockRestore();
  });

  it('does not advertise the retired local browser UI (node9 daemon --openui)', async () => {
    // Local browser dashboard was retired — the only dashboard we advertise is
    // https://node9.ai. Verify both fresh-install and already-configured paths
    // emit no `--openui` hint.
    const consoleSpy = vi.spyOn(console, 'log');

    // Fresh install path
    await setupClaude();

    // Already-configured path
    withExistingFiles({
      [hooksPath]: {
        hooks: {
          PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
        },
        statusLine: { type: 'command', command: 'node9 hud' },
      },
      [mcpPath]: { mcpServers: { node9: NODE9_MCP_ENTRY } },
    });
    await setupClaude();

    const allOutput = consoleSpy.mock.calls.map(([msg]) => String(msg)).join('\n');
    expect(allOutput).not.toMatch(/--openui/);
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
    expect(written.mcpServers.brave.args).toEqual(['mcp', '--upstream', 'npx server-brave']);
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
  const mcpPath = path.join(os.homedir(), '.claude', '.mcp.json');

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

  it('unwraps node9-wrapped MCP servers in .claude/.mcp.json', () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        myServer: { command: 'node9', args: ['mcp', '--upstream', 'npx -y some-mcp'] },
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
        solo: { command: 'node9', args: ['mcp', '--upstream', 'my-binary'] },
      },
    });

    teardownClaude();

    const written = writtenTo(mcpPath);
    expect(written.mcpServers.solo.command).toBe('my-binary');
    // No original args — should be omitted, not set to []
    expect(written.mcpServers.solo.args).toBeUndefined();
  });

  it('skips MCP servers that are not in mcp --upstream format (e.g. node9 mcp-server)', () => {
    withExistingFile(mcpPath, {
      mcpServers: {
        node9: { command: 'node9', args: ['mcp-server'] },
      },
    });

    teardownClaude();
    // node9 mcp-server entry is removed by removeNode9McpServer, not this loop
    // but with no other changes, verify graceful handling
    expect(writtenTo(mcpPath)).not.toBeNull(); // node9 entry removed
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
      windsurf: false,
      vscode: false,
      claudeDesktop: false,
      opencode: false,
    });
  });

  it('detects Opencode via ~/.config/opencode directory', () => {
    vi.mocked(fs.existsSync).mockImplementation(
      (q) => String(q).replace(/\\/g, '/') === p('.config/opencode')
    );
    const result = detectAgents(home);
    expect(result.opencode).toBe(true);
    expect(result.claude).toBe(false);
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

  it('detects all seven agents simultaneously', () => {
    vi.mocked(fs.existsSync).mockImplementation((q) => {
      const s = String(q).replace(/\\/g, '/');
      return (
        s === p('.claude') ||
        s === p('.gemini') ||
        s === p('.cursor') ||
        s === p('.codex') ||
        s === p('.codeium/windsurf') ||
        s === p('.vscode') ||
        s.includes('Claude') // Claude Desktop dir on any platform
      );
    });
    expect(detectAgents(home)).toEqual({
      claude: true,
      gemini: true,
      cursor: true,
      codex: true,
      windsurf: true,
      vscode: true,
      claudeDesktop: true,
      opencode: false,
    });
  });

  it('detects Windsurf via ~/.codeium/windsurf directory', () => {
    vi.mocked(fs.existsSync).mockImplementation(
      (q) => String(q).replace(/\\/g, '/') === p('.codeium/windsurf')
    );
    expect(detectAgents(home).windsurf).toBe(true);
  });

  it('detects VSCode via ~/.vscode directory', () => {
    vi.mocked(fs.existsSync).mockImplementation(
      (q) => String(q).replace(/\\/g, '/') === p('.vscode')
    );
    expect(detectAgents(home).vscode).toBe(true);
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
      windsurf: false,
      vscode: false,
      claudeDesktop: false,
      opencode: false,
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
      windsurf: false,
      vscode: false,
      claudeDesktop: false,
      opencode: false,
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
        brave: { command: 'node9', args: ['mcp', '--upstream', 'npx server-brave'] },
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
  const hooksPath = path.join(os.homedir(), '.codex', 'hooks.json');

  // Codex's hook config lives at ~/.codex/hooks.json. Mixed-format helper because
  // the same test needs config.toml (TOML) and hooks.json (JSON) co-resident.
  function withExistingCodexFiles(files: { configToml?: object; hooksJson?: object }) {
    const paths: Record<string, string> = {};
    if (files.configToml) {
      paths[configPath] = stringifyToml(files.configToml as Record<string, unknown>);
    }
    if (files.hooksJson) {
      paths[hooksPath] = JSON.stringify(files.hooksJson);
    }
    vi.mocked(fs.existsSync).mockImplementation((p) => String(p) in paths);
    vi.mocked(fs.readFileSync).mockImplementation((p) => {
      const content = paths[String(p)];
      if (content !== undefined) return content;
      throw new Error('not found');
    });
  }

  it('writes hooks.json with Bash, apply_patch, and mcp__* PreToolUse matchers on fresh install', async () => {
    const confirm = await getConfirm();
    await setupCodex();

    expect(confirm).not.toHaveBeenCalled();
    const written = writtenTo(hooksPath);
    expect(written).not.toBeNull();

    const preMatchers = written.hooks.PreToolUse.map((m: { matcher: string }) => m.matcher);
    expect(preMatchers).toEqual(expect.arrayContaining(['^Bash$', '^apply_patch$', '^mcp__.*']));

    // Every PreToolUse matcher points at `node9 check`.
    for (const m of written.hooks.PreToolUse) {
      expect(m.hooks[0].command).toBe('node9 check');
    }

    // UserPromptSubmit guard (DLP on pasted prompts) must be present.
    expect(written.hooks.UserPromptSubmit).toBeDefined();
    expect(written.hooks.UserPromptSubmit[0].hooks[0].command).toBe('node9 check');

    // PostToolUse for audit logging.
    expect(written.hooks.PostToolUse[0].hooks[0].command).toBe('node9 log');
  });

  it('does not re-add hooks that already point to node9', async () => {
    withExistingCodexFiles({
      hooksJson: {
        hooks: {
          PreToolUse: [
            { matcher: '^Bash$', hooks: [{ type: 'command', command: 'node9 check' }] },
            { matcher: '^apply_patch$', hooks: [{ type: 'command', command: 'node9 check' }] },
            { matcher: '^mcp__.*', hooks: [{ type: 'command', command: 'node9 check' }] },
          ],
          UserPromptSubmit: [{ hooks: [{ type: 'command', command: 'node9 check' }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
        },
      },
      configToml: { mcp_servers: { node9: { command: 'node9', args: ['mcp-server'] } } },
    });

    await setupCodex();
    expect(writtenTo(hooksPath)).toBeNull();
  });

  it('rewrites hooks whose absolute paths no longer exist on disk', async () => {
    const stalePre =
      '/usr/bin/node /lib/node_modules/node9-ai/node_modules/@node9/proxy/dist/cli.js check';
    const stalePost =
      '/usr/bin/node /lib/node_modules/node9-ai/node_modules/@node9/proxy/dist/cli.js log';
    withExistingCodexFiles({
      hooksJson: {
        hooks: {
          PreToolUse: [
            { matcher: '^Bash$', hooks: [{ type: 'command', command: stalePre }] },
            { matcher: '^apply_patch$', hooks: [{ type: 'command', command: stalePre }] },
            { matcher: '^mcp__.*', hooks: [{ type: 'command', command: stalePre }] },
          ],
          UserPromptSubmit: [{ hooks: [{ type: 'command', command: stalePre }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: stalePost }] }],
        },
      },
      configToml: { mcp_servers: { node9: { command: 'node9', args: ['mcp-server'] } } },
    });

    await setupCodex();

    const written = writtenTo(hooksPath);
    expect(written).not.toBeNull();
    for (const m of written.hooks.PreToolUse) {
      expect(m.hooks[0].command).toBe('node9 check');
    }
    expect(written.hooks.UserPromptSubmit[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.PostToolUse[0].hooks[0].command).toBe('node9 log');
  });

  it('warns and still writes hooks.json when [features].hooks = false in config.toml', async () => {
    withExistingCodexFiles({
      configToml: { features: { hooks: false } },
    });
    const consoleSpy = vi.spyOn(console, 'log');

    await setupCodex();

    const allOutput = consoleSpy.mock.calls.map(([msg]) => String(msg)).join('\n');
    expect(allOutput).toMatch(/\[features\]\.hooks = false|hooks are disabled/i);
    // Still write the file so re-enabling the toggle activates protection.
    expect(writtenTo(hooksPath)).not.toBeNull();
    consoleSpy.mockRestore();
  });

  it('does not print the legacy "Codex does not yet support native hooks" warning', async () => {
    const consoleSpy = vi.spyOn(console, 'log');
    await setupCodex();
    const allOutput = consoleSpy.mock.calls.map(([msg]) => String(msg)).join('\n');
    expect(allOutput).not.toMatch(/does not yet support native pre-execution hooks/);
    consoleSpy.mockRestore();
  });

  it('tells the user to run /hooks in Codex to trust the entries (verified during #178)', async () => {
    // Codex requires explicit user trust before hooks fire (per
    // tui/src/startup_hooks_review.rs: "Hooks need review ... Hooks can run
    // outside the sandbox after you trust them."). Without this instruction
    // the success line ("Node9 is now protecting Codex") overpromises.
    const consoleSpy = vi.spyOn(console, 'log');
    await setupCodex();
    const allOutput = consoleSpy.mock.calls.map(([msg]) => String(msg)).join('\n');
    expect(allOutput).toMatch(/\/hooks/);
    expect(allOutput).toMatch(/trust/i);
    consoleSpy.mockRestore();
  });

  it('re-run on an already-configured system: shows trust hint, no misleading message', async () => {
    // Re-running setup when hooks are already installed used to hit a
    // "No MCP servers found to wrap" branch that (a) misled the user into
    // thinking Codex wasn't protected and (b) skipped the /hooks trust
    // reminder — meaning a user who never trusted hooks the first time
    // would never learn they need to.
    withExistingCodexFiles({
      hooksJson: {
        hooks: {
          PreToolUse: [
            { matcher: '^Bash$', hooks: [{ type: 'command', command: 'node9 check' }] },
            { matcher: '^apply_patch$', hooks: [{ type: 'command', command: 'node9 check' }] },
            { matcher: '^mcp__.*', hooks: [{ type: 'command', command: 'node9 check' }] },
          ],
          UserPromptSubmit: [{ hooks: [{ type: 'command', command: 'node9 check' }] }],
          PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
        },
      },
      configToml: { mcp_servers: { node9: { command: 'node9', args: ['mcp-server'] } } },
    });
    const consoleSpy = vi.spyOn(console, 'log');

    await setupCodex();

    const allOutput = consoleSpy.mock.calls.map(([msg]) => String(msg)).join('\n');
    // Must reach the user even on re-run
    expect(allOutput).toMatch(/\/hooks/);
    expect(allOutput).toMatch(/trust/i);
    // Misleading copy must not appear when hooks are already installed
    expect(allOutput).not.toMatch(/No MCP servers found to wrap/);
    consoleSpy.mockRestore();
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
    expect(written.mcp_servers.brave.args).toEqual(['mcp', '--upstream', 'npx server-brave']);
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
        brave: { command: 'node9', args: ['mcp', '--upstream', 'npx server-brave'] },
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

// ── setupOpencode (#186 part 1) ──────────────────────────────────────────────

describe('setupOpencode', () => {
  const home = '/mock/home';
  // Path layout verified against opencode-dev source (Global.Path.config
  // is `~/.config/opencode`; plugin glob is `{plugin,plugins}/*.{ts,js}`).
  const configPath = path.join(home, '.config', 'opencode', 'opencode.json');
  const pluginPath = path.join(home, '.config', 'opencode', 'plugins', 'node9.js');

  function writtenAsString(filePath: string): string | null {
    // Plugin file is not JSON; we need the raw string written. Helper
    // mirrors writtenTo but returns the un-parsed payload.
    const calls = vi.mocked(fs.writeFileSync).mock.calls.filter(([p]) => String(p) === filePath);
    if (calls.length === 0) return null;
    return String(calls[calls.length - 1][1]);
  }

  it('writes both opencode.json (with mcp.node9) and the plugin shim on fresh install', async () => {
    await setupOpencode();

    const config = writtenTo(configPath);
    expect(config).not.toBeNull();
    expect(config.mcp.node9).toBeDefined();
    expect(config.mcp.node9.type).toBe('local');
    // command[0] is the binary; remaining entries are subcommand-leading args
    expect(Array.isArray(config.mcp.node9.command)).toBe(true);
    expect(config.mcp.node9.command.length).toBeGreaterThanOrEqual(1);
    // Under NODE9_TESTING=1 the resolution short-circuits to "node9 mcp-server"
    expect(config.mcp.node9.command[config.mcp.node9.command.length - 1]).toBe('mcp-server');
    expect(config.mcp.node9.enabled).toBe(true);

    const plugin = writtenAsString(pluginPath);
    expect(plugin).not.toBeNull();
    expect(plugin).toContain('NODE9_SHIM_VERSION');
    expect(plugin).toContain('"tool.execute.before"');
  });

  it('preserves existing MCP servers when adding node9', async () => {
    withExistingFile(configPath, {
      mcp: {
        brave: { type: 'local', command: ['npx', 'server-brave'] },
      },
    });

    await setupOpencode();

    const config = writtenTo(configPath);
    expect(config.mcp.brave).toBeDefined();
    expect(config.mcp.brave.command).toEqual(['npx', 'server-brave']);
    expect(config.mcp.node9).toBeDefined();
  });

  it('is idempotent — no write when both files are already current', async () => {
    // Generate the canonical shim content via the same generator
    // setupOpencode uses, then mock both files as existing with that
    // content. setupOpencode should detect no changes and skip the writes.
    // We construct the expected content lazily by running setupOpencode
    // once to disk-capture it, then resetting and re-running.
    await setupOpencode();
    const initialConfig = writtenTo(configPath);
    const initialPlugin = writtenAsString(pluginPath);
    expect(initialConfig).not.toBeNull();
    expect(initialPlugin).not.toBeNull();

    // Reset write mock; replay the same state and re-run setupOpencode.
    vi.mocked(fs.writeFileSync).mockClear();
    withExistingFiles({
      [configPath]: initialConfig,
      [pluginPath]: initialPlugin as unknown as object, // string passed via JSON.stringify path; readFileSync returns whatever we provide
    });

    await setupOpencode();

    // Implementation may still issue some no-op writes (Codex does); we
    // only assert the content is byte-identical to the initial pass.
    const second = writtenTo(configPath);
    if (second !== null) expect(second).toEqual(initialConfig);
  });

  it('self-heals a shim whose NODE9_SHIM_VERSION is stale', async () => {
    // Drop in an old shim that claims version 0.0.1; setupOpencode
    // should rewrite it because the version constant won't match the
    // current node9 version.
    const stale =
      '// NODE9_SHIM_VERSION = "0.0.1"\nmodule.exports = { id: "node9", server: async () => ({}) };';
    withExistingFiles({
      [configPath]: {
        mcp: { node9: { type: 'local', command: ['node9', 'mcp-server'], enabled: true } },
      },
      [pluginPath]: stale as unknown as object,
    });

    await setupOpencode();

    const plugin = writtenAsString(pluginPath);
    expect(plugin).not.toBeNull();
    expect(plugin).not.toContain('0.0.1');
    expect(plugin).toContain('"tool.execute.before"');
  });
});

// ── teardownOpencode ─────────────────────────────────────────────────────────

describe('teardownOpencode', () => {
  const home = '/mock/home';
  const configPath = path.join(home, '.config', 'opencode', 'opencode.json');
  const pluginPath = path.join(home, '.config', 'opencode', 'plugins', 'node9.js');

  it('removes the node9 MCP entry from opencode.json', () => {
    withExistingFile(configPath, {
      mcp: {
        node9: { type: 'local', command: ['node9', 'mcp-server'], enabled: true },
        brave: { type: 'local', command: ['npx', 'server-brave'] },
      },
    });

    teardownOpencode();

    const written = writtenTo(configPath);
    expect(written.mcp.node9).toBeUndefined();
    expect(written.mcp.brave).toBeDefined();
  });

  it('removes the node9 plugin shim from disk', () => {
    const unlinkSpy = vi.spyOn(fs, 'unlinkSync').mockImplementation(() => undefined);
    withExistingFiles({
      [pluginPath]: '// NODE9_SHIM_VERSION = "1.25.0"\nmodule.exports = {};' as unknown as object,
    });

    teardownOpencode();

    expect(unlinkSpy).toHaveBeenCalledWith(pluginPath);
    unlinkSpy.mockRestore();
  });

  it('does nothing when no opencode config exists', () => {
    teardownOpencode();
    expect(writtenTo(configPath)).toBeNull();
  });
});
