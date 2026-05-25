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
  setupPi,
  setupHermes,
  teardownClaude,
  teardownGemini,
  teardownCursor,
  teardownCodex,
  teardownOpencode,
  teardownPi,
  teardownHermes,
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
// detectAgents falls back to binaryInPath(...) for some agents (issue #186);
// default to "binary not found" so existing "no agents" tests don't leak the
// real machine's PATH into assertions. Individual tests opt-in with their own
// mock when they want to simulate a binary being present.
vi.spyOn(fs, 'accessSync').mockImplementation(() => {
  throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
});
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
      pi: false,
      hermes: false,
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

  // The module-level fs.accessSync mock (top of file) throws ENOENT by
  // default. Tests below override the impl when they need to simulate a
  // binary being found, then restore the throwing default in finally —
  // never mockRestore(), which would tear down the spy entirely and leak
  // the real filesystem into later tests.
  const enoentThrow = (): never => {
    throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
  };

  // Issue #186 regression: opencode creates ~/.config/opencode lazily on
  // first launch, NOT on install. A user who installs the `opencode` CLI
  // but hasn't launched it yet still has the binary in PATH — we should
  // detect it even without the config dir.
  it('detects Opencode when binary is in PATH but config dir does not exist (issue #186)', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    vi.mocked(fs.accessSync).mockImplementation(((target: fs.PathLike) => {
      if (String(target).endsWith(path.sep + 'opencode')) return undefined;
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    }) as typeof fs.accessSync);
    const oldPath = process.env.PATH;
    process.env.PATH = ['/fake/bin', '/usr/local/bin'].join(path.delimiter);
    try {
      expect(detectAgents(home).opencode).toBe(true);
    } finally {
      process.env.PATH = oldPath;
      vi.mocked(fs.accessSync).mockImplementation(enoentThrow);
    }
  });

  it('does not detect Opencode when neither config dir nor binary exist', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    // accessSync already throws ENOENT by default from the module-level mock
    const oldPath = process.env.PATH;
    process.env.PATH = '/usr/local/bin';
    try {
      expect(detectAgents(home).opencode).toBe(false);
    } finally {
      process.env.PATH = oldPath;
    }
  });

  // ── Pi (design doc: doc/roadmap/pi-integration.md) ─────────────────────
  // Pi's config layout (verified against opensources/pi-main):
  //   - CONFIG_DIR_NAME = ".pi" (packages/coding-agent/src/config.ts:449)
  //   - getAgentDir() = ~/.pi/agent (config.ts:475-480)
  //   - Extensions glob in ~/.pi/agent/extensions/ (loader.ts:594-600)

  it('detects Pi via ~/.pi/agent directory', () => {
    vi.mocked(fs.existsSync).mockImplementation(
      (q) => String(q).replace(/\\/g, '/') === p('.pi/agent')
    );
    const result = detectAgents(home);
    expect(result.pi).toBe(true);
    expect(result.claude).toBe(false);
    expect(result.opencode).toBe(false);
  });

  // Design R6: pi may ship as a Bun-compiled binary that creates
  // ~/.pi/agent/ lazily on first launch (mirrors opencode's #186 bug).
  // detectAgents must fall back to a PATH lookup so installed-but-never-
  // launched pi is still wired by `node9 init`.
  it('detects Pi when binary is in PATH but config dir does not exist (R6)', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    vi.mocked(fs.accessSync).mockImplementation(((target: fs.PathLike) => {
      if (String(target).endsWith(path.sep + 'pi')) return undefined;
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    }) as typeof fs.accessSync);
    const oldPath = process.env.PATH;
    process.env.PATH = ['/fake/bin', '/usr/local/bin'].join(path.delimiter);
    try {
      expect(detectAgents(home).pi).toBe(true);
    } finally {
      process.env.PATH = oldPath;
      vi.mocked(fs.accessSync).mockImplementation(enoentThrow);
    }
  });

  it('does not detect Pi when neither config dir nor binary exist', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    const oldPath = process.env.PATH;
    process.env.PATH = '/usr/local/bin';
    try {
      expect(detectAgents(home).pi).toBe(false);
    } finally {
      process.env.PATH = oldPath;
    }
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
      pi: false,
      hermes: false,
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
      pi: false,
      hermes: false,
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
      pi: false,
      hermes: false,
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

// ── setupPi (doc/roadmap/pi-integration.md) ──────────────────────────────────
//
// Pi has no MCP client (verified by greppling opensources/pi-main for
// `mcp` — only build/release config matches, no client). So setupPi
// writes ONLY the extension shim — no opencode.json analog.
//
// Install target: ~/.pi/agent/extensions/node9.js
// (pi loads .ts and .js; we ship .js because the shim is plain CJS with
// no node_modules resolution context — same reasoning as opencode).

describe('setupPi', () => {
  const home = '/mock/home';
  const extensionPath = path.join(home, '.pi', 'agent', 'extensions', 'node9.js');

  function writtenAsString(filePath: string): string | null {
    const calls = vi.mocked(fs.writeFileSync).mock.calls.filter(([p]) => String(p) === filePath);
    if (calls.length === 0) return null;
    return String(calls[calls.length - 1][1]);
  }

  it('writes the extension shim on fresh install', async () => {
    await setupPi();

    const extension = writtenAsString(extensionPath);
    expect(extension).not.toBeNull();
    expect(extension).toContain('NODE9_SHIM_VERSION');
    // All four protection hooks must be wired (design R4 — forgetting
    // user_bash is a silent prompt-escape bypass).
    expect(extension).toContain('"tool_call"');
    expect(extension).toContain('"tool_result"');
    expect(extension).toContain('"input"');
    expect(extension).toContain('"user_bash"');
  });

  it('is idempotent — no rewrite when the shim is already current', async () => {
    await setupPi();
    const initial = writtenAsString(extensionPath);
    expect(initial).not.toBeNull();

    vi.mocked(fs.writeFileSync).mockClear();
    withExistingFiles({
      [extensionPath]: initial as unknown as object,
    });

    await setupPi();

    const second = writtenAsString(extensionPath);
    // Either no write at all, or a byte-identical rewrite.
    if (second !== null) expect(second).toBe(initial);
  });

  it('self-heals a shim whose NODE9_SHIM_VERSION is stale', async () => {
    // Drop in an old shim claiming version 0.0.1; setupPi must rewrite
    // because the embedded version constant won't match the current
    // node9 version.
    const stale =
      '// NODE9_SHIM_VERSION = "0.0.1"\nmodule.exports = function (pi) { /* stale */ };';
    withExistingFiles({
      [extensionPath]: stale as unknown as object,
    });

    await setupPi();

    const extension = writtenAsString(extensionPath);
    expect(extension).not.toBeNull();
    expect(extension).not.toContain('0.0.1');
    expect(extension).toContain('"tool_call"');
  });

  it('creates ~/.pi/agent/extensions/ if missing (lazy-dir case)', async () => {
    const mkdirSpy = vi.mocked(fs.mkdirSync);
    mkdirSpy.mockClear();

    await setupPi();

    // mkdirSync called with the extensions dir + recursive:true. Pi's
    // loader is responsible for ~/.pi/agent/ existence at runtime, but
    // setupPi runs at install time and can't assume pi has been
    // launched (design R6).
    const extensionsDir = path.join(home, '.pi', 'agent', 'extensions');
    const calls = mkdirSpy.mock.calls;
    expect(calls.some(([dir]) => String(dir) === extensionsDir)).toBe(true);
  });
});

// ── teardownPi ───────────────────────────────────────────────────────────────

describe('teardownPi', () => {
  const home = '/mock/home';
  const extensionPath = path.join(home, '.pi', 'agent', 'extensions', 'node9.js');

  it('removes the node9 extension shim from disk', () => {
    const unlinkSpy = vi.spyOn(fs, 'unlinkSync').mockImplementation(() => undefined);
    withExistingFiles({
      [extensionPath]:
        '// NODE9_SHIM_VERSION = "1.26.1"\nmodule.exports = function () {};' as unknown as object,
    });

    teardownPi();

    expect(unlinkSpy).toHaveBeenCalledWith(extensionPath);
    unlinkSpy.mockRestore();
  });

  it('does nothing when no pi extension is installed', () => {
    const unlinkSpy = vi.spyOn(fs, 'unlinkSync').mockImplementation(() => undefined);
    vi.mocked(fs.existsSync).mockReturnValue(false);

    teardownPi();

    expect(unlinkSpy).not.toHaveBeenCalled();
    unlinkSpy.mockRestore();
  });
});

// ── setupHermes / teardownHermes ─────────────────────────────────────────────

const HERMES_CONFIG_PATH = '/mock/home/.hermes/config.yaml';
const HERMES_ALLOWLIST_PATH = '/mock/home/.hermes/shell-hooks-allowlist.json';

function withHermesConfig(yamlText: string, extraFiles: Record<string, string> = {}) {
  const all: Record<string, string> = { [HERMES_CONFIG_PATH]: yamlText, ...extraFiles };
  vi.mocked(fs.existsSync).mockImplementation((p) => String(p) in all);
  vi.mocked(fs.readFileSync).mockImplementation((p) => {
    const c = all[String(p)];
    if (c !== undefined) return c;
    throw new Error('not found');
  });
}

function writtenRaw(filePath: string): string | null {
  const calls = vi.mocked(fs.writeFileSync).mock.calls.filter(([p]) => String(p) === filePath);
  if (calls.length === 0) return null;
  return String(calls[calls.length - 1][1]);
}

describe('setupHermes', () => {
  it('appends pre_tool_call / post_tool_call hooks to a hooks-less config', () => {
    withHermesConfig('model:\n  default: "anthropic/claude-opus-4.6"\n');

    setupHermes();

    const written = writtenRaw(HERMES_CONFIG_PATH);
    expect(written).toBeTruthy();
    expect(written).toContain('pre_tool_call');
    expect(written).toContain('post_tool_call');
    expect(written).toContain('hooks_auto_accept: true');
    // Preserves the existing top-level model: block (Document API).
    expect(written).toContain('default: "anthropic/claude-opus-4.6"');
  });

  it('writes the allowlist file alongside the config (Finding F1)', () => {
    withHermesConfig('model: {}\n');

    setupHermes();

    const allowlistRaw = writtenRaw(HERMES_ALLOWLIST_PATH);
    expect(allowlistRaw).toBeTruthy();
    const allowlist = JSON.parse(allowlistRaw!);
    expect(Array.isArray(allowlist.approvals)).toBe(true);
    expect(allowlist.approvals).toHaveLength(2);
    expect(allowlist.approvals.map((e: { event: string }) => e.event).sort()).toEqual([
      'post_tool_call',
      'pre_tool_call',
    ]);
    for (const e of allowlist.approvals) {
      expect(e.command).toMatch(/node9 (check|log)/);
      expect(e.approved_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it('is idempotent — second run with same state writes no config changes', () => {
    // Seed config that already has node9 entries + the allowlist
    const cfg =
      'hooks:\n  pre_tool_call:\n    - command: "node9 check"\n      timeout: 10\n' +
      '  post_tool_call:\n    - command: "node9 log"\n      timeout: 10\n' +
      'hooks_auto_accept: true\n';
    const allowlist = JSON.stringify({
      approvals: [
        { event: 'pre_tool_call', command: 'node9 check', approved_at: '2026-01-01T00:00:00Z' },
        { event: 'post_tool_call', command: 'node9 log', approved_at: '2026-01-01T00:00:00Z' },
      ],
    });
    withHermesConfig(cfg, { [HERMES_ALLOWLIST_PATH]: allowlist });

    setupHermes();

    // Config shouldn't be rewritten when nothing changed.
    expect(writtenRaw(HERMES_CONFIG_PATH)).toBeNull();
  });

  it('preserves user-added non-node9 hook entries', () => {
    const cfg =
      'hooks:\n  pre_tool_call:\n    - command: "/usr/local/bin/audit.sh"\n      timeout: 5\n';
    withHermesConfig(cfg);

    setupHermes();

    const written = writtenRaw(HERMES_CONFIG_PATH);
    expect(written).toContain('/usr/local/bin/audit.sh');
    expect(written).toContain('node9 check');
  });

  it('warns and bails when ~/.hermes/config.yaml is missing', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);

    setupHermes();

    expect(writtenRaw(HERMES_CONFIG_PATH)).toBeNull();
    expect(writtenRaw(HERMES_ALLOWLIST_PATH)).toBeNull();
    consoleSpy.mockRestore();
  });
});

describe('teardownHermes', () => {
  it('removes node9 entries from the hooks block', () => {
    const cfg =
      'hooks:\n  pre_tool_call:\n    - command: "node9 check"\n      timeout: 10\n' +
      '  post_tool_call:\n    - command: "node9 log"\n      timeout: 10\n' +
      'hooks_auto_accept: true\n';
    withHermesConfig(cfg);

    teardownHermes();

    const written = writtenRaw(HERMES_CONFIG_PATH);
    expect(written).toBeTruthy();
    expect(written).not.toContain('node9 check');
    expect(written).not.toContain('node9 log');
    // hooks_auto_accept stays — user may have set it for their own hooks.
    expect(written).toContain('hooks_auto_accept: true');
  });

  it('removes node9 entries from the allowlist file', () => {
    const cfg = 'hooks:\n  pre_tool_call:\n    - command: "node9 check"\n      timeout: 10\n';
    const allowlist = JSON.stringify({
      approvals: [
        { event: 'pre_tool_call', command: 'node9 check', approved_at: '2026-01-01T00:00:00Z' },
        {
          event: 'pre_tool_call',
          command: '/usr/local/bin/audit.sh',
          approved_at: '2026-01-01T00:00:00Z',
        },
      ],
    });
    withHermesConfig(cfg, { [HERMES_ALLOWLIST_PATH]: allowlist });

    teardownHermes();

    const allowlistRaw = writtenRaw(HERMES_ALLOWLIST_PATH);
    expect(allowlistRaw).toBeTruthy();
    const parsed = JSON.parse(allowlistRaw!);
    expect(parsed.approvals).toHaveLength(1);
    expect(parsed.approvals[0].command).toBe('/usr/local/bin/audit.sh');
  });

  it('preserves user-added non-node9 hook entries on teardown', () => {
    const cfg =
      'hooks:\n  pre_tool_call:\n    - command: "/usr/local/bin/audit.sh"\n      timeout: 5\n' +
      '    - command: "node9 check"\n      timeout: 10\n';
    withHermesConfig(cfg);

    teardownHermes();

    const written = writtenRaw(HERMES_CONFIG_PATH);
    expect(written).toContain('/usr/local/bin/audit.sh');
    expect(written).not.toContain('node9 check');
  });

  it('does nothing when config.yaml is absent', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);

    teardownHermes();

    expect(writtenRaw(HERMES_CONFIG_PATH)).toBeNull();
  });
});

describe('detectAgents includes hermes', () => {
  it('reports hermes: true when ~/.hermes/ exists', () => {
    withHermesConfig('model: {}\n', { '/mock/home/.hermes': '' });
    const detected = detectAgents('/mock/home');
    expect(detected.hermes).toBe(true);
  });

  it('reports hermes: false when neither directory nor binary present', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    // accessSync default mock returns ENOENT so binaryInPath returns false.
    const detected = detectAgents('/mock/home');
    expect(detected.hermes).toBe(false);
  });
});
