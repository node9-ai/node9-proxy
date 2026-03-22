/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import {
  setupClaude,
  setupGemini,
  setupCursor,
  teardownClaude,
  teardownGemini,
  teardownCursor,
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

beforeEach(() => {
  vi.mocked(fs.existsSync).mockReturnValue(false);
  vi.mocked(fs.writeFileSync).mockClear();
});

// ── setupClaude ──────────────────────────────────────────────────────────────

describe('setupClaude', () => {
  const hooksPath = '/mock/home/.claude/settings.json';
  const mcpPath = '/mock/home/.claude.json';

  it('adds both hooks immediately on a fresh install — no prompt', async () => {
    const confirm = await getConfirm();
    await setupClaude();

    expect(confirm).not.toHaveBeenCalled();
    const written = writtenTo(hooksPath);
    expect(written.hooks.PreToolUse[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.PostToolUse[0].hooks[0].command).toBe('node9 log');
  });

  it('does not add hooks that already exist', async () => {
    withExistingFile(hooksPath, {
      hooks: {
        PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
        PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
      },
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
      mcpServers: { github: { command: 'npx', args: ['-y', 'server-github'] } },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(false);

    await setupClaude();
    expect(writtenTo(mcpPath)).toBeNull();
  });

  it('skips MCP servers that are already wrapped', async () => {
    withExistingFile(mcpPath, {
      mcpServers: { github: { command: 'node9', args: ['npx', 'server-github'] } },
    });
    const confirm = await getConfirm();

    await setupClaude();
    expect(confirm).not.toHaveBeenCalled();
    expect(writtenTo(mcpPath)).toBeNull();
  });

  it('prints "already configured" when everything is in place', async () => {
    withExistingFile(hooksPath, {
      hooks: {
        PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
        PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log' }] }],
      },
    });

    const consoleSpy = vi.spyOn(console, 'log');
    await setupClaude();
    expect(consoleSpy.mock.calls.some(([msg]) => String(msg).includes('already'))).toBe(true);
    consoleSpy.mockRestore();
  });
});

// ── setupGemini ──────────────────────────────────────────────────────────────

describe('setupGemini', () => {
  const settingsPath = '/mock/home/.gemini/settings.json';

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
  const mcpPath = '/mock/home/.cursor/mcp.json';

  it('does not write hooks.json — Cursor does not support native hooks', async () => {
    const confirm = await getConfirm();
    await setupCursor();

    expect(confirm).not.toHaveBeenCalled();
    // hooks.json must never be written
    expect(writtenTo('/mock/home/.cursor/hooks.json')).toBeNull();
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
      mcpServers: { brave: { command: 'npx', args: ['server-brave'] } },
    });
    const confirm = await getConfirm();
    confirm.mockResolvedValue(false);

    await setupCursor();
    expect(writtenTo(mcpPath)).toBeNull();
  });
});

// ── teardownClaude ────────────────────────────────────────────────────────────

describe('teardownClaude', () => {
  const hooksPath = '/mock/home/.claude/settings.json';
  const mcpPath = '/mock/home/.claude.json';

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
});

// ── teardownGemini ────────────────────────────────────────────────────────────

describe('teardownGemini', () => {
  const settingsPath = '/mock/home/.gemini/settings.json';

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
});

// ── teardownCursor ────────────────────────────────────────────────────────────

describe('teardownCursor', () => {
  const mcpPath = '/mock/home/.cursor/mcp.json';

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
