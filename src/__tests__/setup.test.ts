import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import { setupClaude, setupGemini, setupCursor } from '../setup.js';

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
function writtenTo(filePath: string): unknown {
  const calls = vi.mocked(fs.writeFileSync).mock.calls
    .filter(([p]) => String(p) === filePath);
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
  const mcpPath   = '/mock/home/.claude.json';

  it('adds both hooks immediately on a fresh install — no prompt', async () => {
    const confirm = await getConfirm();
    await setupClaude();

    expect(confirm).not.toHaveBeenCalled();
    const written = writtenTo(hooksPath) as any;
    expect(written.hooks.PreToolUse[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.PostToolUse[0].hooks[0].command).toBe('node9 log');
  });

  it('does not add hooks that already exist', async () => {
    withExistingFile(hooksPath, {
      hooks: {
        PreToolUse:  [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
        PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log'   }] }],
      },
    });

    await setupClaude();

    // Settings file should not be rewritten since nothing changed
    expect(writtenTo(hooksPath)).toBeNull();
  });

  it('prompts before wrapping existing MCP servers', async () => {
    withExistingFile(mcpPath, {
      mcpServers: { github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] } },
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

    const written = writtenTo(mcpPath) as any;
    expect(written.mcpServers.github.command).toBe('node9');
    expect(written.mcpServers.github.args[0]).toBe('proxy');
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
      mcpServers: { github: { command: 'node9', args: ['proxy', 'npx server-github'] } },
    });
    const confirm = await getConfirm();

    await setupClaude();

    expect(confirm).not.toHaveBeenCalled();
    expect(writtenTo(mcpPath)).toBeNull();
  });

  it('prints "already configured" when everything is in place', async () => {
    withExistingFile(hooksPath, {
      hooks: {
        PreToolUse:  [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
        PostToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log'   }] }],
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
    const written = writtenTo(settingsPath) as any;
    expect(written.hooks.BeforeTool[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.AfterTool[0].hooks[0].command).toBe('node9 log');
  });

  it('does not overwrite hooks that already point to node9', async () => {
    withExistingFile(settingsPath, {
      hooks: {
        BeforeTool: [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 check' }] }],
        AfterTool:  [{ matcher: '.*', hooks: [{ type: 'command', command: 'node9 log'   }] }],
      },
    });

    await setupGemini();
    expect(writtenTo(settingsPath)).toBeNull();
  });

  it('adds both hooks immediately on a fresh install — no prompt', async () => {
    const confirm = await getConfirm();
    await setupGemini();

    expect(confirm).not.toHaveBeenCalled();
    const written = writtenTo(settingsPath) as any;
    expect(written.hooks.BeforeTool[0].hooks[0].command).toBe('node9 check');
    expect(written.hooks.AfterTool[0].hooks[0].command).toBe('node9 log');
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

    // Gemini writes the same file twice (hooks first, then MCP) — check the last write
    const written = writtenTo(settingsPath) as any;
    expect(written?.mcpServers.aws.command).toBe('node9');
  });
});

// ── setupCursor ───────────────────────────────────────────────────────────────

describe('setupCursor', () => {
  const hooksPath = '/mock/home/.cursor/hooks.json';
  const mcpPath   = '/mock/home/.cursor/mcp.json';

  it('adds both hooks immediately on a fresh install — no prompt', async () => {
    const confirm = await getConfirm();
    await setupCursor();

    expect(confirm).not.toHaveBeenCalled();
    const written = writtenTo(hooksPath) as any;
    expect(written.version).toBe(1);
    expect(written.hooks.preToolUse[0].command).toBe('node9');
    expect(written.hooks.postToolUse[0].command).toBe('node9');
  });

  it('does not add hooks that already exist', async () => {
    withExistingFile(hooksPath, {
      version: 1,
      hooks: {
        preToolUse:  [{ command: 'node9', args: ['check'] }],
        postToolUse: [{ command: 'node9', args: ['log']   }],
      },
    });

    await setupCursor();
    expect(writtenTo(hooksPath)).toBeNull();
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

    const written = writtenTo(mcpPath) as any;
    expect(written.mcpServers.brave.command).toBe('node9');
    expect(written.mcpServers.brave.args[0]).toBe('proxy');
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

  it('preserves existing hooks from other tools when adding node9', async () => {
    withExistingFile(hooksPath, {
      version: 1,
      hooks: { preToolUse: [{ command: 'some-other-tool' }] },
    });

    await setupCursor();

    const written = writtenTo(hooksPath) as any;
    // node9 should be appended, not replace the existing hook
    expect(written.hooks.preToolUse).toHaveLength(2);
    expect(written.hooks.preToolUse[0].command).toBe('some-other-tool');
    expect(written.hooks.preToolUse[1].command).toBe('node9');
  });
});
