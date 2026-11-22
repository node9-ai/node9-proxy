// A wrapped MCP server must spawn the command the user actually had.
//
// HOW THIS WAS FOUND. Codex's own log, 2026-09-24, node9 MCP gateway stderr on
// a real Windows machine:
//
//   🚀 Node9 MCP Gateway: Monitoring [C:\Users\m\AppData\Local\OpenAI\...\node_repl.exe]
//   Error: spawn C:UsersmAppDataLocalOpenAI...node_repl.exe ENOENT
//
// Four agent setup flows built the `--upstream` string with a bare
// `[command, ...args].join(' ')`. The gateway re-splits that string with
// tokenize(), which treats `\` as an escape character — so every Windows
// backslash was eaten between writing the config and spawning the child. The
// wrap did not merely fail to govern the server: it REPLACED the user's
// command, so the server stopped working at all.
//
// The correct form already existed in toGateway() (`.map(quoteArg)`), one file
// away. This is the [[feedback_cap_travels_with_the_number]] shape: one value,
// five implementations, four of them wrong.
//
// These rows drive the real setup functions and assert the round trip
// config → tokenize() → argv, because that is the path that actually broke.
// Asserting the written string alone would pass on a form that still dies at
// spawn time.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { tokenize, toGateway, fromGateway, mcpUpstreamString } from '../mcp-wrap.js';
import { parse as parseToml } from 'smol-toml';

// A real Windows MCP server entry: spaces in the path AND backslashes, which
// are the two things the tokenizer treats specially.
const WIN_CMD = 'C:\\Program Files\\Acme\\srv.exe';
const WIN_ARGS = ['--root', 'C:\\data\\mcp', '--name', 'my server'];

describe('mcpUpstreamString — one wrap implementation', () => {
  it('round-trips a Windows command through tokenize() unchanged', () => {
    const upstream = mcpUpstreamString({ command: WIN_CMD, args: WIN_ARGS });
    expect(tokenize(upstream)).toEqual([WIN_CMD, ...WIN_ARGS]);
  });

  it('is what the bare join was not — the control for every row below', () => {
    // The old code. Kept as a calibration row: if this ever round-trips, the
    // tokenizer changed and these tests have stopped measuring the defect.
    const bare = [WIN_CMD, ...WIN_ARGS].join(' ');
    expect(tokenize(bare)).not.toEqual([WIN_CMD, ...WIN_ARGS]);
    expect(tokenize(bare)[0]).not.toContain('\\');
  });

  it('toGateway uses it, so wrap and unwrap agree on Windows', () => {
    const wrapped = toGateway({ command: WIN_CMD, args: WIN_ARGS });
    const back = fromGateway(wrapped);
    expect(back?.command).toBe(WIN_CMD);
    expect(back?.args).toEqual(WIN_ARGS);
  });

  it('leaves a POSIX command byte-identical to the bare join', () => {
    // No regression for the platform that was never broken: nothing to quote.
    const posix = { command: '/usr/bin/srv', args: ['--port', '8080'] };
    expect(mcpUpstreamString(posix)).toBe('/usr/bin/srv --port 8080');
  });
});

// ── The four setup flows ──────────────────────────────────────────────────────
// Driven through the real functions, not the helper, because the helper was
// never the thing that was wrong — the call sites were.

vi.mock('@inquirer/prompts', () => ({
  confirm: vi.fn().mockResolvedValue(true),
  select: vi.fn(),
  input: vi.fn(),
}));

let home = '';
const origHome = process.env.HOME;
const origProfile = process.env.USERPROFILE;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-mcpwrap-'));
  vi.spyOn(os, 'homedir').mockReturnValue(home);
  process.env.HOME = home;
  process.env.USERPROFILE = home;
});

afterEach(() => {
  vi.restoreAllMocks();
  process.env.HOME = origHome;
  process.env.USERPROFILE = origProfile;
  fs.rmSync(home, { recursive: true, force: true });
});

function readJson(p: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(p, 'utf-8'));
}

function writeJson(p: string, data: unknown): void {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(data, null, 2));
}

/** The `--upstream` value out of a wrapped entry's argv. */
function upstreamOf(args: string[]): string {
  const i = args.indexOf('--upstream');
  expect(i, `no --upstream in ${JSON.stringify(args)}`).toBeGreaterThanOrEqual(0);
  return args[i + 1];
}

describe('every agent setup wraps Windows paths so the gateway can spawn them', () => {
  it('setupClaude', async () => {
    // ~/.claude.json: the file Claude Code loads its servers from.
    const mcpPath = path.join(home, '.claude.json');
    writeJson(mcpPath, { mcpServers: { acme: { command: WIN_CMD, args: WIN_ARGS } } });
    const { setupClaude } = await import('../setup.js');
    await setupClaude();
    const written = readJson(mcpPath) as { mcpServers: Record<string, { args: string[] }> };
    expect(tokenize(upstreamOf(written.mcpServers.acme.args))).toEqual([WIN_CMD, ...WIN_ARGS]);
  });

  it('setupGemini', async () => {
    const settingsPath = path.join(home, '.gemini', 'settings.json');
    writeJson(settingsPath, { mcpServers: { acme: { command: WIN_CMD, args: WIN_ARGS } } });
    const { setupGemini } = await import('../setup.js');
    await setupGemini();
    const written = readJson(settingsPath) as { mcpServers: Record<string, { args: string[] }> };
    expect(tokenize(upstreamOf(written.mcpServers.acme.args))).toEqual([WIN_CMD, ...WIN_ARGS]);
  });

  it('setupCursor', async () => {
    const mcpPath = path.join(home, '.cursor', 'mcp.json');
    writeJson(mcpPath, { mcpServers: { acme: { command: WIN_CMD, args: WIN_ARGS } } });
    const { setupCursor } = await import('../setup.js');
    await setupCursor();
    const written = readJson(mcpPath) as { mcpServers: Record<string, { args: string[] }> };
    expect(tokenize(upstreamOf(written.mcpServers.acme.args))).toEqual([WIN_CMD, ...WIN_ARGS]);
  });

  it('setupCodex', async () => {
    const codexDir = path.join(home, '.codex');
    fs.mkdirSync(codexDir, { recursive: true });
    fs.writeFileSync(
      path.join(codexDir, 'config.toml'),
      `[mcp_servers.acme]\ncommand = '${WIN_CMD}'\nargs = ${JSON.stringify(WIN_ARGS)}\n`
    );
    const { setupCodex } = await import('../setup.js');
    await setupCodex();
    // Parse the TOML rather than regex it: smol-toml chooses its own quoting
    // and escaping, and a test that hand-parses that is testing the writer.
    const parsed = parseToml(fs.readFileSync(path.join(codexDir, 'config.toml'), 'utf-8')) as {
      mcp_servers: Record<string, { args: string[] }>;
    };
    expect(tokenize(upstreamOf(parsed.mcp_servers.acme.args))).toEqual([WIN_CMD, ...WIN_ARGS]);
  });
});

// ── B2: Codex's app-managed server ────────────────────────────────────────────

describe('setupCodex leaves servers the Codex app manages alone', () => {
  // The ChatGPT desktop app injects and rewrites [mcp_servers.node_repl]
  // itself. Its env carries per-launch values (a named pipe with a fresh uuid,
  // CODEX_CLI_PATH). Wrapping it (a) broke the app's computer-use and browser
  // tooling when the wrap failed to spawn, and (b) did not stick — the app
  // overwrote the entry back, so every `init` churned it again.
  const RUNTIME_EXE =
    'C:\\Users\\u\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node\\abc123\\bin\\node_repl.exe';

  it('does not wrap node_repl, and does wrap a user server in the same file', async () => {
    const codexDir = path.join(home, '.codex');
    fs.mkdirSync(codexDir, { recursive: true });
    fs.writeFileSync(
      path.join(codexDir, 'config.toml'),
      [
        '[mcp_servers.node_repl]',
        'args = []',
        `command = '${RUNTIME_EXE}'`,
        'startup_timeout_sec = 120',
        '',
        '[mcp_servers.node_repl.env]',
        `CODEX_CLI_PATH = 'C:\\Users\\u\\AppData\\Local\\OpenAI\\Codex\\bin\\d375\\codex.exe'`,
        `SKY_CUA_NATIVE_PIPE_DIRECTORY = '\\\\.\\pipe\\codex-computer-use-uuid'`,
        '',
        '[mcp_servers.acme]',
        `command = '${WIN_CMD}'`,
        'args = []',
        '',
      ].join('\n')
    );
    const { setupCodex } = await import('../setup.js');
    await setupCodex();
    const parsed = parseToml(fs.readFileSync(path.join(codexDir, 'config.toml'), 'utf-8')) as {
      mcp_servers: Record<string, { command?: string; args?: string[] }>;
    };

    // node_repl keeps its own command — untouched.
    expect(parsed.mcp_servers.node_repl.command).toBe(RUNTIME_EXE);
    expect(parsed.mcp_servers.node_repl.args ?? []).not.toContain('mcp-gateway');

    // The user's own server is still wrapped — the skip must be narrow.
    expect(parsed.mcp_servers.acme.command).toBe('node9');
    expect(parsed.mcp_servers.acme.args).toContain('mcp-gateway');
  });
});
