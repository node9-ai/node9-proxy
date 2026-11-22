// migrateMcpLaunchers: the pass that moves node9's own MCP entries, already in
// agent configs, to the launcher (~/.node9/bin/node9). Entries an older node9
// wrote start on the Node the agent's PATH holds; under an old one node9
// refuses to run and the agent reports only "failed to connect".
//
// Real files in a temp HOME, no fs mocks. The rows that go through the CLI
// are in mcp-node-pin.integration.test.ts and
// mcp-node-pin-configs.integration.test.ts; these pin what must NOT move, and
// what must stay the same in an entry that does.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';
import {
  migrateMcpLaunchers,
  inventoryMcp,
  inventoryServerKeys,
  writeMcpEntry,
  type McpServer,
} from '../mcp-wrap';

type Servers = Record<string, McpServer & { env?: Record<string, string>; type?: string }>;

describe.skipIf(process.platform === 'win32')('migrateMcpLaunchers', () => {
  let home = '';
  let cli = ''; // the node9 that "runs setup" in these rows
  let origArgv1 = '';
  const launcher = () => path.join(home, '.node9', 'bin', 'node9');
  const cursorFile = () => path.join(home, '.cursor', 'mcp.json');
  const writeCursor = (servers: Servers) => {
    fs.mkdirSync(path.dirname(cursorFile()), { recursive: true });
    fs.writeFileSync(cursorFile(), JSON.stringify({ mcpServers: servers }, null, 2));
  };
  const readCursor = (): Servers =>
    (JSON.parse(fs.readFileSync(cursorFile(), 'utf-8')) as { mcpServers: Servers }).mcpServers;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-migrate-'));
    // An install as npm lays it out: <prefix>/bin/node9 -> .../dist/cli.js
    cli = path.join(home, 'prefix', 'lib', 'node_modules', 'node9-ai', 'dist', 'cli.js');
    fs.mkdirSync(path.dirname(cli), { recursive: true });
    fs.writeFileSync(cli, '#!/usr/bin/env node\n');
    fs.mkdirSync(path.join(home, 'prefix', 'bin'));
    fs.symlinkSync(cli, path.join(home, 'prefix', 'bin', 'node9'));
    origArgv1 = process.argv[1];
    process.argv[1] = cli;
    // Without this the launcher resolves to the bare name and nothing moves.
    vi.stubEnv('NODE9_TESTING', '');
  });

  afterEach(() => {
    process.argv[1] = origArgv1;
    vi.unstubAllEnvs();
    fs.chmodSync(home, 0o755);
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('moves bare entries and keeps everything behind the subcommand', () => {
    writeCursor({
      node9: { command: 'node9', args: ['mcp-server'] },
      gmail: {
        command: 'node9',
        args: ['mcp-gateway', '--config-name', 'gmail', '--upstream', 'npx -y gmail-mcp'],
        env: { TOKEN_NAME: 'x' },
      },
      plain: { command: 'npx', args: ['-y', 'plain-mcp'] },
    });
    const keysBefore = inventoryServerKeys(inventoryMcp(home));

    const moved = migrateMcpLaunchers({ home });

    expect(moved.map((m) => [m.agent, m.name, m.from])).toEqual([
      ['cursor', 'node9', 'bin'],
      ['cursor', 'gmail', 'bin'],
    ]);
    expect(readCursor()).toEqual({
      node9: { command: launcher(), args: ['mcp-server'] },
      gmail: {
        command: launcher(),
        args: ['mcp-gateway', '--config-name', 'gmail', '--upstream', 'npx -y gmail-mcp'],
        env: { TOKEN_NAME: 'x' },
      },
      // Not node9's: this pass never touches it, wrapped or not.
      plain: { command: 'npx', args: ['-y', 'plain-mcp'] },
    });
    // Pins and app-permission rules hang on the serverKey, hashed from the upstream.
    expect(inventoryServerKeys(inventoryMcp(home))).toEqual(keysBefore);
    expect(fs.statSync(launcher()).mode & 0o777).toBe(0o755);
  });

  it('writes nothing on a second call', () => {
    writeCursor({ node9: { command: 'node9', args: ['mcp-server'] } });
    expect(migrateMcpLaunchers({ home })).toHaveLength(1);
    const before = fs.readFileSync(cursorFile(), 'utf-8');
    const mtime = fs.statSync(cursorFile()).mtimeMs;
    expect(migrateMcpLaunchers({ home })).toEqual([]);
    expect(fs.readFileSync(cursorFile(), 'utf-8')).toBe(before);
    expect(fs.statSync(cursorFile()).mtimeMs).toBe(mtime);
  });

  it('names a wrap that has no --config-name, and repairs the legacy subcommand', () => {
    writeCursor({
      pg: { command: 'node9', args: ['mcp-gateway', '--upstream', 'npx -y pg-mcp'] },
      old: { command: 'node9', args: ['mcp', '--upstream', 'npx -y old-mcp'] },
      // A name the user chose on purpose is theirs.
      custom: {
        command: 'node9',
        args: ['mcp-gateway', '--config-name', 'my-name', '--upstream', 'npx -y c-mcp'],
      },
    });
    migrateMcpLaunchers({ home });
    const after = readCursor();
    expect(after.pg.args).toEqual([
      'mcp-gateway',
      '--config-name',
      'pg',
      '--upstream',
      'npx -y pg-mcp',
    ]);
    expect(after.old.args).toEqual([
      'mcp-gateway',
      '--config-name',
      'old',
      '--upstream',
      'npx -y old-mcp',
    ]);
    expect(after.custom.args).toEqual([
      'mcp-gateway',
      '--config-name',
      'my-name',
      '--upstream',
      'npx -y c-mcp',
    ]);
  });

  it('moves a hand-pinned entry when it runs this node9, or its Node is gone', () => {
    const bin = path.join(home, 'prefix', 'bin', 'node9');
    writeCursor({
      // <node> <bin> written by hand: the bin links to the cli running now.
      node9: { command: process.execPath, args: [bin, 'mcp-server'] },
      // The path to the bin itself.
      viaBin: { command: bin, args: ['mcp-gateway', '--upstream', 'npx a'] },
      // The Node that was pinned has been removed.
      deadNode: {
        command: path.join(home, 'removed', 'node'),
        args: [bin, 'mcp-gateway', '--upstream', 'npx b'],
      },
      // The hook shim used as an MCP command.
      viaHook: { command: path.join(home, '.node9', 'bin', 'hook'), args: ['mcp-server'] },
    });
    const moved = migrateMcpLaunchers({ home });
    expect(moved.map((m) => [m.name, m.from])).toEqual([
      ['node9', 'runtime'],
      ['viaBin', 'bin'],
      ['deadNode', 'runtime'],
      ['viaHook', 'hook-shim'],
    ]);
    for (const entry of Object.values(readCursor())) expect(entry.command).toBe(launcher());
  });

  it('leaves an entry that names another node9, a package runner, or a non-node9 command', () => {
    // A development checkout beside the installed node9.
    const checkout = path.join(home, 'work', 'node9-proxy', 'dist', 'cli.js');
    fs.mkdirSync(path.dirname(checkout), { recursive: true });
    fs.writeFileSync(checkout, '');
    // pnpm's global bin: a shell script, not a link to JavaScript.
    const pnpmBin = path.join(home, 'pnpm', 'node9');
    fs.mkdirSync(path.dirname(pnpmBin), { recursive: true });
    fs.writeFileSync(pnpmBin, '#!/bin/sh\nexec node "$basedir/cli.js" "$@"\n', { mode: 0o755 });
    const servers: Servers = {
      dev: { command: 'node', args: [checkout, 'mcp-server'] },
      devWrap: {
        command: process.execPath,
        args: [checkout, 'mcp-gateway', '--config-name', 'devWrap', '--upstream', 'npx a'],
      },
      pnpm: { command: pnpmBin, args: ['mcp-gateway', '--config-name', 'pnpm', '--upstream', 'x'] },
      runner: { command: 'npx', args: ['-y', 'node9-ai', 'mcp-server'] },
      already: { command: '/elsewhere/.node9/bin/node9', args: ['mcp-server'] },
      // The node9 bin with a subcommand that is not an MCP entry's.
      odd: { command: 'node9', args: ['tail'] },
      plain: { command: 'npx', args: ['-y', 'plain-mcp'] },
      remote: { url: 'https://example.invalid/mcp' } as McpServer,
    };
    writeCursor(servers);
    expect(migrateMcpLaunchers({ home })).toEqual([]);
    expect(readCursor()).toEqual(servers);
    expect(fs.existsSync(`${cursorFile()}.node9-bak`)).toBe(false);
    // With nothing to move, the launcher is not created either.
    expect(fs.existsSync(launcher())).toBe(false);
  });

  it('reaches the agents the inventory leaves out, each under its own key', () => {
    const vscode = path.join(home, '.vscode', 'mcp.json');
    const windsurf = path.join(home, '.codeium', 'windsurf', 'mcp_config.json');
    const own = { command: 'node9', args: ['mcp-server'] };
    fs.mkdirSync(path.dirname(vscode), { recursive: true });
    fs.mkdirSync(path.dirname(windsurf), { recursive: true });
    fs.writeFileSync(vscode, JSON.stringify({ servers: { node9: { type: 'stdio', ...own } } }));
    fs.writeFileSync(windsurf, JSON.stringify({ mcpServers: { node9: own } }));

    const moved = migrateMcpLaunchers({ home });
    expect(moved.map((m) => m.agent).sort()).toEqual(['vscode', 'windsurf']);
    // VS Code reads `servers`. Written under `mcpServers`, the entry it loads
    // would have stayed bare and the file would hold a second map.
    expect(JSON.parse(fs.readFileSync(vscode, 'utf-8'))).toEqual({
      servers: { node9: { type: 'stdio', command: launcher(), args: ['mcp-server'] } },
    });
    expect(JSON.parse(fs.readFileSync(windsurf, 'utf-8'))).toEqual({
      mcpServers: { node9: { command: launcher(), args: ['mcp-server'] } },
    });
  });

  it('moves entries in a TOML config and keeps the other tables', () => {
    const file = path.join(home, '.codex', 'config.toml');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(
      file,
      stringifyToml({
        model: 'x',
        features: { hooks: true },
        mcp_servers: {
          node9: { command: 'node9', args: ['mcp-server'] },
          brave: {
            command: 'node9',
            args: ['mcp-gateway', '--upstream', 'npx server-brave'],
            env: { BRAVE: '1' },
          },
        },
      })
    );
    expect(migrateMcpLaunchers({ home }).map((m) => m.name)).toEqual(['node9', 'brave']);
    expect(parseToml(fs.readFileSync(file, 'utf-8'))).toEqual({
      model: 'x',
      features: { hooks: true },
      mcp_servers: {
        node9: { command: launcher(), args: ['mcp-server'] },
        brave: {
          command: launcher(),
          args: ['mcp-gateway', '--config-name', 'brave', '--upstream', 'npx server-brave'],
          env: { BRAVE: '1' },
        },
      },
    });
  });

  it('skips a config it cannot write, and still moves the others', () => {
    writeCursor({ node9: { command: 'node9', args: ['mcp-server'] } });
    const claude = path.join(home, '.claude.json');
    fs.writeFileSync(
      claude,
      JSON.stringify({ mcpServers: { node9: { command: 'node9', args: ['mcp-server'] } } })
    );
    // The write is a temp file beside the config plus a rename: a read-only
    // directory fails it. ~/.claude.json sits in HOME itself.
    fs.mkdirSync(path.join(home, '.node9', 'bin'), { recursive: true });
    fs.chmodSync(home, 0o555);
    let moved: ReturnType<typeof migrateMcpLaunchers> = [];
    expect(() => {
      moved = migrateMcpLaunchers({ home });
    }).not.toThrow();
    fs.chmodSync(home, 0o755);
    expect(moved.map((m) => m.agent)).toEqual(['cursor']);
    expect(
      (JSON.parse(fs.readFileSync(claude, 'utf-8')) as { mcpServers: Servers }).mcpServers.node9
        .command
    ).toBe('node9');
  });

  it('moves nothing where there is no launcher to move to (a test run)', () => {
    vi.stubEnv('NODE9_TESTING', '1');
    const servers = { node9: { command: 'node9', args: ['mcp-server'] } };
    writeCursor(servers);
    expect(migrateMcpLaunchers({ home })).toEqual([]);
    expect(readCursor()).toEqual(servers);
    expect(fs.existsSync(path.join(home, '.node9'))).toBe(false);
  });
});

describe('writeMcpEntry keys', () => {
  it('writes a VS Code entry under `servers`', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-vscode-key-'));
    try {
      const file = path.join(home, 'mcp.json');
      fs.writeFileSync(file, JSON.stringify({ servers: { a: { command: 'npx', args: ['a'] } } }));
      writeMcpEntry(file, 'vscode', 'a', { command: 'node9', args: ['mcp-server'] });
      expect(JSON.parse(fs.readFileSync(file, 'utf-8'))).toEqual({
        servers: { a: { command: 'node9', args: ['mcp-server'] } },
      });
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
