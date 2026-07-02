// P3 Phase 2.6 engine — classify / wrap / unwrap / inventory / write.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { parse as parseTomlTest } from 'smol-toml';
import {
  classifyMcp,
  toGateway,
  fromGateway,
  tokenize,
  inventoryMcp,
  writeMcpEntry,
  type McpServer,
} from '../mcp-wrap';

describe('classifyMcp', () => {
  it('classifies gatewayed / node9-self / ungoverned', () => {
    expect(classifyMcp({ command: 'node9', args: ['mcp-gateway', '--upstream', 'x'] })).toBe(
      'gatewayed'
    );
    expect(classifyMcp({ command: 'node9', args: ['mcp-server'] })).toBe('node9-self');
    expect(classifyMcp({ command: 'npx', args: ['@scope/pkg'] })).toBe('ungoverned');
  });

  it('classifies a remote (URL/SSE, no command) server as "remote" — never wrapped', () => {
    // A commandless remote server must NOT be wrapped (would produce --upstream "").
    expect(classifyMcp({ url: 'https://x/mcp' } as unknown as McpServer)).toBe('remote');
    expect(classifyMcp({ command: '', args: [] })).toBe('remote');
  });

  it('does NOT double-wrap an entry launched via an absolute node9 path (fix #7)', () => {
    // args[0]==='mcp-gateway' means already governed, regardless of command path.
    expect(
      classifyMcp({ command: '/usr/local/bin/node9', args: ['mcp-gateway', '--upstream', 'x'] })
    ).toBe('gatewayed');
    expect(classifyMcp({ command: '/opt/node9', args: ['mcp-server'] })).toBe('node9-self');
  });

  it('a NON-node9 server whose first arg is literally "mcp-gateway" is still ungoverned (fix #7)', () => {
    // Must require the node9 binary — else a real server escapes governance.
    expect(classifyMcp({ command: 'python', args: ['mcp-gateway', 'server.py'] })).toBe(
      'ungoverned'
    );
  });

  it('recognizes Windows node9.exe/.cmd + backslash paths (re-review)', () => {
    expect(classifyMcp({ command: 'node9.cmd', args: ['mcp-gateway', '--upstream', 'x'] })).toBe(
      'gatewayed'
    );
    expect(
      classifyMcp({ command: 'C:\\tools\\node9.exe', args: ['mcp-gateway', '--upstream', 'x'] })
    ).toBe('gatewayed');
    expect(classifyMcp({ command: 'mynode9', args: [] })).toBe('ungoverned'); // no false-match
  });

  it('fromGateway declines (null) a corrupt gateway entry with no --upstream (re-review)', () => {
    expect(fromGateway({ command: 'node9', args: ['mcp-gateway'] })).toBeNull();
    expect(fromGateway({ command: 'node9', args: ['mcp-gateway', '--upstream', ''] })).toBeNull();
  });
});

describe('toGateway / fromGateway round-trip', () => {
  const cases: McpServer[] = [
    { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/home'] },
    { command: 'npx', args: ['@gongrzhe/server-gmail-autoauth-mcp'] },
    { command: 'node', args: ['/opt/tools/a server/server.js'] }, // arg with a space
    { command: 'srv', args: ['serve', '', '--port', '3000'] }, // empty-string arg (fix #4)
    { command: 'uvx', args: [] },
  ];
  it.each(cases)('round-trips %j (incl. spaces)', (orig) => {
    const wrapped = toGateway(orig);
    expect(wrapped.command).toBe('node9');
    expect(wrapped.args?.[0]).toBe('mcp-gateway');
    const back = fromGateway(wrapped);
    expect(back).toEqual({ ...orig, command: orig.command, args: orig.args });
  });

  it('preserves extra fields (env/type) through the wrap', () => {
    const orig = { command: 'npx', args: ['x'], env: { A: '1' }, type: 'stdio' } as McpServer &
      Record<string, unknown>;
    const wrapped = toGateway(orig) as McpServer & Record<string, unknown>;
    expect(wrapped.env).toEqual({ A: '1' });
    expect(wrapped.type).toBe('stdio');
  });

  it('the --upstream string tokenizes back to the original command tokens', () => {
    const orig = { command: 'npx', args: ['-y', '@scope/pkg', '/a b/c'] };
    const upstream = (toGateway(orig).args ?? [])[2];
    expect(tokenize(upstream)).toEqual(['npx', '-y', '@scope/pkg', '/a b/c']);
  });

  it('fromGateway returns null for a non-gatewayed entry', () => {
    expect(fromGateway({ command: 'npx', args: ['x'] })).toBeNull();
  });
});

describe('inventoryMcp + writeMcpEntry (fs, tmp-HOME)', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-recon-'));
  });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  it('inventories JSON (Claude) + TOML (Codex) with correct states', () => {
    fs.writeFileSync(
      path.join(home, '.claude.json'),
      JSON.stringify({
        mcpServers: {
          node9: { command: 'node9', args: ['mcp-server'] }, // self
          gmail: { command: 'npx', args: ['@gongrzhe/server-gmail-autoauth-mcp'] }, // ungoverned
          fs: { command: 'node9', args: ['mcp-gateway', '--upstream', 'npx x'] }, // gatewayed
        },
      })
    );
    fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.codex', 'config.toml'),
      '[mcp_servers.git]\ncommand = "uvx"\nargs = ["mcp-server-git"]\n'
    );
    const inv = inventoryMcp(home);
    const byName = Object.fromEntries(inv.map((e) => [e.name, e]));
    expect(byName.node9.state).toBe('node9-self');
    expect(byName.gmail.state).toBe('ungoverned');
    expect(byName.fs.state).toBe('gatewayed');
    expect(byName.git.state).toBe('ungoverned');
    expect(byName.git.format).toBe('toml');
  });

  it('writeMcpEntry wraps a JSON server, backs up once, and re-reads as gatewayed', () => {
    const f = path.join(home, '.claude.json');
    fs.writeFileSync(
      f,
      JSON.stringify({ mcpServers: { gmail: { command: 'npx', args: ['gmail-mcp'] } } })
    );
    const inv = inventoryMcp(home).find((e) => e.name === 'gmail')!;
    writeMcpEntry(f, 'json', 'gmail', toGateway({ command: inv.command, args: inv.args }));
    expect(fs.existsSync(`${f}.node9-bak`)).toBe(true);
    const after = inventoryMcp(home).find((e) => e.name === 'gmail')!;
    expect(after.state).toBe('gatewayed');
    // unwrap-able back to the original
    const raw = JSON.parse(fs.readFileSync(f, 'utf-8')).mcpServers.gmail;
    expect(fromGateway(raw)).toEqual({ command: 'npx', args: ['gmail-mcp'] });
  });

  it('writeMcpEntry wraps a TOML (Codex) server too', () => {
    const f = path.join(home, 'config.toml');
    fs.writeFileSync(f, '[mcp_servers.git]\ncommand = "uvx"\nargs = ["mcp-server-git"]\n');
    writeMcpEntry(f, 'toml', 'git', toGateway({ command: 'uvx', args: ['mcp-server-git'] }));
    const inv = inventoryMcp(home); // won't see it (not a registry path) — read directly
    void inv;
    const back = fromGateway(readTomlServer(f, 'git') as McpServer);
    expect(back).toEqual({ command: 'uvx', args: ['mcp-server-git'] });
  });
});

// tiny helper: read one server out of a TOML file for the assertion above
function readTomlServer(file: string, name: string): unknown {
  return (parseTomlTest(fs.readFileSync(file, 'utf-8')) as { mcp_servers: Record<string, unknown> })
    .mcp_servers[name];
}
