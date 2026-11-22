// What doctor and the daemon read about node9's MCP entries without starting
// anything: which entries depend on the agent's PATH Node, the launcher's
// state, and the refusals node9 logged when an entry started on an old Node.
// Real files in a temp HOME.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  readMcpNodeFailures,
  mcpLaunchHealth,
  launcherState,
  MCP_NODE_FAILURE_WINDOW_MS,
} from '../mcp-launch-health';
import { shimBody } from '../node9-shim';

const NOW = Date.parse('2026-11-22T12:00:00.000Z');
const at = (msAgo: number) => new Date(NOW - msAgo).toISOString();
const HOUR = 60 * 60 * 1000;
const refusal = (iso: string, sub: string, version = 'v18.19.1', exec = '/usr/bin/node') =>
  `[${iso}] UNSUPPORTED NODE (${sub}): node9: Node.js ${version} (${exec}) cannot run node9; it needs Node.js 22.12 or later.`;

let home = '';
const logFile = () => path.join(home, '.node9', 'hook-debug.log');
const writeLog = (lines: string[]) => {
  fs.mkdirSync(path.dirname(logFile()), { recursive: true });
  fs.writeFileSync(logFile(), lines.join('\n') + '\n');
};

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-launch-health-'));
  // On Windows Claude Desktop's config is under %APPDATA%, not under the home
  // these functions are given (claudeDesktopConfigPath). Without this the
  // "no node9 entry" row read the machine's real config: on the Windows CI
  // runner it held a node9 entry another test had left there, and the row
  // counted it.
  vi.stubEnv('APPDATA', path.join(home, 'AppData', 'Roaming'));
});
afterEach(() => {
  vi.unstubAllEnvs();
  fs.rmSync(home, { recursive: true, force: true });
});

describe('readMcpNodeFailures', () => {
  it('is null with no log, and with a log that holds no refusal', () => {
    expect(readMcpNodeFailures(home, NOW)).toBeNull();
    writeLog([`[${at(HOUR)}] {"event":"mcp-config-name-refreshed","name":"gmail"}`]);
    expect(readMcpNodeFailures(home, NOW)).toBeNull();
  });

  it('counts the MCP refusals of the last 7 days and reports the newest Node', () => {
    writeLog([
      refusal(at(8 * 24 * HOUR), 'mcp-gateway', 'v16.20.0', '/opt/old/node'), // outside the window
      refusal(at(3 * 24 * HOUR), 'mcp-gateway', 'v18.0.0', '/opt/n18/node'),
      refusal(at(2 * HOUR), 'mcp-server'),
      refusal(at(HOUR), 'mcp-gateway'),
    ]);
    expect(readMcpNodeFailures(home, NOW)).toEqual({
      count: 3,
      lastAt: NOW - HOUR,
      version: 'v18.19.1',
      execPath: '/usr/bin/node',
      partial: false,
    });
    expect(MCP_NODE_FAILURE_WINDOW_MS).toBe(7 * 24 * HOUR);
  });

  it('does not count a hook refusal: that is another failure with another fix', () => {
    writeLog([refusal(at(HOUR), 'check'), refusal(at(HOUR), 'log')]);
    expect(readMcpNodeFailures(home, NOW)).toBeNull();
  });

  // The same log holds hook payloads. A session that talks about this failure
  // quotes the line, and the quote must not read as a failure.
  it('does not count the text quoted inside another log line', () => {
    const quoted = refusal(at(HOUR), 'mcp-gateway');
    writeLog([
      `[${at(HOUR)}] STDIN: ${JSON.stringify(JSON.stringify({ prompt: `the log says ${quoted}` }))}`,
      `{"ts":"${at(HOUR)}","note":"${quoted.replace(/"/g, '')}"}`,
      `  ${quoted}`,
    ]);
    expect(readMcpNodeFailures(home, NOW)).toBeNull();
  });

  it('reads only the tail of a large log, and says the count is a floor', () => {
    const filler = `[${at(2 * HOUR)}] STDIN: ${'x'.repeat(1000)}`;
    const lines = [refusal(at(3 * HOUR), 'mcp-server')]; // before the tail: not seen
    for (let i = 0; i < 9000; i++) lines.push(filler); // about 9 MB
    lines.push(refusal(at(HOUR), 'mcp-gateway'));
    writeLog(lines);
    expect(fs.statSync(logFile()).size).toBeGreaterThan(8 * 1024 * 1024);
    expect(readMcpNodeFailures(home, NOW)).toMatchObject({ count: 1, partial: true });
  });
});

describe('mcpLaunchHealth', () => {
  const writeJson = (file: string, data: unknown) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(data));
  };

  it.skipIf(process.platform === 'win32')('sorts every node9 entry by how it starts', () => {
    const launcher = path.join(home, '.node9', 'bin', 'node9');
    writeJson(path.join(home, '.claude.json'), {
      mcpServers: {
        node9: { command: '/opt/n/bin/node', args: ['/opt/n/bin/node9', 'mcp-server'] },
        gmail: { command: 'node9', args: ['mcp-gateway', '--upstream', 'npx gmail-mcp'] },
        pg: { command: 'node9', args: ['mcp-gateway', '--config-name', 'pg', '--upstream', 'x'] },
        plain: { command: 'npx', args: ['plain-mcp'] },
        remote: { url: 'https://example.invalid/mcp' },
        // The node9 bin with something that is not an MCP entry.
        odd: { command: 'node9', args: ['tail'] },
      },
    });
    writeJson(path.join(home, '.cursor', 'mcp.json'), {
      mcpServers: {
        node9: { command: launcher, args: ['mcp-server'] },
        s: { command: launcher, args: ['mcp-gateway', '--config-name', 's', '--upstream', 'x'] },
        // A bare `node` in front of the script is PATH's node too.
        loose: { command: 'node', args: ['/opt/n/bin/node9', 'mcp-gateway', '--upstream', 'y'] },
      },
    });
    // An agent the inventory leaves out.
    writeJson(path.join(home, '.vscode', 'mcp.json'), {
      servers: { node9: { type: 'stdio', command: 'node9', args: ['mcp-server'] } },
    });

    const health = mcpLaunchHealth(home);
    expect(health.total).toBe(7);
    expect(health.onLauncher).toBe(2);
    expect(health.pinnedByHand).toBe(1);
    expect(health.pathDependent.map((g) => [g.agent, g.names, g.setupCommand])).toEqual([
      ['claude', ['gmail', 'pg'], 'node9 agents add claude'],
      ['cursor', ['loose'], 'node9 agents add cursor'],
      ['vscode', ['node9'], 'node9 agents add vscode'],
    ]);
    expect(health.newestConfigChange).toBeGreaterThan(0);
  });

  it('is empty on a machine with no node9 MCP entry', () => {
    writeJson(path.join(home, '.cursor', 'mcp.json'), {
      mcpServers: { plain: { command: 'npx', args: ['plain-mcp'] } },
    });
    expect(mcpLaunchHealth(home)).toEqual({
      total: 0,
      onLauncher: 0,
      pinnedByHand: 0,
      pathDependent: [],
      newestConfigChange: 0,
    });
  });
});

describe('launcherState', () => {
  it('reads missing, ok and stale, and the Node the launcher pins', () => {
    const file = path.join(home, '.node9', 'bin', 'node9');
    expect(launcherState(home)).toEqual({ state: 'missing', path: file });

    const cli = path.join(home, 'cli.js');
    fs.writeFileSync(cli, '');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, shimBody('node9', process.execPath, cli), { mode: 0o755 });
    expect(launcherState(home)).toEqual({ state: 'ok', path: file, node: process.execPath });

    fs.writeFileSync(file, shimBody('node9', '/gone/bin/node', cli), { mode: 0o755 });
    expect(launcherState(home)).toEqual({ state: 'stale', path: file, node: '/gone/bin/node' });
  });
});
