// The one parser for "does this MCP entry start node9, and how". Every judge
// (classifyMcp, fromGateway, agent-wiring, later setup/teardown and posture)
// reads an entry through it, so each launch form is pinned here once.
import { describe, it, expect } from 'vitest';
import {
  parseNode9Launch,
  gatewayUpstream,
  isMcpWrapSubcommand,
  MCP_WRAP_SUBCOMMAND,
} from '../mcp-entry';

const NODE = '/home/u/.nvm/versions/node/v25.9.0/bin/node';
const BIN = '/home/u/.nvm/versions/node/v25.9.0/bin/node9';

describe('parseNode9Launch — forms', () => {
  it('bin: the bare name', () => {
    expect(parseNode9Launch({ command: 'node9', args: ['mcp-server'] })).toEqual({
      form: 'bin',
      launcher: ['node9'],
      subcommand: 'mcp-server',
      rest: [],
    });
  });

  it('bin: an absolute path, and the Windows wrappers', () => {
    expect(parseNode9Launch({ command: BIN, args: ['mcp-server'] })?.form).toBe('bin');
    expect(parseNode9Launch({ command: 'node9.cmd', args: ['mcp-server'] })?.form).toBe('bin');
    expect(parseNode9Launch({ command: 'C:\\tools\\node9.exe', args: ['mcp-server'] })?.form).toBe(
      'bin'
    );
  });

  it('bin: no arguments is still node9 (never wrapped), with an empty subcommand', () => {
    expect(parseNode9Launch({ command: 'node9' })).toEqual({
      form: 'bin',
      launcher: ['node9'],
      subcommand: '',
      rest: [],
    });
  });

  it('launcher: the fixed path node9 writes', () => {
    const command = '/home/u/.node9/bin/node9';
    expect(
      parseNode9Launch({
        command,
        args: ['mcp-gateway', '--config-name', 'gmail', '--upstream', 'npx gmail-mcp'],
      })
    ).toEqual({
      form: 'launcher',
      launcher: [command],
      subcommand: 'mcp-gateway',
      rest: ['--config-name', 'gmail', '--upstream', 'npx gmail-mcp'],
    });
  });

  it('hook-shim: the hook shim used as an MCP command', () => {
    const command = '/home/u/.node9/bin/hook';
    expect(parseNode9Launch({ command, args: ['mcp-server'] })).toEqual({
      form: 'hook-shim',
      launcher: [command],
      subcommand: 'mcp-server',
      rest: [],
    });
  });

  it('runtime: node in front of the node9 bin (the hand-pinned form)', () => {
    expect(parseNode9Launch({ command: NODE, args: [BIN, 'mcp-server'] })).toEqual({
      form: 'runtime',
      launcher: [NODE, BIN],
      subcommand: 'mcp-server',
      rest: [],
    });
  });

  it('runtime: a gateway entry keeps everything after the subcommand', () => {
    const l = parseNode9Launch({
      command: NODE,
      args: [BIN, 'mcp-gateway', '--config-name', 'pg', '--upstream', 'npx -y pg-mcp'],
    });
    expect(l?.form).toBe('runtime');
    expect(l?.launcher).toEqual([NODE, BIN]);
    expect(l?.subcommand).toBe('mcp-gateway');
    expect(l?.rest).toEqual(['--config-name', 'pg', '--upstream', 'npx -y pg-mcp']);
  });

  it('runtime: cli.js inside a node9 package folder, bun, and Windows paths', () => {
    expect(
      parseNode9Launch({
        command: 'node',
        args: ['/usr/lib/node_modules/@node9/proxy/dist/cli.js', 'mcp-server'],
      })?.form
    ).toBe('runtime');
    expect(
      parseNode9Launch({
        command: 'bun',
        args: ['/home/u/src/node9-proxy/dist/cli.js', 'mcp-gateway', '--upstream', 'x'],
      })?.form
    ).toBe('runtime');
    expect(
      parseNode9Launch({
        command: 'C:\\Program Files\\nodejs\\node.exe',
        args: [
          'C:\\Users\\u\\AppData\\Roaming\\npm\\node_modules\\node9-ai\\dist\\cli.js',
          'mcp-server',
        ],
      })?.form
    ).toBe('runtime');
  });

  it('runner: npx with the node9 package, flags and a version allowed', () => {
    expect(
      parseNode9Launch({ command: 'npx', args: ['-y', 'node9-ai@2.66.3', 'mcp-server'] })
    ).toEqual({
      form: 'runner',
      launcher: ['npx', '-y', 'node9-ai@2.66.3'],
      subcommand: 'mcp-server',
      rest: [],
    });
    expect(
      parseNode9Launch({ command: 'npx', args: ['node9', 'mcp-gateway', '--upstream', 'x'] })?.form
    ).toBe('runner');
    expect(
      parseNode9Launch({ command: 'pnpm', args: ['dlx', '@node9/proxy', 'mcp-server'] })?.launcher
    ).toEqual(['pnpm', 'dlx', '@node9/proxy']);
  });
});

describe('parseNode9Launch — not node9', () => {
  it.each([
    ['a name that only contains node9', { command: 'mynode9', args: ['mcp-server'] }],
    ['another one', { command: '/opt/notnode9', args: ['mcp-server'] }],
    ['a plain server', { command: 'npx', args: ['-y', '@scope/pkg'] }],
    [
      'a non-node9 server whose first argument is mcp-gateway',
      { command: 'python', args: ['mcp-gateway', 'server.py'] },
    ],
    [
      'a script in a folder named node9, no node9 subcommand',
      { command: 'node', args: ['/srv/node9/server.js'] },
    ],
    [
      'a runtime in front of the node9 bin with a subcommand that is not an MCP one',
      { command: 'node', args: [BIN, 'serve'] },
    ],
    [
      'node flags before the script (strict on purpose)',
      { command: 'node', args: ['--no-warnings', BIN, 'mcp-server'] },
    ],
    [
      'a runner whose argument merely ends in node9',
      { command: 'npx', args: ['some-tool', '--config', '/x/node9'] },
    ],
    [
      'a runner with the node9 package but no MCP subcommand',
      { command: 'npx', args: ['node9-ai'] },
    ],
    ['a look-alike package', { command: 'npx', args: ['node9-aix', 'mcp-server'] }],
    ['a remote server', { url: 'https://x/mcp' }],
    ['an empty command', { command: '', args: [] }],
    ['a command that is not a string', { command: 7, args: ['mcp-server'] }],
  ])('%s', (_label, entry) => {
    expect(parseNode9Launch(entry as { command?: unknown; args?: unknown })).toBeNull();
  });

  it('tolerates args that are not an array', () => {
    expect(parseNode9Launch({ command: 'node9', args: 'mcp-server' })).toEqual({
      form: 'bin',
      launcher: ['node9'],
      subcommand: '',
      rest: [],
    });
    expect(parseNode9Launch({ command: 'node', args: null })).toBeNull();
  });
});

describe('gatewayUpstream', () => {
  const upstreamOf = (entry: { command: string; args: string[] }) => {
    const l = parseNode9Launch(entry);
    return l ? gatewayUpstream(l) : null;
  };

  it('reads the upstream wherever the subcommand sits', () => {
    expect(upstreamOf({ command: 'node9', args: ['mcp-gateway', '--upstream', 'npx a'] })).toBe(
      'npx a'
    );
    expect(
      upstreamOf({
        command: 'node9',
        args: ['mcp-gateway', '--config-name', 'a', '--upstream', 'npx a'],
      })
    ).toBe('npx a');
    expect(
      upstreamOf({
        command: NODE,
        args: [BIN, 'mcp-gateway', '--config-name', 'a', '--upstream', 'npx a'],
      })
    ).toBe('npx a');
  });

  it('reads a legacy wrap (`node9 mcp --upstream`)', () => {
    expect(upstreamOf({ command: 'node9', args: ['mcp', '--upstream', 'npx a'] })).toBe('npx a');
  });

  it('is null without an upstream, with an empty one, or for another subcommand', () => {
    expect(upstreamOf({ command: 'node9', args: ['mcp-gateway'] })).toBeNull();
    expect(upstreamOf({ command: 'node9', args: ['mcp-gateway', '--upstream', ''] })).toBeNull();
    expect(upstreamOf({ command: 'node9', args: ['mcp-gateway', '--upstream'] })).toBeNull();
    expect(upstreamOf({ command: 'node9', args: ['mcp-server', '--upstream', 'x'] })).toBeNull();
  });
});

describe('wrap vocabulary', () => {
  it('knows the current and the legacy wrap subcommand', () => {
    expect(MCP_WRAP_SUBCOMMAND).toBe('mcp-gateway');
    expect(isMcpWrapSubcommand('mcp-gateway')).toBe(true);
    expect(isMcpWrapSubcommand('mcp')).toBe(true);
    expect(isMcpWrapSubcommand('mcp-server')).toBe(false);
    expect(isMcpWrapSubcommand(undefined)).toBe(false);
  });
});
