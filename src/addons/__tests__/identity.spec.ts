import { describe, it, expect } from 'vitest';
import { mcpIdentityFromCommand, mcpIdentityFromUrl } from '../identity';

describe('mcpIdentityFromCommand', () => {
  const cases: Array<[string, string[], string]> = [
    [
      'npx',
      ['-y', '@modelcontextprotocol/server-postgres', 'postgres://u:pw@db/x'],
      'npm:@modelcontextprotocol/server-postgres',
    ],
    ['npx', ['--yes', 'mcp-redis@1.4.0'], 'npm:mcp-redis'],
    ['npx', ['-p', '@scope/pkg@latest', 'bin-name'], 'npm:@scope/pkg'],
    ['npx', ['--package=@scope/pkg', 'bin'], 'npm:@scope/pkg'],
    ['/usr/local/bin/npx', ['@scope/pkg@^2'], 'npm:@scope/pkg'],
    ['npx.cmd', ['-y', 'pkg'], 'npm:pkg'],
    ['pnpm', ['dlx', 'pkg@3'], 'npm:pkg'],
    ['npm', ['exec', '--', 'pkg'], 'npm:pkg'],
    ['uvx', ['mcp-server-fetch'], 'pypi:mcp-server-fetch'],
    ['uvx', ['--from', 'git-mcp==1.2', 'git-mcp-server'], 'pypi:git-mcp'],
    ['uv', ['tool', 'run', 'mcp-server-time'], 'pypi:mcp-server-time'],
    ['pipx', ['run', 'mcp-thing'], 'pypi:mcp-thing'],
    [
      'docker',
      ['run', '-i', '--rm', '-e', 'GITHUB_TOKEN=ghp_secret', 'ghcr.io/github/github-mcp-server:v1'],
      'docker:ghcr.io/github/github-mcp-server',
    ],
    ['docker', ['run', '--env=A=b', 'registry:5000/img@sha256:abc'], 'docker:registry:5000/img'],
    ['python3', ['-m', 'mcp_server_git'], 'python:mcp_server_git'],
    ['node', ['/home/u/x/node_modules/@scope/srv/dist/index.js'], 'npm:@scope/srv'],
    ['node', ['/home/u/private/project/server.js'], 'script:server.js'],
    ['/opt/tools/my-server', ['--token', 'abc'], 'binary:my-server'],
    ['C:\\tools\\srv.exe', [], 'binary:srv'],
  ];
  it.each(cases)('%s %j -> %s', (cmd, args, want) => {
    expect(mcpIdentityFromCommand(cmd, args)).toBe(want);
  });

  it('never returns an argument value, a path or an env value', () => {
    const id = mcpIdentityFromCommand('npx', ['-y', 'postgres://user:hunter2@db/prod']);
    expect(id).not.toMatch(/hunter2|postgres:/);
    expect(mcpIdentityFromCommand('node', ['/home/alice/secret-project/srv.js'])).not.toMatch(
      /alice|secret-project/
    );
  });
});

describe('mcpIdentityFromUrl', () => {
  it('keeps the host only', () => {
    expect(mcpIdentityFromUrl('https://mcp.example.com/sse?token=abc')).toBe('url:mcp.example.com');
    expect(mcpIdentityFromUrl('not a url')).toBe('url:unknown');
    expect(mcpIdentityFromUrl(undefined)).toBe('url:unknown');
  });
});
