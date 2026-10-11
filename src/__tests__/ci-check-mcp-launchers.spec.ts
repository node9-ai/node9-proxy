// T.3 — CI-3.mcp-unpinned for every launcher and every committed MCP config (2026-10-11).
// WRITTEN BEFORE THE IMPLEMENTATION. The rule tested `npx` only, in `.mcp.json` and
// `.cursor/mcp.json`. The same supply-chain risk comes through bunx, pnpx, uvx, pipx and an
// image without a tag, and through the VS Code, Kiro, Gemini and opencode config files.

import { describe, it, expect } from 'vitest';
import { analyzeMcp, launchedPackages, ownPackageNames } from '../ci-check/mcp';
import { routeOf } from '../ci-check/route';

const cfg = (servers: Record<string, unknown>, key = 'mcpServers') =>
  JSON.stringify({ [key]: servers }, null, 2);
const one = (command: string, args: string[]) => cfg({ srv: { command, args } });
const unpinned = (path: string, content: string) =>
  analyzeMcp(path, content).filter((f) => f.rule === 'CI-3.mcp-unpinned');

describe('T.3 — every package launcher is checked', () => {
  it.each([
    ['bunx', ['-y', '@scope/some-mcp']],
    ['bunx', ['some-mcp@latest']],
    ['pnpx', ['some-mcp@latest']],
    ['uvx', ['some-mcp']],
    ['pipx', ['run', 'some-mcp']],
    ['pnpm', ['dlx', 'some-mcp']],
    ['docker', ['run', '-i', '--rm', '-e', 'TOKEN', 'ghcr.io/example/some-mcp']],
    ['docker', ['run', '-i', 'ghcr.io/example/some-mcp:latest']],
  ])('%s %j is unpinned', (command, args) => {
    expect(unpinned('.mcp.json', one(command, args))).toHaveLength(1);
  });

  it.each([
    ['bunx', ['some-mcp@1.6.0']],
    ['pnpx', ['some-mcp@1.6.0']],
    ['uvx', ['some-mcp==1.2.3']],
    ['uvx', ['--from', 'some-mcp==1.2.3', 'some-mcp']],
    ['docker', ['run', '-i', '--rm', 'ghcr.io/example/some-mcp:1.4.2']],
    ['docker', ['run', '-i', 'ghcr.io/example/some-mcp@sha256:' + 'a'.repeat(64)]],
    ['bun', ['run', './server.ts']],
    ['claude', ['mcp', 'serve']],
  ])('%s %j stays clean', (command, args) => {
    expect(unpinned('.mcp.json', one(command, args))).toHaveLength(0);
  });

  it('the signal names the launcher, and the explanation the registry', () => {
    const [f] = unpinned('.mcp.json', one('uvx', ['some-mcp']));
    expect(f.signals.join(' ')).toMatch(/uvx/);
    expect(f.explain?.happens).toMatch(/PyPI/);
  });
});

describe('T.3 — every committed MCP config is read', () => {
  it.each([
    '.vscode/mcp.json',
    '.kiro/settings/mcp.json',
    '.gemini/settings.json',
    'opencode.json',
    '.opencode/config.json',
  ])('%s routes to the MCP check', (p) => {
    expect(routeOf(p, new Set())).toBe('mcp');
  });

  it('VS Code keeps its servers under `servers`', () => {
    expect(
      unpinned('.vscode/mcp.json', cfg({ s: { command: 'npx', args: ['some-mcp'] } }, 'servers'))
    ).toHaveLength(1);
  });

  it('opencode keeps a local server as a command array under `mcp`', () => {
    const oc = JSON.stringify({
      mcp: { s: { type: 'local', command: ['npx', '-y', 'some-mcp'] } },
    });
    expect(unpinned('opencode.json', oc)).toHaveLength(1);
  });

  it('a remote server (url only) is not an executable', () => {
    expect(
      unpinned('.mcp.json', cfg({ s: { type: 'http', url: 'https://mcp.example.com/mcp' } }))
    ).toHaveLength(0);
  });
});

describe("T.3 — the repository's own package is not a third-party supply chain", () => {
  const own = ownPackageNames([
    { path: 'pyproject.toml', content: '[project]\nname = "Some_Tool"\nversion = "1.0"\n' },
    { path: 'package.json', content: '{"name": "@acme/server"}' },
  ]);

  it('reads the names a repository publishes', () => {
    expect([...own].sort()).toEqual(['npm:@acme/server', 'pypi:some-tool', 'pypi:some_tool']);
  });

  it('starting its own package unpinned is not flagged', () => {
    expect(
      analyzeMcp('plugins/x/.mcp.json', one('uvx', ['--prerelease=allow', 'some-tool', 'mcp']), own)
    ).toHaveLength(0);
    expect(analyzeMcp('.mcp.json', one('npx', ['-y', '@acme/server@latest']), own)).toHaveLength(0);
  });

  it('another package next to it still is', () => {
    expect(unpinned('.mcp.json', one('uvx', ['other-tool']))).toHaveLength(1);
    expect(analyzeMcp('.mcp.json', one('uvx', ['other-tool']), own)).toHaveLength(1);
  });

  it('finds the launched package behind flags and versions', () => {
    expect(launchedPackages('uvx --from some-tool==1.2 some-tool')).toEqual(['some-tool']);
    expect(launchedPackages('npx -y @scope/pkg@latest')).toEqual(['@scope/pkg']);
    expect(launchedPackages('corepack pnpm dlx @playwright/mcp@latest')).toEqual([
      '@playwright/mcp',
    ]);
    expect(launchedPackages('npx -p a@1 --package=b c')).toEqual(['a', 'b']);
  });
});
