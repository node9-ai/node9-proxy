// The daemon keeps the hook's MCP index current (node9Firewall#376 item 6).
import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readMcpIndex } from '../addons/index-file';
import { refreshAddonsIndex, refreshStandingOnce } from '../daemon/addons-index';
import { _resetConfigCache } from '../config';

const homes: string[] = [];
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
  vi.unstubAllEnvs();
  _resetConfigCache();
});

function home(): string {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-addons-index-'));
  homes.push(h);
  fs.mkdirSync(path.join(h, '.node9'), { recursive: true });
  fs.mkdirSync(path.join(h, '.codex'), { recursive: true });
  return h;
}

const codex = (h: string, name: string, pkg: string) =>
  fs.writeFileSync(
    path.join(h, '.codex', 'config.toml'),
    `[mcp_servers.${name}]\ncommand = "npx"\nargs = ["-y", "${pkg}"]\n`
  );

describe('refreshAddonsIndex', () => {
  it('writes the index at once, then only when an MCP config changed', () => {
    const h = home();
    codex(h, 'db', '@acme/db-mcp');
    let sig = refreshAddonsIndex(undefined, h, {});
    expect(readMcpIndex(h)).toEqual([
      { name: 'db', identity: 'npm:@acme/db-mcp', state: 'outside', agents: ['codex'] },
    ]);
    // Nothing changed: the index is not rewritten.
    fs.writeFileSync(path.join(h, '.node9', 'addons-index.json'), '{"v":1,"mcp":[]}');
    sig = refreshAddonsIndex(sig, h, {});
    expect(readMcpIndex(h)).toEqual([]);
    // A server renamed in Codex's config (an agent other than Claude Code,
    // whose hook calls are judged from this index): picked up on the next tick.
    codex(h, 'db2', '@acme/db-mcp');
    const later = new Date(Date.now() + 5000);
    fs.utimesSync(path.join(h, '.codex', 'config.toml'), later, later);
    refreshAddonsIndex(sig, h, {});
    expect(readMcpIndex(h).map((e) => e.name)).toEqual(['db2']);
  });

  it('a config created after the start counts as a change', () => {
    const h = home();
    const sig = refreshAddonsIndex(undefined, h, {});
    expect(readMcpIndex(h)).toEqual([]);
    codex(h, 'files', 'mcp-files');
    refreshAddonsIndex(sig, h, {});
    expect(readMcpIndex(h).map((e) => e.identity)).toEqual(['npm:mcp-files']);
  });

  it('does not rewrite an index that did not change', () => {
    const h = home();
    codex(h, 'db', '@acme/db-mcp');
    refreshAddonsIndex(undefined, h, {});
    const file = path.join(h, '.node9', 'addons-index.json');
    const old = new Date(Date.now() - 60_000);
    fs.utimesSync(file, old, old);
    // A config write that leaves the MCP servers as they were.
    const later = new Date(Date.now() + 5000);
    fs.utimesSync(path.join(h, '.codex', 'config.toml'), later, later);
    refreshAddonsIndex('stale', h, {});
    // Untouched: still the old time (to the second; mtimes are not exact ms).
    expect(Math.round(fs.statSync(file).mtimeMs / 1000)).toBe(Math.round(old.getTime() / 1000));
  });
});

// Phase 4, check D: the package check for the configured MCP servers.
describe('refreshStandingOnce', () => {
  function asHome(h: string, policy: object = {}): void {
    vi.stubEnv('HOME', h);
    vi.stubEnv('USERPROFILE', h);
    fs.writeFileSync(path.join(h, '.node9', 'config.json'), JSON.stringify({ policy }));
    _resetConfigCache();
  }

  it('checks the servers that run a registry package, by identity and package', async () => {
    const h = home();
    asHome(h);
    fs.writeFileSync(
      path.join(h, '.codex', 'config.toml'),
      '[mcp_servers.db]\ncommand = "npx"\nargs = ["-y", "@acme/db-mcp@1.2.3"]\n' +
        '[mcp_servers.img]\ncommand = "docker"\nargs = ["run", "-i", "ghcr.io/acme/mcp"]\n'
    );
    const seen: unknown[] = [];
    const run = vi.fn(async (targets: unknown) => {
      seen.push(targets);
      return { v: 1 as const, entries: {} };
    });
    await refreshStandingOnce(h, {}, run);
    expect(run).toHaveBeenCalledTimes(1);
    expect(seen[0]).toEqual([
      {
        identity: 'npm:@acme/db-mcp',
        pkg: { ecosystem: 'npm', name: '@acme/db-mcp', version: '1.2.3' },
      },
    ]);
  });

  it('asks no registry when the user switched the package check off', async () => {
    const h = home();
    asHome(h, { packageCheck: { enabled: false } });
    codex(h, 'db', '@acme/db-mcp');
    const run = vi.fn(async () => ({ v: 1 as const, entries: {} }));
    await refreshStandingOnce(h, {}, run);
    expect(run).not.toHaveBeenCalled();
  });

  it('never throws, and runs again after a failed round', async () => {
    const h = home();
    asHome(h);
    codex(h, 'db', '@acme/db-mcp');
    await expect(
      refreshStandingOnce(h, {}, async () => {
        throw new Error('registry down');
      })
    ).resolves.toBeUndefined();
    const run = vi.fn(async () => ({ v: 1 as const, entries: {} }));
    await refreshStandingOnce(h, {}, run);
    expect(run).toHaveBeenCalledTimes(1);
  });
});
