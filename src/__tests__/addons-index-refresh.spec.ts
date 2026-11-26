// The daemon keeps the hook's MCP index current (node9Firewall#376 item 6).
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { readMcpIndex } from '../addons/index-file';
import { refreshAddonsIndex } from '../daemon/addons-index';

const homes: string[] = [];
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
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
});
