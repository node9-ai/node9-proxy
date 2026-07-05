/**
 * `node9 mcp gateway|ungateway|status` — real subprocess against the built CLI.
 * Requires `npm run build` first (checks for dist/cli.js), per the repo pattern.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function run(home: string, args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'mcp', ...args], {
    encoding: 'utf-8',
    env: { ...process.env, HOME: home, USERPROFILE: home, NODE9_TESTING: '1' },
  });
  return { out: (r.stdout ?? '') + (r.stderr ?? ''), status: r.status };
}

describe('node9 mcp gateway (integration)', () => {
  let home: string;
  let claudeCfg: string;

  beforeAll(() => {
    if (!fs.existsSync(CLI))
      throw new Error('Run `npm run build` before this suite (no dist/cli.js).');
  });
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-recon-cli-'));
    claudeCfg = path.join(home, '.claude.json');
    fs.writeFileSync(
      claudeCfg,
      JSON.stringify({
        mcpServers: {
          gmail: { command: 'npx', args: ['@gongrzhe/server-gmail-autoauth-mcp'], env: { X: '1' } },
          node9: { command: 'node9', args: ['mcp-server'] },
        },
      })
    );
  });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  const gmail = () => JSON.parse(fs.readFileSync(claudeCfg, 'utf-8')).mcpServers.gmail;

  it('status flags the ungoverned server and leaves node9-self alone', () => {
    const { out } = run(home, ['status']);
    expect(out).toMatch(/gmail/);
    expect(out).toMatch(/UNGOVERNED/);
    expect(out).toMatch(/ungoverned — run/);
  });

  it('gateway wraps the server (backup written, env preserved) and ungateway restores it', () => {
    const g1 = run(home, ['gateway', 'gmail']);
    expect(g1.out).toMatch(/governed gmail/);
    expect(fs.existsSync(`${claudeCfg}.node9-bak`)).toBe(true);
    const wrapped = gmail();
    expect(wrapped.command).toBe('node9');
    expect(wrapped.args[0]).toBe('mcp-gateway');
    expect(wrapped.env).toEqual({ X: '1' }); // extra fields preserved

    const g2 = run(home, ['ungateway', 'gmail']);
    expect(g2.out).toMatch(/restored gmail/);
    const restored = gmail();
    expect(restored.command).toBe('npx');
    expect(restored.args).toEqual(['@gongrzhe/server-gmail-autoauth-mcp']);
  });

  it('gateway --all wraps every ungoverned server; a second run is a no-op', () => {
    run(home, ['gateway', '--all']);
    expect(gmail().command).toBe('node9');
    const again = run(home, ['gateway', '--all']);
    expect(again.out).toMatch(/Nothing to do/);
  });

  it('an unknown name exits non-zero', () => {
    const { out, status } = run(home, ['gateway', 'nope']);
    expect(status).not.toBe(0);
    expect(out).toMatch(/No MCP server named/);
  });

  // P2.2 — the wrap carries the config key as --config-name for display/audit.
  it('wraps with --config-name = the config key', () => {
    run(home, ['gateway', 'gmail']);
    const w = gmail();
    expect(w.args).toContain('--config-name');
    expect(w.args[w.args.indexOf('--config-name') + 1]).toBe('gmail');
    // and it still points at the same upstream (config-name sits before --upstream)
    expect(w.args).toContain('--upstream');
  });

  it('--rewrap retrofits an already-governed server that lacks --config-name', () => {
    // A server wrapped by the OLD format (no --config-name).
    fs.writeFileSync(
      claudeCfg,
      JSON.stringify({
        mcpServers: {
          redis: {
            command: 'node9',
            args: ['mcp-gateway', '--upstream', 'npx redis-mcp redis://h:6379'],
          },
        },
      })
    );
    const r = run(home, ['gateway', 'redis', '--rewrap']);
    expect(r.out).toMatch(/refreshed redis/);
    const w = JSON.parse(fs.readFileSync(claudeCfg, 'utf-8')).mcpServers.redis;
    expect(w.args).toContain('--config-name');
    expect(w.args[w.args.indexOf('--config-name') + 1]).toBe('redis');
    // upstream (and therefore serverKey) preserved through the re-wrap
    expect(w.args[w.args.indexOf('--upstream') + 1]).toBe('npx redis-mcp redis://h:6379');
  });
});
