// Outside content (OWASP ASI01): a server that brings outside content in,
// plus an open way out. Synthetic MCP files under a temp HOME; the config is
// mocked so egress and the hold can be set per test.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

vi.mock('../../config', async () => {
  const actual = await vi.importActual<typeof import('../../config')>('../../config');
  return { ...actual, getConfig: () => mockConfig() };
});

import { checkOutsideContent, outsideSources, CATEGORY } from '../outside-content';
import { DEFAULT_CONFIG } from '../../config';
import type { CheckContext } from '../types';

let home: string;
let egress: { enabled: boolean; mode: string } = { enabled: false, mode: 'log' };
let roles: Record<string, Record<string, 'source' | 'action' | 'read'>> = {};
let checks: Record<string, string> = {};

function mockConfig() {
  return {
    ...DEFAULT_CONFIG,
    policy: {
      ...DEFAULT_CONFIG.policy,
      egress: { ...DEFAULT_CONFIG.policy.egress, ...egress },
      untrustedContent: { ...DEFAULT_CONFIG.policy.untrustedContent, roles },
      checks: { ...checks },
    },
  };
}

function claudeMcp(servers: Record<string, unknown>): void {
  const file = path.join(home, '.claude.json');
  fs.writeFileSync(file, JSON.stringify({ mcpServers: servers }));
}

const ctx = (): CheckContext => ({ home, cwd: home });

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-outside-'));
  egress = { enabled: false, mode: 'log' };
  roles = {};
  checks = {};
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

describe('outsideSources', () => {
  it('finds a server by its name, and by a role the user set', () => {
    claudeMcp({
      fetcher: { command: 'npx', args: ['-y', 'web-fetch-server'] },
      billing: { command: 'node', args: ['billing.js'] },
    });
    expect(outsideSources(home, {})).toEqual([
      { server: 'fetcher', agent: 'Claude Code', how: 'name' },
    ]);
    expect(outsideSources(home, { billing: { list_invoices: 'source' } })).toEqual([
      { server: 'fetcher', agent: 'Claude Code', how: 'name' },
      { server: 'billing', agent: 'Claude Code', how: 'role' },
    ]);
  });

  it('a server whose tools are all marked read is not a source, whatever its name', () => {
    claudeMcp({ github: { command: 'node', args: ['gh.js'] } });
    expect(outsideSources(home, { github: { get_issue: 'read' } })).toEqual([]);
  });
});

describe('checkOutsideContent', () => {
  it('is clean with no source server', () => {
    claudeMcp({ billing: { command: 'node', args: ['billing.js'] } });
    expect(checkOutsideContent(ctx())).toEqual([]);
  });

  it('is clean when the way out is gated: egress reviewed and the hold on', () => {
    claudeMcp({ github: { command: 'node', args: ['gh.js'] } });
    egress = { enabled: true, mode: 'review' };
    expect(checkOutsideContent(ctx())).toEqual([]);
  });

  it('flags a source server with egress open, naming the server and the gap', () => {
    claudeMcp({ github: { command: 'node', args: ['gh.js'] } });
    const [f] = checkOutsideContent(ctx());
    expect(f.category).toBe(CATEGORY);
    expect(f.severity).toBe('high');
    expect(f.owner).toBe('node9');
    expect(f.detail).toContain('github (Claude Code, by name)');
    expect(f.detail.join(' ')).toContain('egress is open');
    expect(f.fix).toContain('node9 egress watch');
  });

  it('one server wired into two agents counts once and names both agents', () => {
    claudeMcp({ gmail: { command: 'node', args: ['gmail.js'] } });
    fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.codex', 'config.toml'),
      '[mcp_servers.gmail]\ncommand = "node"\nargs = ["gmail.js"]\n'
    );
    const [f] = checkOutsideContent(ctx());
    expect(f.title).toMatch(/^1 MCP server brings outside content in/);
    expect(f.detail[0]).toMatch(/^gmail \(Claude Code, Codex, by name\)$/);
  });

  it('flags a source server when egress is gated but the hold is off', () => {
    claudeMcp({ gmail: { command: 'node', args: ['gmail.js'] } });
    egress = { enabled: true, mode: 'block' };
    checks = { 'behavior.untrusted-content': 'off' };
    const [f] = checkOutsideContent(ctx());
    expect(f.detail.join(' ')).toContain('behavior.untrusted-content is off');
    expect(f.detail.join(' ')).not.toContain('egress is open');
  });
});
