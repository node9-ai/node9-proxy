// P3 Phase 2 polish — friendly MCP server name derived from the launch command,
// reported in the SEE inventory so the dashboard shows "Filesystem" not a hash.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { deriveServerName } from '../daemon/mcp-tools';
import { resolveServerLabel } from '../mcp-gateway/index';

describe('deriveServerName', () => {
  it.each([
    ['npx -y @modelcontextprotocol/server-filesystem /home', 'filesystem'],
    ['npx @gongrzhe/server-gmail-autoauth-mcp', 'gmail-autoauth'],
    ['uvx mcp-server-git --repo .', 'git'],
    ['node /opt/tools/slack-mcp-server.js', 'slack'],
    ['python3 -m my_server', 'my_server'],
    ['', 'MCP Server'],
    ['   ', 'MCP Server'],
  ])('%s → %s', (cmd, expected) => {
    expect(deriveServerName(cmd)).toBe(expected);
  });

  it('is display-only and never throws on odd input', () => {
    expect(() => deriveServerName('--only --flags')).not.toThrow();
    expect(deriveServerName('--only --flags')).toBe('MCP Server');
  });
});

// Server label used for the audit row's MCP attribution. The real gateway
// forwards BARE tool names, so the namespaced extract usually misses — the
// fallback chain (inventory name → derived-from-command) is what keeps the
// BLOCKED audit row from shipping anonymous.
describe('resolveServerLabel', () => {
  let tmpHome: string;
  let origHome: string | undefined;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-srvlabel-'));
    origHome = process.env.HOME;
    process.env.HOME = tmpHome;
    fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'mcp-tools.json'),
      JSON.stringify({
        srv1: { name: 'gmail-autoauth', tools: [], disabled: [], status: 'approved' },
        srv2: { tools: [], disabled: [], status: 'pending' }, // predates name capture
      })
    );
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('bare tool name + known key → the inventory friendly name (the real gateway path)', () => {
    expect(
      resolveServerLabel('read_email', 'srv1', 'npx @gongrzhe/server-gmail-autoauth-mcp')
    ).toBe('gmail-autoauth');
  });

  it('namespaced tool name → the extracted server name wins', () => {
    expect(resolveServerLabel('mcp__gmail__read_email', 'srv1', 'npx x')).toBe('gmail');
  });

  it('known key but no stored name → derived from the launch command', () => {
    expect(resolveServerLabel('read_email', 'srv2', 'uvx mcp-server-git --repo .')).toBe('git');
  });

  it('unknown key → derived from the launch command (never empty)', () => {
    expect(
      resolveServerLabel('read_email', 'nope', 'npx -y @modelcontextprotocol/server-filesystem /h')
    ).toBe('filesystem');
  });
});
