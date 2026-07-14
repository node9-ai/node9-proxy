// P3 Phase 2 polish — friendly MCP server name derived from the launch command,
// reported in the SEE inventory so the dashboard shows "Filesystem" not a hash.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
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

  // Review fix #7 — tokenize (not split-on-whitespace) so a quoted upstream
  // doesn't pick a leading-quote token as the name.
  it('tokenizes a quoted upstream instead of splitting on whitespace', () => {
    // split() picked `"/opt/my` → "my"; tokenize picks the real binary → "srv".
    expect(deriveServerName('node "/opt/my server/srv.js"')).toBe('srv');
    // `sh -c "npx foo"` must never yield a name containing a quote char.
    expect(deriveServerName('sh -c "npx foo-server"')).not.toMatch(/"/);
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
    // readMcpToolsConfig resolves the config path via os.homedir(), which
    // ignores $HOME on Windows (it uses USERPROFILE) — so the HOME override
    // alone left the code reading the runner's real home, and the one test
    // with a stored name that differs from the derived fallback fell through
    // to the derived name (Windows CI: 'git' ≠ 'my-git'). Spy os.homedir
    // directly — the cross-platform pattern already used in mcp-status.spec.
    vi.spyOn(os, 'homedir').mockReturnValue(tmpHome);
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
    vi.restoreAllMocks();
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

  // P2.2 — an explicit --config-name wins over the derived name (but not over an
  // extracted namespaced name), so audit shows "redis-dev" from the first call.
  it('config name beats the derived name', () => {
    expect(resolveServerLabel('get', 'nope', 'npx redis-mcp redis://h', 'redis-dev')).toBe(
      'redis-dev'
    );
  });

  it('an extracted namespaced name still wins over config name', () => {
    expect(resolveServerLabel('mcp__gmail__read_email', 'srv1', 'npx x', 'cfg-name')).toBe('gmail');
  });

  // F4b — the fire-and-forget cloud reporters have NO tool name; they resolve
  // with an empty toolName at REPORT time, so a name persisted by discovery
  // AFTER gateway startup is still picked up (mcp-tools.json read per call).
  it('empty tool name (reporter path) → config name → persisted name → derived, at call time', () => {
    // Late discovery: srv2 has no name at first call…
    expect(resolveServerLabel('', 'srv2', 'uvx mcp-server-git --repo .')).toBe('git');
    // …then discovery persists one — the SAME call now resolves to it.
    const file = path.join(tmpHome, '.node9', 'mcp-tools.json');
    const cfg = JSON.parse(fs.readFileSync(file, 'utf-8'));
    cfg.srv2.name = 'my-git';
    fs.writeFileSync(file, JSON.stringify(cfg));
    expect(resolveServerLabel('', 'srv2', 'uvx mcp-server-git --repo .')).toBe('my-git');
    // configName still beats both.
    expect(resolveServerLabel('', 'srv2', 'uvx mcp-server-git', 'git-prod')).toBe('git-prod');
  });
});
