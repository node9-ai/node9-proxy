// P3 Phase 2 polish — friendly MCP server name derived from the launch command,
// reported in the SEE inventory so the dashboard shows "Filesystem" not a hash.
import { describe, it, expect } from 'vitest';
import { deriveServerName } from '../daemon/mcp-tools';

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
