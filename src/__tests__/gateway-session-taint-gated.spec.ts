// The MCP gateway taints its own session when a tool result carries injected
// instructions. authorizeHeadless only consulted session taint for built-in
// write tools and shell network calls, so a bare MCP tool (`create_issue`,
// `send_message`) sailed past a tainted session. The gateway now marks every
// tool the server does not declare read-only as `sessionTaintGated`.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const { mockCheckSessionTaint } = vi.hoisted(() => ({
  mockCheckSessionTaint: vi.fn(async (_id: string) => ({
    tainted: true,
    record: {
      sessionId: 'mcp-gateway-test',
      source: 'output-injection:override-instructions+action-to-destination',
      createdAt: 0,
      expiresAt: Date.now() + 60_000,
    },
  })),
}));

vi.mock('../auth/daemon.js', async (orig) => ({
  ...(await orig<typeof import('../auth/daemon.js')>()),
  isDaemonRunning: () => false,
  notifyActivitySocket: vi.fn(async () => true),
  checkSessionTaint: (id: string) => mockCheckSessionTaint(id),
  checkTaint: vi.fn(async () => ({ tainted: false })),
  getInternalToken: () => null,
}));

import { authorizeHeadless, _resetConfigCache } from '../core.js';

// The real caller's shape: the gateway forwards BARE tool names.
const META = { agent: 'claude-code', mcpServer: 'github', sessionId: 'mcp-gateway-test' };

describe('gateway session taint reaches MCP tools that are not read-only', () => {
  let home: string;
  let origHome: string | undefined;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-gw-taint-'));
    origHome = process.env.HOME;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 50,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
        },
      })
    );
    _resetConfigCache();
    mockCheckSessionTaint.mockClear();
  });

  afterEach(() => {
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    fs.rmSync(home, { recursive: true, force: true });
    _resetConfigCache();
  });

  it('a gated MCP tool in a tainted session is not auto-approved', async () => {
    const r = await authorizeHeadless('create_issue', { title: 'x' }, META, {
      sessionTaintGated: true,
    });
    expect(mockCheckSessionTaint).toHaveBeenCalledWith('mcp-gateway-test');
    expect(r.approved).toBe(false);
  });

  it('control: the same call without the flag never consults session taint', async () => {
    const r = await authorizeHeadless('create_issue', { title: 'x' }, META, {});
    expect(mockCheckSessionTaint).not.toHaveBeenCalled();
    expect(r.approved).toBe(true);
  });

  it('a read-only tool (flag false) is not routed by taint', async () => {
    const r = await authorizeHeadless('list_issues', {}, META, { sessionTaintGated: false });
    expect(mockCheckSessionTaint).not.toHaveBeenCalled();
    expect(r.approved).toBe(true);
  });
});
