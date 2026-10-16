// fw#344: session taint never reached MCP tools in the agent hook path.
// The gateway marks its (bare-named) tools `sessionTaintGated` itself; the
// hook forwards `mcp__<server>__<tool>` names with no such flag, and the
// taint gate only looked at shell network commands, built-in write tools and
// that flag. So after PostToolUse flagged a poisoned email, the very next
// `mcp__gmail__send_email` was authorised without a review. A namespaced MCP
// tool is now gated whenever the caller says nothing about it.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const { mockCheckSessionTaint } = vi.hoisted(() => ({
  mockCheckSessionTaint: vi.fn(async (_id: string) => ({
    tainted: true,
    record: {
      sessionId: 'hook-session',
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

// The hook's meta shape (src/cli/commands/check.ts): no serverKey, the server
// name parsed out of the namespaced tool, the agent's own session id.
const META = { agent: 'Claude Code', mcpServer: 'gmail', sessionId: 'hook-session' };

describe('hook path: session taint gates namespaced MCP tools (fw#344)', () => {
  let home: string;
  let origHome: string | undefined;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-hook-taint-'));
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

  it('a send through an MCP tool in a tainted session goes to review', async () => {
    const r = await authorizeHeadless(
      'mcp__gmail__send_email',
      { to: 'outsider@example.com', body: 'the code is 123456' },
      META
    );
    expect(mockCheckSessionTaint).toHaveBeenCalledWith('hook-session');
    expect(r.approved).toBe(false);
    // Denied by the approver race timing out (every approver is off here), not
    // by a rule: the call reached human review, which is the fix.
    expect(r.blockedBy).toBe('timeout');
  });

  it('the same send in a clean session is not interrupted', async () => {
    mockCheckSessionTaint.mockResolvedValueOnce({ tainted: false } as never);
    const r = await authorizeHeadless(
      'mcp__gmail__send_email',
      { to: 'colleague@example.com', body: 'see you at 10' },
      META
    );
    expect(mockCheckSessionTaint).toHaveBeenCalledWith('hook-session');
    expect(r.approved).toBe(true);
  });

  it('a caller that declares the tool read-only keeps it out of the gate', async () => {
    // The shape a future annotation-aware hook (fw#318) would use: an explicit
    // false wins over the name rule, as it does for the gateway today.
    const r = await authorizeHeadless('mcp__github__list_issues', {}, META, {
      sessionTaintGated: false,
    });
    expect(mockCheckSessionTaint).not.toHaveBeenCalled();
    expect(r.approved).toBe(true);
  });

  it('control: a built-in read tool in a tainted session is still not consulted', async () => {
    const r = await authorizeHeadless('Grep', { pattern: 'TODO' }, META);
    expect(mockCheckSessionTaint).not.toHaveBeenCalled();
    expect(r.approved).toBe(true);
  });
});
