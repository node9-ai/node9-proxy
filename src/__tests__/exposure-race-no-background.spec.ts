// fw#318 P1.1, design untrusted-content-proxy-p2-p5-code-design.md section 3:
// on the race path (node9's own approver: a `node9 tail` is connected), the
// hook registers a card with the daemon, and the daemon re-runs
// authorizeHeadless in the background WITHOUT the session id. That re-run
// cannot see an exposure or a session taint, so for a rule-free call it
// would answer the card `allow`, which the terminal racer takes as a human
// decision. A call-specific review must therefore register its card with
// skipBackgroundAuth, as app-permission reviews already do.
//
// The vitest silencer forces approvers.terminal off (orchestrator: isTestEnv),
// so this test clears the four test-env markers for the duration of one call
// and mocks every daemon client: nothing real is started or contacted.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

const H = vi.hoisted(() => ({
  registerDaemonEntry: vi.fn(async () => ({ id: 'card-1', allowCount: 1 })),
  waitForDaemonDecision: vi.fn(async () => ({ decision: 'deny' as const, source: 'terminal' })),
  checkSessionExposure: vi.fn(async (_id: string) => ({ exposed: false }) as unknown),
  checkSessionTaint: vi.fn(async (_id: string) => ({ tainted: false }) as unknown),
}));

vi.mock('../auth/daemon.js', async (orig) => ({
  ...(await orig<typeof import('../auth/daemon.js')>()),
  isDaemonRunning: () => true,
  daemonHasInteractiveApprover: async () => true,
  notifyActivitySocket: vi.fn(async () => true),
  registerDaemonEntry: H.registerDaemonEntry,
  waitForDaemonDecision: H.waitForDaemonDecision,
  resolveViaDaemon: vi.fn(async () => undefined),
  notifyDaemonViewer: vi.fn(async () => null),
  checkSessionExposure: (id: string) => H.checkSessionExposure(id),
  checkSessionTaint: (id: string) => H.checkSessionTaint(id),
  approveSessionExposure: vi.fn(async () => undefined),
  checkTaint: vi.fn(async () => ({ tainted: false })),
  getInternalToken: () => 'tok',
}));

import { authorizeHeadless, _resetConfigCache } from '../core.js';

const META = { agent: 'Codex', mcpServer: 'crm', sessionId: 'race-session' };
const ENV_KEYS = ['VITEST', 'NODE_ENV', 'CI', 'NODE9_TESTING'] as const;

/** skipBackgroundAuth is registerDaemonEntry's eighth argument. */
const skipArg = (): unknown => (H.registerDaemonEntry.mock.calls[0] as unknown[] | undefined)?.[7];

describe('race path: a call-specific review never lets the daemon answer its card', () => {
  let home: string;
  let origHome: string | undefined;
  const saved: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>> = {};

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-race-'));
    origHome = process.env.HOME;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          approvalTimeoutMs: 2000,
          reviewChannel: 'approver',
          approvers: { native: false, browser: false, cloud: false, terminal: true },
        },
        policy: { loopDetection: { enabled: false } },
      })
    );
    _resetConfigCache();
    for (const k of ENV_KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    H.registerDaemonEntry.mockClear();
    H.checkSessionExposure.mockReset();
    H.checkSessionExposure.mockResolvedValue({ exposed: false });
    H.checkSessionTaint.mockReset();
    H.checkSessionTaint.mockResolvedValue({ tainted: false });
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    if (origHome !== undefined) process.env.HOME = origHome;
    else delete process.env.HOME;
    fs.rmSync(home, { recursive: true, force: true });
    _resetConfigCache();
  });

  it('an exposure review registers its card with skipBackgroundAuth', async () => {
    H.checkSessionExposure.mockResolvedValue({
      exposed: true,
      record: {
        sessionId: 'race-session',
        sources: [{ tool: 'WebFetch', at: Date.now() }],
        destinations: ['email:press@news.example'],
        userMentioned: [],
        approved: [],
        createdAt: Date.now(),
        expiresAt: Date.now() + 60_000,
      },
    });
    const r = await authorizeHeadless(
      'mcp__crm__add_contact',
      { email: 'press@news.example' },
      META
    );
    expect(H.registerDaemonEntry).toHaveBeenCalledTimes(1);
    expect(skipArg()).toBe(true);
    expect(r.approved).toBe(false);
    // The card carries the reason, not only the label.
    const risk = (H.registerDaemonEntry.mock.calls[0] as unknown[])[3] as {
      ruleDescription?: string;
      ruleName?: string;
    };
    expect(risk.ruleName).toBe('exposure');
    expect(risk.ruleDescription).toMatch(
      /press@news\.example, an address that appeared in that web page/
    );
  });

  it('a session-taint review registers its card with skipBackgroundAuth', async () => {
    H.checkSessionTaint.mockResolvedValue({
      tainted: true,
      record: {
        sessionId: 'race-session',
        source: 'output-injection:override-instructions',
        createdAt: 0,
        expiresAt: Date.now() + 60_000,
      },
    });
    await authorizeHeadless('mcp__crm__add_contact', { email: 'x@y.example' }, META);
    expect(H.registerDaemonEntry).toHaveBeenCalledTimes(1);
    expect(skipArg()).toBe(true);
  });

  it('control: an ordinary review (a smart rule) still lets the daemon run its background check', async () => {
    await authorizeHeadless('Bash', { command: 'git push --force' }, META);
    expect(H.registerDaemonEntry).toHaveBeenCalledTimes(1);
    expect(skipArg()).toBeUndefined();
  });
});
