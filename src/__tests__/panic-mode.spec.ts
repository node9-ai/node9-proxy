// src/__tests__/panic-mode.spec.ts
//
// Tests for cloud-pushed panic mode + shadow mode. When the rules-cache
// pushed by the SaaS contains panicMode: true, every review-verdict
// action must be upgraded to a hard block. When shadowMode: true, every
// block becomes a would-block (observed but not enforced).
//
// Strategy: real fs in a tmpdir per test. We set HOME to the tmp dir
// (so the cache file lives at <tmp>/.node9/rules-cache.json) and chdir
// into it (so the orchestrator's project-config lookup finds our test
// config at <tmp>/node9.config.json). Same approach as scan-watermark.spec
// — no fragile vi.mock interop on fs/os.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// ── Environment (must come before imports) ─────────────────────────────────
process.env.NODE9_TESTING = '1';
process.env.VITEST = 'true';
process.env.NODE_ENV = 'test';

vi.mock('@inquirer/prompts', () => ({ confirm: vi.fn() }));
vi.mock('../ui/native', () => ({
  askNativePopup: vi.fn().mockResolvedValue('deny'),
  sendDesktopNotification: vi.fn(),
}));
vi.mock('child_process', () => ({
  spawn: vi.fn().mockReturnValue({ unref: vi.fn() }),
  spawnSync: vi.fn().mockReturnValue({ status: 1, stdout: '', stderr: '' }),
}));

const { mockRegisterDaemonEntry } = vi.hoisted(() => ({
  mockRegisterDaemonEntry: vi.fn().mockResolvedValue('fake-id'),
}));

vi.mock('../auth/daemon.js', () => ({
  DAEMON_PORT: 7391,
  DAEMON_HOST: '127.0.0.1',
  notifyActivitySocket: vi.fn().mockResolvedValue(undefined),
  checkStatePredicates: vi.fn().mockResolvedValue(null),
  isDaemonRunning: vi.fn().mockReturnValue(false),
  checkTaint: vi.fn().mockResolvedValue({ tainted: false }),
  registerDaemonEntry: mockRegisterDaemonEntry,
  waitForDaemonDecision: vi.fn().mockResolvedValue({ decision: 'allow' }),
  notifyDaemonViewer: vi.fn().mockResolvedValue(undefined),
  resolveViaDaemon: vi.fn().mockResolvedValue(undefined),
  notifyTaint: vi.fn().mockResolvedValue(undefined),
  notifyTaintPropagate: vi.fn().mockResolvedValue(undefined),
  getInternalToken: vi.fn().mockReturnValue(null),
}));

vi.mock('../auth/cloud.js', () => ({
  auditLocalAllow: vi.fn().mockResolvedValue(undefined),
  initNode9SaaS: vi.fn().mockResolvedValue({ allow: false, denyReason: 'no cloud' }),
  pollNode9SaaS: vi.fn().mockResolvedValue(null),
  resolveNode9SaaS: vi.fn().mockResolvedValue(undefined),
}));

import { authorizeHeadless, _resetConfigCache } from '../core.js';

// ── Per-test isolated filesystem ──────────────────────────────────────────

let tmpHome: string;
let originalHome: string | undefined;
let originalUserProfile: string | undefined;
let originalCwd: string;

beforeEach(() => {
  // Snapshot env + cwd to restore in afterEach.
  originalHome = process.env.HOME;
  originalUserProfile = process.env.USERPROFILE;
  originalCwd = process.cwd();

  // Fresh tmp dir per test. Used as both HOME (cache lives here) and cwd
  // (project-config lookup finds our test config here).
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'n9-panic-'));
  process.env.HOME = tmpHome;
  process.env.USERPROFILE = tmpHome;
  fs.mkdirSync(path.join(tmpHome, '.node9'), { recursive: true });
  process.chdir(tmpHome);

  _resetConfigCache();
  mockRegisterDaemonEntry.mockReset().mockResolvedValue('fake-id');
});

afterEach(() => {
  // Always restore cwd before HOME so tmp dir cleanup is safe.
  try {
    process.chdir(originalCwd);
  } catch {
    /* original cwd may have been deleted by another test — ignore */
  }
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  if (originalUserProfile === undefined) delete process.env.USERPROFILE;
  else process.env.USERPROFILE = originalUserProfile;
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

// ── Helpers ────────────────────────────────────────────────────────────────

const REVIEW_RULE = {
  name: 'review-deploy',
  tool: 'Bash',
  conditions: [{ field: 'command', op: 'matches', value: 'deploy\\.sh' }],
  verdict: 'review',
  reason: 'Deploys require review',
};

function configWithRule(rule: object) {
  return {
    settings: { mode: 'standard', approvalTimeoutMs: 50 },
    policy: { smartRules: [rule] },
  };
}

function cacheWithFlags(flags: { panicMode?: boolean; shadowMode?: boolean }) {
  return {
    fetchedAt: '2026-05-03T00:00:00.000Z',
    rules: [],
    panicMode: flags.panicMode === true,
    shadowMode: flags.shadowMode === true,
  };
}

/** Write the project config + cloud rules-cache for a test scenario. */
function writeFixtures(opts: { config: object; cache?: object }): void {
  fs.writeFileSync(path.join(tmpHome, 'node9.config.json'), JSON.stringify(opts.config));
  if (opts.cache) {
    fs.writeFileSync(path.join(tmpHome, '.node9', 'rules-cache.json'), JSON.stringify(opts.cache));
  }
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe('cloud panic mode', () => {
  it('upgrades a review-verdict rule to a hard block when panicMode is true', async () => {
    writeFixtures({
      config: configWithRule(REVIEW_RULE),
      cache: cacheWithFlags({ panicMode: true }),
    });

    const result = await authorizeHeadless('Bash', { command: './deploy.sh' });

    expect(result.approved).toBe(false);
    expect(result.blockedByLabel).toMatch(/Panic mode/);
    expect(result.reason).toMatch(/panic mode/i);
    // Hard-block path bypasses the race engine entirely — no daemon registration.
    expect(mockRegisterDaemonEntry).not.toHaveBeenCalled();
  });

  it('panic-mode block carries a reason pointing the user back to their admin', async () => {
    writeFixtures({
      config: configWithRule(REVIEW_RULE),
      cache: cacheWithFlags({ panicMode: true }),
    });

    const result = await authorizeHeadless('Bash', { command: './deploy.sh' });

    expect(result.reason).toMatch(/admin|dashboard/i);
  });

  it('does not block when panicMode is false (only the upgrade is conditional)', async () => {
    writeFixtures({
      config: configWithRule(REVIEW_RULE),
      cache: cacheWithFlags({ panicMode: false }),
    });

    const result = await authorizeHeadless('Bash', { command: './deploy.sh' });

    // Without panicMode the orchestrator must not synthesize a panic block.
    // The result might still be approved/denied via other paths (race engine,
    // cloud approver) but it must NOT carry the panic-mode label.
    expect(result.blockedByLabel ?? '').not.toMatch(/Panic mode/);
  });

  it('panic mode does not affect allow-verdict rules — safe ops stay allowed', async () => {
    const ALLOW_RULE = {
      name: 'allow-ls',
      tool: 'Bash',
      conditions: [{ field: 'command', op: 'matches', value: '^ls\\b' }],
      verdict: 'allow',
      reason: 'ls is always safe',
    };
    writeFixtures({
      config: configWithRule(ALLOW_RULE),
      cache: cacheWithFlags({ panicMode: true }),
    });

    const result = await authorizeHeadless('Bash', { command: 'ls -la' });

    // Panic mode upgrades review → block; it must NOT touch allow verdicts.
    // Otherwise the ignored-tool fast path (Read/Grep/Glob) and explicit
    // user-allow rules would also be blocked, which is too aggressive even
    // for a panic switch.
    expect(result.approved).toBe(true);
    expect(result.blockedByLabel ?? '').not.toMatch(/Panic mode/);
  });
});

describe('cloud shadow mode', () => {
  it('shadowMode in cache forces settings.mode to observe (block becomes would-block)', async () => {
    const BLOCK_RULE = {
      name: 'block-deploy',
      tool: 'Bash',
      conditions: [{ field: 'command', op: 'matches', value: 'deploy\\.sh' }],
      verdict: 'block',
      reason: 'No deploys',
    };
    writeFixtures({
      config: configWithRule(BLOCK_RULE),
      cache: cacheWithFlags({ shadowMode: true }),
    });

    const result = await authorizeHeadless('Bash', { command: './deploy.sh' });

    // observe mode: never blocks, but tags the result as observeWouldBlock
    expect(result.approved).toBe(true);
    expect(result.observeWouldBlock).toBe(true);
  });
});
