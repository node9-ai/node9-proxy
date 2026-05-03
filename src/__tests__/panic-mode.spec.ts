// src/__tests__/panic-mode.spec.ts
// Tests for cloud-pushed panic mode: when settings.panicMode is true (synced
// from the SaaS workspace's isPanicMode flag into ~/.node9/rules-cache.json),
// every review-verdict action is upgraded to a hard block. The orchestrator
// applies the transformation after evaluatePolicy() returns its verdict.
//
// Mocking shape mirrors observe-mode.spec.ts. Each test seeds a project
// config + cloud-cache fixture and calls authorizeHeadless() to exercise
// the full orchestrator path.

import { describe, it, expect, vi, beforeEach } from 'vitest';
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

// ── fs / homedir mocks ─────────────────────────────────────────────────────
const existsSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
const readSpy = vi.spyOn(fs, 'readFileSync');
vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');

// ── Module imports ─────────────────────────────────────────────────────────
import { authorizeHeadless, _resetConfigCache } from '../core.js';

// ── Helpers ────────────────────────────────────────────────────────────────

const PROJECT_PATH = path.join(process.cwd(), 'node9.config.json');
const CACHE_PATH = '/mock/home/.node9/rules-cache.json';

function mockFiles(files: Record<string, string>) {
  existsSpy.mockImplementation((p) => String(p) in files);
  readSpy.mockImplementation((p) => {
    const content = files[String(p)];
    if (content === undefined) throw new Error(`ENOENT: ${String(p)}`);
    return content;
  });
}

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

// ── Lifecycle ──────────────────────────────────────────────────────────────

beforeEach(() => {
  _resetConfigCache();
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  mockRegisterDaemonEntry.mockReset().mockResolvedValue('fake-id');
});

// ── Tests ──────────────────────────────────────────────────────────────────

describe('cloud panic mode', () => {
  it('upgrades a review-verdict rule to a hard block when panicMode is true', async () => {
    mockFiles({
      [PROJECT_PATH]: JSON.stringify(configWithRule(REVIEW_RULE)),
      [CACHE_PATH]: JSON.stringify(cacheWithFlags({ panicMode: true })),
    });

    const result = await authorizeHeadless('Bash', { command: './deploy.sh' });

    expect(result.approved).toBe(false);
    expect(result.blockedByLabel).toMatch(/Panic mode/);
    expect(result.reason).toMatch(/panic mode/i);
    // Hard-block path bypasses the race engine entirely — no daemon registration.
    expect(mockRegisterDaemonEntry).not.toHaveBeenCalled();
  });

  it('panic-mode block carries a reason pointing the user back to their admin', async () => {
    mockFiles({
      [PROJECT_PATH]: JSON.stringify(configWithRule(REVIEW_RULE)),
      [CACHE_PATH]: JSON.stringify(cacheWithFlags({ panicMode: true })),
    });

    const result = await authorizeHeadless('Bash', { command: './deploy.sh' });

    expect(result.reason).toMatch(/admin|dashboard/i);
  });

  it('does not block when panicMode is false (only the upgrade is conditional)', async () => {
    mockFiles({
      [PROJECT_PATH]: JSON.stringify(configWithRule(REVIEW_RULE)),
      [CACHE_PATH]: JSON.stringify(cacheWithFlags({ panicMode: false })),
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
    mockFiles({
      [PROJECT_PATH]: JSON.stringify(configWithRule(ALLOW_RULE)),
      [CACHE_PATH]: JSON.stringify(cacheWithFlags({ panicMode: true })),
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
    mockFiles({
      [PROJECT_PATH]: JSON.stringify(configWithRule(BLOCK_RULE)),
      [CACHE_PATH]: JSON.stringify(cacheWithFlags({ shadowMode: true })),
    });

    const result = await authorizeHeadless('Bash', { command: './deploy.sh' });

    // observe mode: never blocks, but tags the result as observeWouldBlock
    expect(result.approved).toBe(true);
    expect(result.observeWouldBlock).toBe(true);
  });
});
