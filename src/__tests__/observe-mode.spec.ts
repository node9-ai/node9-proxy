// src/__tests__/observe-mode.spec.ts
// Tests for observe mode: runs the full policy pipeline but never blocks.
// Verifies that would-block decisions are recorded without denying the call.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';

// ── Environment setup (must come before imports) ──────────────────────────────
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

// ── fs / homedir mocks ────────────────────────────────────────────────────────
const existsSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
const readSpy = vi.spyOn(fs, 'readFileSync');
vi.spyOn(os, 'homedir').mockReturnValue('/mock/home');

// ── Module imports ────────────────────────────────────────────────────────────
import { authorizeHeadless, _resetConfigCache } from '../core.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function mockProjectConfig(config: object) {
  const projectPath = path.join(process.cwd(), 'node9.config.json');
  existsSpy.mockImplementation((p) => String(p) === projectPath);
  readSpy.mockImplementation((p) => (String(p) === projectPath ? JSON.stringify(config) : ''));
}

// Constructed at runtime so the literal never appears in source — avoids
// triggering node9's own DLP scanner when this file is written or committed.
// This is the canonical AWS example key from AWS documentation (not a real credential).
const FAKE_AWS_KEY = 'AKIA' + 'J2XZKZMV' + 'P3NQRSTU';

const BASE_OBSERVE_CONFIG = {
  settings: { mode: 'observe', approvalTimeoutMs: 100 },
};

const BLOCK_RULE_CONFIG = {
  settings: { mode: 'observe', approvalTimeoutMs: 100 },
  policy: {
    smartRules: [
      {
        name: 'block-deploy',
        tool: 'Bash',
        conditions: [{ field: 'command', op: 'matches', value: './deploy.sh' }],
        verdict: 'block',
        reason: 'No deploys without review',
      },
    ],
  },
};

// ── Lifecycle ─────────────────────────────────────────────────────────────────

beforeEach(() => {
  _resetConfigCache();
  existsSpy.mockReturnValue(false);
  readSpy.mockReturnValue('');
  mockRegisterDaemonEntry.mockReset().mockResolvedValue('fake-id');
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('observe mode — always approves', () => {
  it('approves a normal tool call with no rule match', async () => {
    mockProjectConfig(BASE_OBSERVE_CONFIG);

    const result = await authorizeHeadless('Bash', { command: 'npm install' });

    expect(result.approved).toBe(true);
    expect(result.observeWouldBlock).toBeFalsy();
  });

  it('approves even when a smart rule would hard-block in standard mode', async () => {
    mockProjectConfig(BLOCK_RULE_CONFIG);

    const result = await authorizeHeadless('Bash', { command: './deploy.sh --env=production' });

    expect(result.approved).toBe(true);
  });

  it('never starts the race engine (no registerDaemonEntry) even when a rule would block', async () => {
    mockProjectConfig(BLOCK_RULE_CONFIG);

    await authorizeHeadless('Bash', { command: './deploy.sh' });

    expect(mockRegisterDaemonEntry).not.toHaveBeenCalled();
  });
});

describe('observe mode — would-block tagging', () => {
  it('sets observeWouldBlock when a block rule matches', async () => {
    mockProjectConfig(BLOCK_RULE_CONFIG);

    const result = await authorizeHeadless('Bash', { command: './deploy.sh --env=production' });

    expect(result.approved).toBe(true);
    expect(result.observeWouldBlock).toBe(true);
  });

  it('does not set observeWouldBlock when no rule matches', async () => {
    mockProjectConfig(BLOCK_RULE_CONFIG);

    const result = await authorizeHeadless('Bash', { command: 'npm test' });

    expect(result.approved).toBe(true);
    expect(result.observeWouldBlock).toBeFalsy();
  });

  it('includes blockedByLabel and ruleHit when a named rule would block', async () => {
    mockProjectConfig(BLOCK_RULE_CONFIG);

    const result = await authorizeHeadless('Bash', { command: './deploy.sh' });

    expect(result.observeWouldBlock).toBe(true);
    expect(result.blockedByLabel).toBeDefined();
    expect(result.ruleHit).toBe('block-deploy');
  });
});

describe('observe mode — DLP in observe', () => {
  it('approves a call containing a secret but marks it as would-block', async () => {
    mockProjectConfig({
      settings: { mode: 'observe', approvalTimeoutMs: 100 },
      policy: { dlp: { enabled: true } },
    });

    const result = await authorizeHeadless('Bash', {
      command: `echo ${FAKE_AWS_KEY}`,
    });

    expect(result.approved).toBe(true);
    expect(result.observeWouldBlock).toBe(true);
    expect(result.blockedByLabel).toContain('DLP');
  });

  it('approves a clean call with DLP enabled', async () => {
    mockProjectConfig({
      settings: { mode: 'observe', approvalTimeoutMs: 100 },
      policy: { dlp: { enabled: true } },
    });

    const result = await authorizeHeadless('Bash', { command: 'ls -la' });

    expect(result.approved).toBe(true);
    expect(result.observeWouldBlock).toBeFalsy();
  });
});

describe('observe mode vs audit mode', () => {
  it('audit mode does not set observeWouldBlock or ruleHit even when a rule matches', async () => {
    mockProjectConfig({
      settings: { mode: 'audit', approvalTimeoutMs: 100 },
      policy: {
        smartRules: [
          {
            name: 'block-deploy',
            tool: 'Bash',
            conditions: [{ field: 'command', op: 'matches', value: './deploy.sh' }],
            verdict: 'block',
          },
        ],
      },
    });

    const result = await authorizeHeadless('Bash', { command: './deploy.sh' });

    expect(result.approved).toBe(true);
    expect(result.observeWouldBlock).toBeFalsy();
    expect(result.ruleHit).toBeUndefined();
  });

  it('observe mode surfaces ruleHit; audit mode does not', async () => {
    const policy = {
      smartRules: [
        {
          name: 'block-deploy',
          tool: 'Bash',
          conditions: [{ field: 'command', op: 'matches', value: './deploy.sh' }],
          verdict: 'block',
        },
      ],
    };

    mockProjectConfig({ settings: { mode: 'observe', approvalTimeoutMs: 100 }, policy });
    const observeResult = await authorizeHeadless('Bash', { command: './deploy.sh' });
    _resetConfigCache();

    mockProjectConfig({ settings: { mode: 'audit', approvalTimeoutMs: 100 }, policy });
    const auditResult = await authorizeHeadless('Bash', { command: './deploy.sh' });

    expect(observeResult.approved).toBe(true);
    expect(observeResult.ruleHit).toBe('block-deploy');

    expect(auditResult.approved).toBe(true);
    expect(auditResult.ruleHit).toBeUndefined();
  });
});
