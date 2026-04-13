/**
 * Integration tests for loop detection in `node9 check`.
 *
 * Spawns the real built CLI subprocess with an isolated HOME directory.
 * Loop state lives at ~/.node9/loop-state.json and persists across
 * sequential check invocations within the same tmpHome.
 *
 * Requirements:
 *   - `npm run build` must be run before these tests
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCheck(
  payload: object,
  env: Record<string, string> = {},
  cwd = os.tmpdir(),
  timeoutMs = 60000
): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const result = spawnSync(process.execPath, [CLI, 'check', JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: timeoutMs,
    cwd,
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      ...env,
      ...(env.HOME != null ? { USERPROFILE: env.HOME } : {}),
    },
  });

  if (result.status === null) {
    const errorMsg = result.error?.message || 'Process terminated';
    console.error(`[runCheck Fail] ${errorMsg}\nStderr: ${result.stderr}`);
  }

  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function makeTempHome(config: object): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-loop-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(path.join(node9Dir, 'config.json'), JSON.stringify(config));
  return tmpHome;
}

function cleanupHome(tmpHome: string) {
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code !== 'EBUSY') throw e;
  }
}

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error('dist/cli.js not found — run `npm run build` first');
  }
});

describe('loop detection — default config (threshold=3, window=120s)', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = makeTempHome({
      settings: { mode: 'standard', autoStartDaemon: false },
    });
  });
  afterEach(() => cleanupHome(tmpHome));

  const payload = { tool_name: 'bash', tool_input: { command: 'echo stuck' } };

  it('allows first two identical calls (below threshold)', () => {
    const r1 = runCheck(payload, { HOME: tmpHome }, tmpHome);
    expect(r1.status).toBe(0);

    const r2 = runCheck(payload, { HOME: tmpHome }, tmpHome);
    expect(r2.status).toBe(0);
  });

  it('blocks the third identical call with loop reason', () => {
    runCheck(payload, { HOME: tmpHome }, tmpHome);
    runCheck(payload, { HOME: tmpHome }, tmpHome);

    const r3 = runCheck(payload, { HOME: tmpHome }, tmpHome);
    expect(r3.status).toBe(2);
    const parsed = JSON.parse(r3.stdout.trim());
    expect(parsed.decision).toBe('block');
    expect(parsed.reason).toContain('Loop Detected');
  });

  it('does not flag different args as a loop', () => {
    runCheck({ tool_name: 'bash', tool_input: { command: 'echo a' } }, { HOME: tmpHome }, tmpHome);
    runCheck({ tool_name: 'bash', tool_input: { command: 'echo b' } }, { HOME: tmpHome }, tmpHome);
    const r3 = runCheck(
      { tool_name: 'bash', tool_input: { command: 'echo c' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r3.status).toBe(0);
  });

  it('does not flag different tools as a loop', () => {
    runCheck({ tool_name: 'bash', tool_input: { command: 'echo x' } }, { HOME: tmpHome }, tmpHome);
    runCheck({ tool_name: 'bash', tool_input: { command: 'echo x' } }, { HOME: tmpHome }, tmpHome);
    // Third call is a different tool with same args shape
    const r3 = runCheck(
      { tool_name: 'write', tool_input: { command: 'echo x' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r3.status).toBe(0);
  });
});

describe('loop detection — disabled via config', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = makeTempHome({
      settings: { mode: 'standard', autoStartDaemon: false },
      policy: { loopDetection: { enabled: false } },
    });
  });
  afterEach(() => cleanupHome(tmpHome));

  it('allows repeated identical calls when loop detection is disabled', () => {
    const payload = { tool_name: 'bash', tool_input: { command: 'echo repeat' } };

    runCheck(payload, { HOME: tmpHome }, tmpHome);
    runCheck(payload, { HOME: tmpHome }, tmpHome);
    const r3 = runCheck(payload, { HOME: tmpHome }, tmpHome);

    // Without loop detection, the 3rd call goes through normal policy evaluation.
    // It should not be blocked by loop detection (may still be reviewed/allowed by policy).
    expect(r3.status).not.toBe(2);
  });
});

describe('loop detection — custom threshold', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = makeTempHome({
      settings: { mode: 'standard', autoStartDaemon: false },
      policy: { loopDetection: { threshold: 5 } },
    });
  });
  afterEach(() => cleanupHome(tmpHome));

  it('allows 4 identical calls when threshold is 5', () => {
    const payload = { tool_name: 'bash', tool_input: { command: 'echo high-threshold' } };

    for (let i = 0; i < 4; i++) {
      const r = runCheck(payload, { HOME: tmpHome }, tmpHome);
      expect(r.status).toBe(0);
    }
  });

  it('blocks at the 5th identical call when threshold is 5', () => {
    const payload = { tool_name: 'bash', tool_input: { command: 'echo high-threshold' } };

    for (let i = 0; i < 4; i++) {
      runCheck(payload, { HOME: tmpHome }, tmpHome);
    }

    const r5 = runCheck(payload, { HOME: tmpHome }, tmpHome);
    expect(r5.status).toBe(2);
    const parsed = JSON.parse(r5.stdout.trim());
    expect(parsed.decision).toBe('block');
    expect(parsed.reason).toContain('Loop Detected');
  });
});
