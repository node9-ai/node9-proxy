/**
 * Integration tests for `node9 posture` — spawns the built CLI subprocess
 * (`dist/cli.js`) against an isolated HOME so the scorecard is deterministic.
 *
 * Requires `npm run build` first (asserts dist/cli.js exists).
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

// A fake token assembled at runtime — matches the DLP "GitHub Token" pattern
// once joined, but no secret-shaped literal appears in this source file.
const FAKE_TOKEN = ['ghp', '_', 'A1b2C3d4E5f6', 'G7h8I9j0K1l2', 'M3n4O5p6Q7r8'].join('');

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runPosture(args: string[], home: string, cwd = home): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const result = spawnSync(process.execPath, [CLI, 'posture', ...args], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd,
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      HOME: home,
      USERPROFILE: home,
    },
  });
  if (result.status === null) {
    console.error(`[runPosture Fail] ${result.error?.message} (signal ${result.signal})`);
  }
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

describe('node9 posture (integration)', () => {
  let home: string;

  beforeAll(() => {
    expect(fs.existsSync(CLI), `built CLI not found at ${CLI} — run npm run build`).toBe(true);
  });

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'posture-int-'));
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('prints a scorecard with a score and the posture header', () => {
    const r = runPosture([], home);
    expect(r.status).not.toBeNull();
    expect(r.stdout).toContain('Node9 Posture');
    expect(r.stdout).toMatch(/Score: \d+\/100/);
  });

  it('emits valid JSON with --json containing score + findings', () => {
    const r = runPosture(['--json'], home);
    const parsed = JSON.parse(r.stdout);
    expect(typeof parsed.score).toBe('number');
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect(typeof parsed.tier).toBe('string');
  });

  it('exits non-zero (2) when the posture is critical', () => {
    // Plant a plaintext secret → guaranteed critical Secrets finding →
    // critical tier, so the critical exit path (process.exitCode = 2) is
    // exercised deterministically rather than depending on the default config.
    fs.writeFileSync(path.join(home, '.env'), `GITHUB_TOKEN=${FAKE_TOKEN}\n`);
    const r = runPosture(['--json'], home);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.tier).toBe('critical');
    expect(r.status).toBe(2);
  });

  it('exits 0 on a clean (non-critical) home', () => {
    const r = runPosture(['--json'], home);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.tier).not.toBe('critical');
    expect(r.status).toBe(0);
  });
});
