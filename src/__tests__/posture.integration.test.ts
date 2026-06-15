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

  it('emits valid JSON with --json containing score, findings, and all checks', () => {
    const r = runPosture(['--json'], home);
    const parsed = JSON.parse(r.stdout);
    expect(typeof parsed.score).toBe('number');
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect(typeof parsed.tier).toBe('string');
    expect(parsed.checksRun).toBe(8);
  });

  it('reports critical + exits 2 when node9 is not wired (bare home)', () => {
    // A bare HOME has no node9 hooks/MCP for any agent, so the Coverage check
    // is critical ("not in-path") → critical tier → process.exitCode = 2.
    // Deterministic regardless of the default policy.
    const r = runPosture(['--json'], home);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.tier).toBe('critical');
    expect(r.status).toBe(2);
    expect(parsed.findings.some((f: { category: string }) => f.category === 'Coverage')).toBe(true);
  });
});
