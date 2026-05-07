/**
 * Integration tests for `node9 scan --json`.
 *
 * Spawns the real built CLI subprocess against an isolated HOME (so no
 * real agent history is found) and asserts that stdout is valid JSON
 * with the documented envelope. Required per CLAUDE.md "anything that
 * touches stdout/stderr (protocol correctness)" — this is the test
 * that catches a stray console.log leaking into the JSON stream.
 *
 * Requires: `npm run build` before running.
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

function runScan(args: string[], env: Record<string, string> = {}, timeoutMs = 30000): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const result = spawnSync(process.execPath, [CLI, 'scan', ...args], {
    encoding: 'utf-8',
    timeout: timeoutMs,
    cwd: os.tmpdir(),
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      ...env,
      ...(env.HOME != null ? { USERPROFILE: env.HOME } : {}),
    },
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

let tmpHome: string;

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(
      `dist/cli.js not found. Run "npm run build" before running integration tests.\nExpected: ${CLI}`
    );
  }
});

beforeEach(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-scan-json-'));
});

afterEach(() => {
  if (tmpHome && fs.existsSync(tmpHome)) {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
});

describe('node9 scan --json', () => {
  it('emits valid JSON to stdout with the documented envelope', () => {
    const r = runScan(['--json', '--days=0'], { HOME: tmpHome });

    expect(r.status).toBe(0);

    // The single most important assertion: stdout is parseable. If a
    // console.log leaked through any gate, this fails.
    let parsed: unknown;
    expect(() => {
      parsed = JSON.parse(r.stdout);
    }).not.toThrow();

    const env = parsed as Record<string, unknown>;
    expect(env.schemaVersion).toBe(1);
    expect(typeof env.generatedAt).toBe('string');
    expect(typeof env.isWired).toBe('boolean');
    expect(typeof env.score).toBe('number');
    expect(['good', 'at-risk', 'critical']).toContain(env.band);
    expect(env.totals).toMatchObject({
      blocked: expect.any(Number),
      review: expect.any(Number),
      leaks: expect.any(Number),
      loops: expect.any(Number),
      blastExposures: expect.any(Number),
    });
    expect(env.summary).toBeDefined();
    expect(env.blast).toBeDefined();
  });

  it('exits 1 when --json is combined with --compact', () => {
    const r = runScan(['--json', '--compact'], { HOME: tmpHome });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--json cannot be combined');
    expect(r.stdout).toBe(''); // no JSON, no chalk — stderr only
  });

  it('exits 1 when --json is combined with --narrative', () => {
    const r = runScan(['--json', '--narrative'], { HOME: tmpHome });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--json cannot be combined');
  });

  it('exits 1 when --json is combined with --upload-history', () => {
    const r = runScan(['--json', '--upload-history'], { HOME: tmpHome });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('--json cannot be combined');
  });
});
