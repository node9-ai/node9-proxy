/**
 * Integration tests for `node9 report --json`.
 *
 * Spawns the real built CLI subprocess against an isolated HOME (so no
 * audit.log exists) and asserts that stdout is valid JSON with the
 * documented envelope. Required per CLAUDE.md "anything that touches
 * stdout/stderr (protocol correctness)" — this test catches a stray
 * console.log leaking into the JSON stream.
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

function runReport(args: string[], env: Record<string, string> = {}, timeoutMs = 30000): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const result = spawnSync(process.execPath, [CLI, 'report', ...args], {
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
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-report-json-'));
});

afterEach(() => {
  if (tmpHome && fs.existsSync(tmpHome)) {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
});

describe('node9 report --json', () => {
  it('emits valid JSON with the documented envelope when audit.log is empty', () => {
    const r = runReport(['--json'], { HOME: tmpHome });

    expect(r.status).toBe(0);

    let parsed: unknown;
    expect(() => {
      parsed = JSON.parse(r.stdout);
    }).not.toThrow();

    const env = parsed as Record<string, unknown>;
    expect(env.schemaVersion).toBe(1);
    expect(typeof env.generatedAt).toBe('string');
    expect(env.period).toBe('7d');
    expect(env.range).toMatchObject({
      start: expect.any(String),
      end: expect.any(String),
    });
    expect(env.totals).toMatchObject({
      events: 0,
      blocked: 0,
      blockRate: 0,
      userApproved: 0,
      userDenied: 0,
      timedOut: 0,
      hardBlocked: 0,
      dlpBlocked: 0,
      observeDlp: 0,
      loopHits: 0,
      unackedDlp: 0,
    });
    expect(env.tests).toMatchObject({ passes: 0, fails: 0 });
    expect(env.cost).toBeDefined();
    expect(Array.isArray(env.byTool)).toBe(true);
    expect(Array.isArray(env.byBlock)).toBe(true);
    expect(Array.isArray(env.byDay)).toBe(true);
    expect(env.trend).toMatchObject({ priorBlockRate: null, deltaPct: null });
  });

  it('emits valid JSON with the supplied period', () => {
    const r = runReport(['--json', '--period=30d'], { HOME: tmpHome });
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout) as Record<string, unknown>;
    expect(parsed.period).toBe('30d');
  });

  it('produces parseable output when audit.log has entries (DLP warning gated)', () => {
    // Write a minimal audit.log with one entry that would normally trigger
    // the unacked-DLP banner (source: 'response-dlp'). Expect: clean JSON,
    // unackedDlp count surfaces in totals, no banner leakage.
    const node9Dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(node9Dir, { recursive: true });
    const auditPath = path.join(node9Dir, 'audit.log');
    const entry = {
      ts: new Date().toISOString(),
      tool: 'Bash',
      decision: 'block',
      source: 'response-dlp',
      checkedBy: 'response-dlp-aws',
    };
    fs.writeFileSync(auditPath, JSON.stringify(entry) + '\n');

    const r = runReport(['--json'], { HOME: tmpHome });
    expect(r.status).toBe(0);

    let parsed: Record<string, unknown>;
    expect(() => {
      parsed = JSON.parse(r.stdout) as Record<string, unknown>;
    }).not.toThrow();

    const totals = (parsed! as { totals: { unackedDlp: number } }).totals;
    expect(totals.unackedDlp).toBe(1);
  });
});
