/**
 * Regression test for the "clean history hides the dashboard" bug.
 *
 * Previously, the scan action handler gated the entire scorecard render on
 * `totalFindings === 0 && scan.dlpFindings.length === 0`. A user with real
 * session activity (cost, tools, sessions) but no risky findings — common
 * for users on a fresh machine or for any activity-light account — saw
 * only a green "✅ No risky operations found in your history" line and
 * nothing else. The COST / ACTIVITY / SHIELDS panels never rendered even
 * though they don't depend on finding risky behavior.
 *
 * Fix: drop the gate so the dashboard always renders once history exists.
 * Risk-specific bands (Critical / High / Medium) collapse on their own
 * inside StaticScorecard when their counts are zero.
 *
 * This test seeds a single benign Claude JSONL session into an isolated
 * HOME, runs the real built CLI, and asserts that the COST and ACTIVITY
 * panel headers appear in stdout while the reassurance line is still
 * shown above them.
 *
 * Requires: `npm run build` before running.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { stripTerminalEscapes } from '../cli/commands/scan';

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

function seedCleanClaudeSession(home: string): void {
  // Mirror the real Claude Code layout: ~/.claude/projects/<projDir>/<sessionId>.jsonl
  const projDir = path.join(home, '.claude', 'projects', '-tmp-clean-proj');
  fs.mkdirSync(projDir, { recursive: true });

  // A benign exchange: one user text prompt, one assistant text reply.
  // No tool_use blocks, no Bash, no secrets. Timestamps are recent so
  // the default --days=90 window includes them.
  const now = new Date().toISOString();
  const lines = [
    JSON.stringify({
      type: 'user',
      timestamp: now,
      message: { content: [{ type: 'text', text: 'hello there' }] },
    }),
    JSON.stringify({
      type: 'assistant',
      timestamp: now,
      message: {
        model: 'claude-sonnet-4-6',
        content: [{ type: 'text', text: 'hi! how can I help?' }],
        usage: { input_tokens: 100, output_tokens: 50 },
      },
    }),
  ];
  fs.writeFileSync(path.join(projDir, 'sess-clean.jsonl'), lines.join('\n') + '\n');
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
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-scan-clean-'));
});

afterEach(() => {
  if (tmpHome && fs.existsSync(tmpHome)) {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  }
});

describe('node9 scan — clean history renders dashboard', () => {
  it('renders COST + ACTIVITY panels when sessions exist but no risky findings', () => {
    seedCleanClaudeSession(tmpHome);

    const r = runScan(['--days=365'], { HOME: tmpHome });

    expect(r.status).toBe(0);
    const out = stripTerminalEscapes(r.stdout);

    // The reassurance line should still be there above the dashboard —
    // we kept it as a banner for clean histories.
    expect(out).toContain('No risky operations found in your history');

    // The whole point of the fix: COST and ACTIVITY panels render even
    // with zero findings. These strings are the Ink panel headers
    // (CostPanel.tsx, ActivityPanel.tsx) and are only emitted when
    // StaticScorecard is actually mounted.
    expect(out).toContain('COST');
    expect(out).toContain('ACTIVITY');
  });
});
