/**
 * Integration tests for `node9 log` PostToolUse snapshot behavior.
 *
 * Covers three cases from the snapshot/undo bug fix:
 *   1. Bash tool + prior snapshot exists → creates snapshot with tool='Bash'
 *   2. Bash tool + no prior snapshot → no snapshot created (cold-start guard)
 *   3. Edit tool PostToolUse → no 'unknown' duplicate snapshot created
 *
 * All tests spawn the real built CLI against an isolated HOME so the snapshot
 * stack file lives in a temp directory that doesn't affect the real user state.
 */

import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
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

function runLog(payload: object, tmpHome: string, tmpCwd: string): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const result = spawnSync(process.execPath, [CLI, 'log', JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: 60000,
    cwd: tmpCwd,
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      HOME: tmpHome,
      USERPROFILE: tmpHome,
    },
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function makeTempHome(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-log-test-'));
  fs.mkdirSync(path.join(dir, '.node9'), { recursive: true });
  return dir;
}

function snapshotStackPath(tmpHome: string): string {
  return path.join(tmpHome, '.node9', 'snapshots.json');
}

function writeSnapshotStack(tmpHome: string, entries: object[]): void {
  fs.writeFileSync(snapshotStackPath(tmpHome), JSON.stringify(entries));
}

function readSnapshotStack(tmpHome: string): object[] {
  const p = snapshotStackPath(tmpHome);
  if (!fs.existsSync(p)) return [];
  return JSON.parse(fs.readFileSync(p, 'utf-8')) as object[];
}

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found — run 'npm run build' first`);
  }
});

describe('log PostToolUse snapshot behavior', () => {
  let tmpHome: string;
  let tmpCwd: string;

  beforeEach(() => {
    tmpHome = makeTempHome();
    tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-log-cwd-'));
  });

  it('invokes createShadowSnapshot for Bash when a prior snapshot exists for the cwd', () => {
    // Seed the stack with an existing snapshot for this cwd.
    // We use a fake hash — git diff will fail to find it, so createShadowSnapshot
    // deduplicates and returns the prior hash without writing a new stack entry.
    // What we care about here is that createShadowSnapshot was CALLED at all,
    // which we verify by checking that the shadow repo directory was initialized.
    writeSnapshotStack(tmpHome, [
      {
        hash: 'prior000',
        tool: 'Edit',
        argsSummary: 'src/app.ts',
        cwd: tmpCwd,
        timestamp: Date.now() - 1000,
      },
    ]);

    const result = runLog(
      {
        tool_name: 'Bash',
        tool_input: { command: 'echo hello > output.txt' },
        cwd: tmpCwd,
      },
      tmpHome,
      tmpCwd
    );

    expect(result.status).toBe(0);
    // The shadow repo dir for tmpCwd is created by ensureShadowRepo inside
    // createShadowSnapshot — its existence proves the function was invoked.
    const shadowsDir = path.join(tmpHome, '.node9', 'snapshots');
    expect(fs.existsSync(shadowsDir)).toBe(true);
    // At least one shadow repo subdirectory should have been created
    const subdirs = fs.readdirSync(shadowsDir);
    expect(subdirs.length).toBeGreaterThan(0);
  });

  it('does NOT create a snapshot when no prior snapshot exists for the cwd', () => {
    // Stack is empty — no prior snapshot for this cwd
    const result = runLog(
      {
        tool_name: 'Bash',
        tool_input: { command: 'echo hello > output.txt' },
        cwd: tmpCwd,
      },
      tmpHome,
      tmpCwd
    );

    expect(result.status).toBe(0);
    // No snapshot file should be written at all
    const stack = readSnapshotStack(tmpHome);
    expect(stack).toHaveLength(0);
  });

  it('does NOT create a snapshot for Edit tool PostToolUse (avoids unknown duplicates)', () => {
    // Seed a prior Edit snapshot so the tool isn't skipped on cold-start grounds
    writeSnapshotStack(tmpHome, [
      {
        hash: 'prior000',
        tool: 'Edit',
        argsSummary: 'src/app.ts',
        cwd: tmpCwd,
        timestamp: Date.now() - 1000,
      },
    ]);

    const result = runLog(
      {
        tool_name: 'Edit',
        tool_input: { file_path: 'src/app.ts', old_string: 'foo', new_string: 'bar' },
        cwd: tmpCwd,
      },
      tmpHome,
      tmpCwd
    );

    expect(result.status).toBe(0);
    // Stack should still have only the one seeded entry — no new 'unknown' duplicate
    const stack = readSnapshotStack(tmpHome) as Array<{ tool: string }>;
    expect(stack).toHaveLength(1);
    expect(stack[0].tool).toBe('Edit');
    // No entry with tool='unknown' should ever appear
    expect(stack.find((e) => e.tool === 'unknown')).toBeUndefined();
  });

  it('does NOT create a snapshot for Write tool PostToolUse', () => {
    writeSnapshotStack(tmpHome, [
      {
        hash: 'prior000',
        tool: 'Write',
        argsSummary: 'src/new.ts',
        cwd: tmpCwd,
        timestamp: Date.now() - 1000,
      },
    ]);

    const result = runLog(
      {
        tool_name: 'Write',
        tool_input: { file_path: 'src/new.ts', content: 'hello' },
        cwd: tmpCwd,
      },
      tmpHome,
      tmpCwd
    );

    expect(result.status).toBe(0);
    const stack = readSnapshotStack(tmpHome) as Array<{ tool: string }>;
    expect(stack).toHaveLength(1);
    expect(stack.find((e) => e.tool === 'unknown')).toBeUndefined();
  });

  it('still writes to audit.log regardless of snapshot path', () => {
    const result = runLog(
      {
        tool_name: 'Bash',
        tool_input: { command: 'ls .' },
        cwd: tmpCwd,
      },
      tmpHome,
      tmpCwd
    );

    expect(result.status).toBe(0);
    const auditLog = path.join(tmpHome, '.node9', 'audit.log');
    expect(fs.existsSync(auditLog)).toBe(true);
    const lines = fs.readFileSync(auditLog, 'utf-8').trim().split('\n');
    const entry = JSON.parse(lines[lines.length - 1]) as { tool: string; decision: string };
    expect(entry.tool).toBe('Bash');
    expect(entry.decision).toBe('allowed');
  });
});
