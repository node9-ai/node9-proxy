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
  error?: Error;
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
    error: result.error,
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
    // The engine ships OFF (enableUndo defaults to false — the snapshot store
    // filled a disk), and log.ts gates the Bash snapshot on it. This row is
    // about the PRIOR-SNAPSHOT condition, so it states the precondition rather
    // than inheriting whatever the default happens to be.
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: true } })
    );
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
    // The engine ships OFF (enableUndo defaults to false — the snapshot store
    // filled a disk), and log.ts gates the Bash snapshot on it. This row is
    // about the PRIOR-SNAPSHOT condition, so it states the precondition rather
    // than inheriting whatever the default happens to be.
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({ settings: { enableUndo: true } })
    );
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

  it('attributes agent=Codex when payload has turn_id (regression for #178)', () => {
    // Codex's PostToolUse payload is Claude-compatible except for turn_id —
    // without the turn_id check, this gets misattributed as "Claude Code".
    const result = runLog(
      {
        session_id: '019e34c4-02f7-7002-8384-6e54b99f5bc5',
        turn_id: '019e352f-4df0-7902-b156-0d71433c5a6e',
        cwd: tmpCwd,
        hook_event_name: 'PostToolUse',
        permission_mode: 'default',
        tool_name: 'Bash',
        tool_input: { command: 'ls /tmp' },
        tool_use_id: 'call_fEKINAMZxjMuJbczLPxtBwTF',
      },
      tmpHome,
      tmpCwd
    );

    expect(result.status).toBe(0);
    const auditLog = path.join(tmpHome, '.node9', 'audit.log');
    const lines = fs.readFileSync(auditLog, 'utf-8').trim().split('\n');
    const entry = JSON.parse(lines[lines.length - 1]) as { tool: string; agent?: string };
    expect(entry.agent).toBe('Codex');
  });

  it('attributes agent=Claude Code when payload has no turn_id', () => {
    // Sanity: existing Claude detection must still work — turn_id absence
    // means the original PreToolUse/permission_mode fingerprint takes over.
    const result = runLog(
      {
        cwd: tmpCwd,
        hook_event_name: 'PostToolUse',
        permission_mode: 'default',
        tool_name: 'Bash',
        tool_input: { command: 'ls /tmp' },
        tool_use_id: 'toolu_claude_abc',
      },
      tmpHome,
      tmpCwd
    );

    expect(result.status).toBe(0);
    const auditLog = path.join(tmpHome, '.node9', 'audit.log');
    const lines = fs.readFileSync(auditLog, 'utf-8').trim().split('\n');
    const entry = JSON.parse(lines[lines.length - 1]) as { tool: string; agent?: string };
    expect(entry.agent).toBe('Claude Code');
  });

  it('honors meta.agent over hook_event_name fingerprint (Pi/Opencode shims)', () => {
    // The Pi shim (and Opencode shim) tag tool_result payloads with
    // meta.agent: "Pi"/"Opencode" — but they still ship
    // hook_event_name: "PostToolUse" because that's the format `node9
    // log` understands. Without a Layer-0 meta.agent check (mirroring
    // check.ts:48-60), log.ts's local fingerprint chain misattributes
    // these rows to "Claude Code" (regression discovered during pi
    // integration live verify, doc/roadmap/pi-integration.md).
    const result = runLog(
      {
        cwd: tmpCwd,
        hook_event_name: 'PostToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'echo hi' },
        meta: { agent: 'Pi' },
      },
      tmpHome,
      tmpCwd
    );

    expect(result.status).toBe(0);
    const auditLog = path.join(tmpHome, '.node9', 'audit.log');
    const lines = fs.readFileSync(auditLog, 'utf-8').trim().split('\n');
    const entry = JSON.parse(lines[lines.length - 1]) as { tool: string; agent?: string };
    expect(entry.agent).toBe('Pi');
  });

  it('ignores meta.agent if empty string or non-string (defensive)', () => {
    // Mirrors check.ts:57-60 — a malformed payload with meta.agent: ""
    // or meta.agent: null must fall through to the existing fingerprint
    // chain, never tag the row with an empty-string agent name.
    const result = runLog(
      {
        cwd: tmpCwd,
        hook_event_name: 'PostToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'echo hi' },
        meta: { agent: '' },
      },
      tmpHome,
      tmpCwd
    );

    expect(result.status).toBe(0);
    const auditLog = path.join(tmpHome, '.node9', 'audit.log');
    const lines = fs.readFileSync(auditLog, 'utf-8').trim().split('\n');
    const entry = JSON.parse(lines[lines.length - 1]) as { tool: string; agent?: string };
    // hook_event_name: "PostToolUse" → Claude Code via Layer-1 fingerprint
    expect(entry.agent).toBe('Claude Code');
  });
});

/**
 * Regression: bare (label-less) credentials in PostToolUse args.
 *
 * `redactSecrets` only masks LABEL-ATTACHED secrets (`Authorization:`,
 * `token=`, `api_key=`). A credential passed as a positional CLI argument —
 * `./deploy.sh --token <jwt>` — sailed straight through it and was written to
 * ~/.node9/audit.log in the clear. log.ts now runs the DLP scanner over the
 * args and stores a hash on any hit.
 *
 * The JWT is built here at runtime, so no credential-shaped literal is ever
 * committed to this file.
 */
describe('log PostToolUse args — bare credential redaction', () => {
  let tmpHome: string;
  let tmpCwd: string;

  beforeEach(() => {
    tmpHome = makeTempHome();
    tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-log-cwd-'));
  });

  function makeJwt(): string {
    const seg = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const header = seg({ alg: 'HS256', typ: 'JWT' });
    const payload = seg({ sub: '1234567890', iat: 1516239022, role: 'deploy' });
    return `${header}.${payload}.9dQ7fbKm2LpVsXcNwRtYuIoPa1bC3dE5`;
  }

  function lastEntry(tmpHome: string): Record<string, unknown> {
    const auditLog = path.join(tmpHome, '.node9', 'audit.log');
    const lines = fs.readFileSync(auditLog, 'utf-8').trim().split('\n');
    return JSON.parse(lines[lines.length - 1]) as Record<string, unknown>;
  }

  it('hashes args instead of writing a bare JWT positional argument in the clear', () => {
    const jwt = makeJwt();
    const result = runLog(
      {
        cwd: tmpCwd,
        hook_event_name: 'PostToolUse',
        tool_name: 'Bash',
        tool_input: { command: `./deploy.sh --token ${jwt}` },
      },
      tmpHome,
      tmpCwd
    );

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);

    // The whole file, not just the parsed row — the token must not appear
    // anywhere, including in fields added later.
    const auditLog = path.join(tmpHome, '.node9', 'audit.log');
    const raw = fs.readFileSync(auditLog, 'utf-8');
    expect(raw).not.toContain(jwt);

    const entry = lastEntry(tmpHome);
    // Row is still written — audit trail must never gap.
    expect(entry.tool).toBe('Bash');
    expect(entry.decision).toBe('allowed');
    // Args are replaced by the hash + safe DLP attribution, mirroring
    // appendLocalAudit's DLP-row stance (argsHash, no plaintext preview).
    expect(entry.args).toBeUndefined();
    expect(entry.argsHash).toMatch(/^[0-9a-f]{32}$/);
    expect(entry.dlpPattern).toBe('JWT');
    expect(String(entry.dlpSample)).not.toContain(jwt);
  });

  it('keeps plaintext args for a clean command (no needless readability loss)', () => {
    const result = runLog(
      {
        cwd: tmpCwd,
        hook_event_name: 'PostToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'ls -la /tmp' },
      },
      tmpHome,
      tmpCwd
    );

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);

    const entry = lastEntry(tmpHome);
    expect((entry.args as { command?: string }).command).toBe('ls -la /tmp');
    expect(entry.argsHash).toBeUndefined();
    expect(entry.dlpPattern).toBeUndefined();
  });
});
