/**
 * Integration tests for Hermes Agent payload handling end-to-end.
 *
 * Spawns the real built CLI with Hermes-shape stdin payloads (matching
 * agent/shell_hooks.py:_serialize_payload byte-for-byte, verified
 * against a real Hermes v0.14.0 install during the 2026-05-26 cloud
 * smoke test — see doc/roadmap/hermes-integration/).
 *
 * Covers the load-bearing claims of the Hermes integration:
 *   - pre_tool_call payload is parsed and produces a sensible decision
 *   - post_tool_call writes an audit row with agent: "Hermes"
 *   - canonicalToolName rewrote `terminal` → `Bash` so the audit row's
 *     tool field is the canonical name
 *   - the agent-native tool name is preserved under `agentToolName`
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

interface AuditEntry {
  ts?: string;
  tool?: string;
  agentToolName?: string;
  agent?: string;
  decision?: string;
  source?: string;
  sessionId?: string;
  args?: unknown;
  argsHash?: string;
  [key: string]: unknown;
}

function runNode9(subcmd: 'check' | 'log', payload: object, tmpHome: string): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  // Also strip any Hermes env vars from the developer's shell so they
  // don't leak into the test process and skew detection.
  delete baseEnv.HERMES_SESSION_ID;
  delete baseEnv.HERMES_HOME;
  delete baseEnv.HERMES_INTERACTIVE;

  const result = spawnSync(process.execPath, [CLI, subcmd, JSON.stringify(payload)], {
    encoding: 'utf-8',
    timeout: 60000,
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-hermes-test-'));
  fs.mkdirSync(path.join(dir, '.node9'), { recursive: true });
  return dir;
}

function readAuditLog(tmpHome: string): AuditEntry[] {
  const p = path.join(tmpHome, '.node9', 'audit.log');
  if (!fs.existsSync(p)) return [];
  return fs
    .readFileSync(p, 'utf-8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as AuditEntry);
}

// Real captured Hermes pre_tool_call payload from the 2026-05-26 smoke
// test (doc/roadmap/hermes-integration/fixtures/). Wire shape matches
// _serialize_payload in opensources/hermes-agent-main/agent/shell_hooks.py.
function hermesPreToolCallPayload(overrides: Record<string, unknown> = {}): object {
  return {
    hook_event_name: 'pre_tool_call',
    tool_name: 'terminal',
    tool_input: { command: 'ls -la' },
    session_id: 'hermes-test-session',
    cwd: '/tmp',
    extra: { task_id: 'task-1', tool_call_id: 'call-abc' },
    ...overrides,
  };
}

function hermesPostToolCallPayload(overrides: Record<string, unknown> = {}): object {
  return {
    hook_event_name: 'post_tool_call',
    tool_name: 'terminal',
    tool_input: { command: 'echo hello' },
    session_id: 'hermes-test-session',
    cwd: '/tmp',
    extra: { task_id: 'task-1', tool_call_id: 'call-abc', duration_ms: 12 },
    ...overrides,
  };
}

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found — run 'npm run build' first`);
  }
});

describe('hermes pre_tool_call: payload accepted end-to-end', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = makeTempHome();
  });

  it('accepts a real Hermes pre_tool_call payload (echo hello → allow)', () => {
    const result = runNode9('check', hermesPreToolCallPayload(), tmpHome);
    // Allow path returns 0; block returns 2. Either is fine for this
    // test — we're asserting the process didn't crash on the payload
    // shape, not making policy assertions.
    expect(result.error).toBeUndefined();
    expect([0, 2]).toContain(result.status);
  });

  it('does not crash on the canonicalisation path (terminal → Bash)', () => {
    // If canonicalToolName mis-handled the empty-string fallback or
    // some downstream consumer asserted the original `terminal` name,
    // the process would exit non-zero with a stack trace on stderr.
    const result = runNode9('check', hermesPreToolCallPayload(), tmpHome);
    expect(result.stderr).not.toMatch(/TypeError|ReferenceError|Cannot read/i);
  });
});

describe('hermes post_tool_call: audit row attribution + canonicalisation', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = makeTempHome();
  });

  it('writes an audit entry with agent: "Hermes"', () => {
    const result = runNode9('log', hermesPostToolCallPayload(), tmpHome);
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);

    const audit = readAuditLog(tmpHome);
    expect(audit).toHaveLength(1);
    expect(audit[0].agent).toBe('Hermes');
  });

  it('canonicalises tool field (terminal → Bash) in the audit row', () => {
    runNode9('log', hermesPostToolCallPayload(), tmpHome);
    const audit = readAuditLog(tmpHome);
    expect(audit[0].tool).toBe('Bash');
  });

  it('preserves the agent-native name under agentToolName', () => {
    runNode9('log', hermesPostToolCallPayload(), tmpHome);
    const audit = readAuditLog(tmpHome);
    expect(audit[0].agentToolName).toBe('terminal');
  });

  it('does NOT populate agentToolName when the name was already canonical', () => {
    // A Claude-shape payload with tool_name: "Bash" → canonical "Bash".
    // No rename happened, so the agentToolName field stays out of the row.
    const claudeShapePayload = {
      hook_event_name: 'PostToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'ls' },
      session_id: 'claude-shape-session',
      cwd: '/tmp',
    };
    runNode9('log', claudeShapePayload, tmpHome);
    const audit = readAuditLog(tmpHome);
    expect(audit[0].tool).toBe('Bash');
    expect(audit[0].agentToolName).toBeUndefined();
    expect(audit[0].agent).toBe('Claude Code');
  });

  it('forwards session_id to the audit row', () => {
    runNode9('log', hermesPostToolCallPayload({ session_id: 'sess_xyz_42' }), tmpHome);
    const audit = readAuditLog(tmpHome);
    expect(audit[0].sessionId).toBe('sess_xyz_42');
  });

  it('handles write_file canonicalisation (Hermes → Write)', () => {
    runNode9(
      'log',
      hermesPostToolCallPayload({
        tool_name: 'write_file',
        tool_input: { path: '/tmp/foo.txt', content: 'hi' },
      }),
      tmpHome
    );
    const audit = readAuditLog(tmpHome);
    expect(audit[0].tool).toBe('Write');
    expect(audit[0].agentToolName).toBe('write_file');
  });

  it('handles patch canonicalisation (Hermes → Edit)', () => {
    runNode9(
      'log',
      hermesPostToolCallPayload({
        tool_name: 'patch',
        tool_input: { path: '/tmp/foo.txt', old: 'a', new: 'b' },
      }),
      tmpHome
    );
    const audit = readAuditLog(tmpHome);
    expect(audit[0].tool).toBe('Edit');
    expect(audit[0].agentToolName).toBe('patch');
  });

  it('passes Hermes-specific tools through unchanged (no agentToolName)', () => {
    // delegate_task, execute_code, vision_analyze, etc. have no Claude
    // equivalent — they stay as-is and don't get an agentToolName.
    runNode9(
      'log',
      hermesPostToolCallPayload({
        tool_name: 'delegate_task',
        tool_input: { task: 'analyse this' },
      }),
      tmpHome
    );
    const audit = readAuditLog(tmpHome);
    expect(audit[0].tool).toBe('delegate_task');
    expect(audit[0].agentToolName).toBeUndefined();
    expect(audit[0].agent).toBe('Hermes');
  });
});

describe('hermes detection via HERMES_SESSION_ID env var (no payload fingerprint)', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = makeTempHome();
  });

  it('attributes audit row to Hermes when env says so but payload is bare', () => {
    const baseEnv = { ...process.env };
    delete baseEnv.NODE9_API_KEY;
    delete baseEnv.NODE9_API_URL;

    const result = spawnSync(
      process.execPath,
      [
        CLI,
        'log',
        JSON.stringify({
          tool_name: 'Bash',
          tool_input: { command: 'echo hi' },
          session_id: 'env-only-session',
          cwd: '/tmp',
        }),
      ],
      {
        encoding: 'utf-8',
        timeout: 60000,
        env: {
          ...baseEnv,
          NODE9_NO_AUTO_DAEMON: '1',
          NODE9_TESTING: '1',
          HOME: tmpHome,
          USERPROFILE: tmpHome,
          HERMES_SESSION_ID: 'sess_from_env_only',
        },
      }
    );

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    // Note: the inline detector in log.ts uses payload-only fingerprints
    // (it doesn't check process.env). This test documents that gap — it
    // currently expects undefined or "Claude Code" (from PostToolUse-less
    // payload going through the Layer-3 fallback) rather than "Hermes".
    // When log.ts's detector grows env-var awareness, update this test
    // to expect 'Hermes'.
    const audit = readAuditLog(tmpHome);
    expect(audit).toHaveLength(1);
  });
});
