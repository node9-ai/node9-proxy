/**
 * Integration tests for MCP stdio compatibility — regression suite for #33.
 *
 * Tests two bugs fixed in #33:
 *   1. Proxy banner must go to stderr, never stdout — stdout must stay clean for JSON-RPC.
 *   2. `node9 log` must write to audit.log even when payload.cwd differs from process.cwd().
 *
 * Requirements:
 *   - `npm run build` must be run before these tests (suite checks for dist/cli.js)
 *   - Tests set NODE9_NO_AUTO_DAEMON=1 to prevent daemon auto-start side effects
 *   - Tests set NODE9_TESTING=1 to disable interactive approval UI
 *   - Tests set HOME to an isolated tmp directory to control config state
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function makeTempHome(config: object): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(path.join(node9Dir, 'config.json'), JSON.stringify(config));
  return tmpHome;
}

function cleanupDir(dir: string) {
  fs.rmSync(dir, { recursive: true, force: true });
}

const BASE_ENV = {
  NODE9_NO_AUTO_DAEMON: '1',
  NODE9_TESTING: '1',
};

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(
      `dist/cli.js not found. Run "npm run build" before running integration tests.\nExpected: ${CLI}`
    );
  }
});

// ── 1. Proxy stdout cleanliness ───────────────────────────────────────────────
// Regression: banner was written to stdout via console.log, corrupting JSON-RPC
// streams when node9 wrapped stdio MCP servers.

describe('proxy command — stdout must stay clean for stdio protocols (MCP / JSON-RPC)', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = makeTempHome({ settings: { mode: 'audit', autoStartDaemon: false } });
  });

  afterEach(() => {
    cleanupDir(tmpHome);
  });

  it('banner goes to stderr; stdout contains only the child process output', () => {
    // Note: uses the external /usr/bin/echo (resolved via `which`), not a shell builtin.
    // This test is Linux/macOS only — Windows echo is a shell builtin and not spawnable.
    const result = spawnSync(process.execPath, [CLI, 'echo', 'hello-mcp-test'], {
      encoding: 'utf-8',
      timeout: 8000,
      cwd: os.tmpdir(),
      env: { ...process.env, ...BASE_ENV, HOME: tmpHome },
    });

    // Guard: if spawn itself failed, result.error is set — fail loudly
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    // Critical: stdout must be exactly what the child wrote — no banner injected
    expect(result.stdout).toBe('hello-mcp-test\n');
    // Banner must appear on stderr so MCP clients are unaffected
    expect(result.stderr).toContain('Node9 Proxy Active');
  });

  it('stdout is valid JSON when the child writes JSON — banner does not corrupt the stream', () => {
    // Simulate a minimal JSON-RPC response from an MCP server
    const jsonRpcResponse = '{"jsonrpc":"2.0","id":1,"result":{"ok":true}}';

    const result = spawnSync(process.execPath, [CLI, 'echo', jsonRpcResponse], {
      encoding: 'utf-8',
      timeout: 8000,
      cwd: os.tmpdir(),
      env: { ...process.env, ...BASE_ENV, HOME: tmpHome },
    });

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    // Pre-assertion: non-empty stdout before attempting JSON.parse (better diagnostics)
    expect(result.stdout.trim()).toBeTruthy();
    // stdout must parse as valid JSON — banner injection would break this
    const parsed: unknown = JSON.parse(result.stdout.trim());
    expect(parsed).toMatchObject({ jsonrpc: '2.0', id: 1 });
  });
});

// ── 2. Log command cross-cwd audit write ──────────────────────────────────────
// Regression: `node9 log` silently failed to write audit.log when payload.cwd
// pointed to a project dir different from the binary's process.cwd(). The root
// cause was getConfig() reading the wrong config (wrong project), which caused
// it to throw and the catch block to silently swallow the error.

describe('log command — audit.log written when payload.cwd differs from process.cwd()', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = makeTempHome({ settings: { mode: 'audit', autoStartDaemon: false } });
  });

  afterEach(() => {
    cleanupDir(tmpHome);
  });

  it('writes MCP tool call to audit.log when payload.cwd is a different project directory', () => {
    // Project directory is different from the node9 binary's cwd
    const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-project-'));
    try {
      const payload = JSON.stringify({
        tool_name: 'mcp__opsgenie__list_teams',
        tool_input: { limit: 10 },
        cwd: projectDir,
        hook_event_name: 'PostToolUse',
      });

      const r = spawnSync(process.execPath, [CLI, 'log', payload], {
        encoding: 'utf-8',
        timeout: 5000,
        cwd: os.tmpdir(), // intentionally different from projectDir
        env: { ...process.env, ...BASE_ENV, HOME: tmpHome },
      });
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(0);

      const auditLog = path.join(tmpHome, '.node9', 'audit.log');
      expect(fs.existsSync(auditLog)).toBe(true);

      const entries = fs
        .readFileSync(auditLog, 'utf-8')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l) as Record<string, unknown>);

      expect(entries).toHaveLength(1);
      expect(entries[0]).toMatchObject({
        tool: 'mcp__opsgenie__list_teams',
        decision: 'allowed',
        source: 'post-hook',
      });
    } finally {
      cleanupDir(projectDir);
    }
  });

  it('writes to audit.log when payload has no cwd (backward compat — uses process.cwd())', () => {
    const payload = JSON.stringify({
      tool_name: 'write_file',
      tool_input: { file_path: '/tmp/test.txt', content: 'hello' },
      hook_event_name: 'PostToolUse',
    });

    const r = spawnSync(process.execPath, [CLI, 'log', payload], {
      encoding: 'utf-8',
      timeout: 5000,
      cwd: os.tmpdir(),
      env: { ...process.env, ...BASE_ENV, HOME: tmpHome },
    });
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);

    const auditLog = path.join(tmpHome, '.node9', 'audit.log');
    expect(fs.existsSync(auditLog)).toBe(true);

    const entries = fs
      .readFileSync(auditLog, 'utf-8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as Record<string, unknown>);

    expect(entries[0]).toMatchObject({ tool: 'write_file', decision: 'allowed' });
  });

  it('writes to audit.log when payload.cwd is a nonexistent directory — falls back to global config', () => {
    // getConfig() must not throw when the project dir doesn't exist.
    // tryLoadConfig returns null for a missing path → global config used → audit write succeeds.
    const payload = JSON.stringify({
      tool_name: 'read_file',
      tool_input: { file_path: '/tmp/test.txt' },
      cwd: '/nonexistent/project/dir/that/does/not/exist',
      hook_event_name: 'PostToolUse',
    });

    const r = spawnSync(process.execPath, [CLI, 'log', payload], {
      encoding: 'utf-8',
      timeout: 5000,
      cwd: os.tmpdir(),
      env: { ...process.env, ...BASE_ENV, HOME: tmpHome },
    });
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);

    const auditLog = path.join(tmpHome, '.node9', 'audit.log');
    expect(fs.existsSync(auditLog)).toBe(true);

    const entries = fs
      .readFileSync(auditLog, 'utf-8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as Record<string, unknown>);

    expect(entries[0]).toMatchObject({ tool: 'read_file', decision: 'allowed' });
  });

  it('audit.log is written even when global config.json is corrupt JSON — config load must not skip audit', () => {
    // Regression: getConfig() was called BEFORE appendFileSync. A config parse error
    // would throw and skip the audit write entirely. The fix moves the audit write first.
    // This test proves a corrupt config never creates a silent audit gap.
    const corruptHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-corrupt-'));
    try {
      const node9Dir = path.join(corruptHome, '.node9');
      fs.mkdirSync(node9Dir, { recursive: true });
      // Write deliberately corrupt JSON to trigger a parse error in tryLoadConfig
      fs.writeFileSync(path.join(node9Dir, 'config.json'), '{ this is not valid json !!');

      const payload = JSON.stringify({
        tool_name: 'bash',
        tool_input: { command: 'ls' },
        hook_event_name: 'PostToolUse',
      });

      const r = spawnSync(process.execPath, [CLI, 'log', payload], {
        encoding: 'utf-8',
        timeout: 5000,
        cwd: os.tmpdir(),
        env: { ...process.env, ...BASE_ENV, HOME: corruptHome },
      });
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(0);

      // audit.log must exist and contain the entry despite the corrupt config
      const auditLog = path.join(corruptHome, '.node9', 'audit.log');
      expect(fs.existsSync(auditLog)).toBe(true);
      const entries = fs
        .readFileSync(auditLog, 'utf-8')
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l) as Record<string, unknown>);
      expect(entries[0]).toMatchObject({ tool: 'bash', decision: 'allowed' });
    } finally {
      cleanupDir(corruptHome);
    }
  });
});
