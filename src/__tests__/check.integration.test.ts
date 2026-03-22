/**
 * Integration tests for `node9 check` CLI command.
 *
 * These tests spawn the real built CLI subprocess (`dist/cli.js`) with an
 * isolated HOME directory so each test controls the exact config in play.
 * No mocking — the full pipeline from JSON parsing → policy evaluation →
 * authorizeHeadless → exit code runs as-is.
 *
 * Requirements:
 *   - `npm run build` must be run before these tests (the suite checks for dist/cli.js)
 *   - Tests set NODE9_NO_AUTO_DAEMON=1 to prevent daemon auto-start side effects
 *   - Tests set NODE9_TESTING=1 to disable interactive approval UI (terminal/browser/native
 *     racers return early so tests complete without waiting for human input)
 *   - Tests set HOME to a tmp directory per test group to isolate config state
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync, spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import http from 'http';

// ── Helpers ───────────────────────────────────────────────────────────────────

const CLI = path.resolve(__dirname, '../../dist/cli.js');

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Synchronous runner — safe only when no in-process mock server is involved,
 * because spawnSync blocks the event loop (preventing the mock server from
 * responding to requests from the child process).
 *
 * cwd defaults to os.tmpdir() (not the project root) so the subprocess never
 * picks up the repo's own node9.config.json and inherits only the HOME config
 * written by makeTempHome(). Pass tmpHome explicitly to keep both HOME and cwd
 * consistent.
 */
function runCheck(
  payload: object | string,
  env: Record<string, string> = {},
  cwd = os.tmpdir(),
  timeoutMs = 8000
): RunResult {
  const payloadArg = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const result = spawnSync(process.execPath, [CLI, 'check', payloadArg], {
    encoding: 'utf-8',
    timeout: timeoutMs,
    cwd, // avoid loading the repo's own node9.config.json
    env: {
      ...process.env,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      ...env,
    },
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

/**
 * Async runner using spawn — required when the test hosts a mock HTTP server
 * in the same process, since spawnSync would block the event loop and prevent
 * the server from handling requests from the child.
 *
 * Accepts either an object (serialized to JSON) or a raw string (passed as-is),
 * allowing tests to exercise the CLI's JSON-parse error path.
 */
function runCheckAsync(
  payload: object | string,
  env: Record<string, string> = {},
  cwd = os.tmpdir(),
  timeoutMs = 8000
): Promise<RunResult> {
  const payloadArg = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return new Promise((resolve) => {
    // Guard against double-resolve: child.on('close') fires even after child.kill()
    let resolved = false;
    const settle = (result: RunResult) => {
      if (!resolved) {
        resolved = true;
        resolve(result);
      }
    };

    const child = spawn(process.execPath, [CLI, 'check', payloadArg], {
      cwd,
      env: {
        ...process.env,
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_TESTING: '1',
        ...env,
      },
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));

    const timer = setTimeout(() => {
      child.kill();
      settle({ status: null, stdout, stderr });
    }, timeoutMs);

    child.on('close', (code) => {
      clearTimeout(timer);
      settle({ status: code, stdout, stderr });
    });
  });
}

/** Write a config.json into a temp HOME `.node9` directory. Returns the HOME path. */
function makeTempHome(config: object): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(path.join(node9Dir, 'config.json'), JSON.stringify(config));
  return tmpHome;
}

/** Write raw text (may be invalid JSON) directly into the config file. */
function makeTempHomeRaw(content: string): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(path.join(node9Dir, 'config.json'), content);
  return tmpHome;
}

function cleanupHome(tmpHome: string) {
  fs.rmSync(tmpHome, { recursive: true, force: true });
}

// ── Pre-flight: ensure the binary is built ────────────────────────────────────

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(
      `dist/cli.js not found. Run "npm run build" before running integration tests.\nExpected: ${CLI}`
    );
  }
});

// ── 1. Ignored tools → fast-path allow ───────────────────────────────────────

describe('ignored tools fast-path', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = makeTempHome({
      settings: { mode: 'standard', autoStartDaemon: false },
    });
  });
  afterEach(() => cleanupHome(tmpHome));

  it('glob is ignored → approved with no block output', () => {
    const r = runCheck(
      { tool_name: 'glob', tool_input: { pattern: '**/*.ts' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    // "glob" is an ignored tool — no review message, just silently allowed
    expect(r.stderr).not.toContain('blocked');
  });

  it('read is ignored → approved', () => {
    const r = runCheck(
      { tool_name: 'read', tool_input: { file_path: '/tmp/test.txt' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
  });

  it('webfetch is ignored → approved', () => {
    const r = runCheck(
      { tool_name: 'webfetch', tool_input: { url: 'https://example.com' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
  });

  it('task* wildcard — task_drop_all_tables is fast-pathed to allow', () => {
    // "task*" is in ignoredTools; a tool name that looks dangerous but matches
    // the pattern must still be silently allowed (the pattern is opt-in by the user)
    const r = runCheck(
      { tool_name: 'task_drop_all_tables', tool_input: {} },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(''); // no block JSON
    expect(r.stderr).not.toContain('blocked');
  });

  it('task* wildcard + dangerous word in input → ignoredTools wins (silently allowed)', () => {
    // Security note: ignoredTools is an explicit opt-in by the operator. When a tool
    // matches an ignoredTools pattern, it is fast-pathed BEFORE dangerousWords are
    // evaluated. This is intentional — ignoredTools means "trust this tool completely".
    // Operators should not add write-capable or destructive tools to ignoredTools unless
    // they are certain those tools are safe. The test below documents this precedence.
    const r = runCheck(
      { tool_name: 'task_execute', tool_input: { query: 'mkfs.ext4 /dev/sda' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe(''); // no block JSON — ignoredTools took precedence
    expect(r.stderr).not.toContain('blocked');
  });
});

// ── 2. Smart rules ────────────────────────────────────────────────────────────

describe('smart rules', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = makeTempHome({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
      policy: {
        smartRules: [
          {
            name: 'block-force-push',
            tool: 'bash',
            conditions: [
              { field: 'command', op: 'matches', value: 'git push.*(--force|-f\\b)', flags: 'i' },
            ],
            conditionMode: 'all',
            verdict: 'block',
            reason: 'Force push blocked by policy',
          },
          {
            name: 'allow-readonly-bash',
            tool: 'bash',
            conditions: [
              {
                field: 'command',
                op: 'matches',
                value: '^\\s*(ls|cat|grep|find|echo)',
                flags: 'i',
              },
            ],
            conditionMode: 'all',
            verdict: 'allow',
            reason: 'Read-only command',
          },
        ],
      },
    });
  });
  afterEach(() => cleanupHome(tmpHome));

  it('force push → blocked with JSON decision:block in stdout', () => {
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'git push origin main --force' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0); // CLI always exits 0; block is communicated via stdout JSON
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.decision).toBe('block');
    expect(r.stderr).toContain('blocked');
  });

  it('readonly bash → allowed with checkedBy in stderr', () => {
    // NODE9_DEBUG: '1' is required to see the "allowed" confirmation on stderr.
    // Without it the message is suppressed to avoid Claude Code treating any
    // stderr output as a hook error (GitHub issue: hook error on every tool call).
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'ls -la /tmp' } },
      { HOME: tmpHome, NODE9_DEBUG: '1' },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('allowed');
  });

  it('allowed call produces no stderr in production mode (NODE9_DEBUG unset)', () => {
    // This is the actual production behavior: Claude Code treats any stderr
    // output as a hook error regardless of exit code, so allowed calls must
    // be completely silent on stderr when NODE9_DEBUG is not set.
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'ls -la /tmp' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
  });
});

// ── 3. Dangerous words ────────────────────────────────────────────────────────

describe('dangerous words', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = makeTempHome({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 0,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
      policy: {
        dangerousWords: ['mkfs', 'shred'],
      },
    });
  });
  afterEach(() => cleanupHome(tmpHome));

  it('command with mkfs → blocked (no approval mechanism → block)', () => {
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'mkfs.ext4 /dev/sdb' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.decision).toBe('block');
    expect(r.stderr).toContain('blocked');
  });

  it('safe command without dangerous word → allowed', () => {
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'echo hello world' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    // Should either be silently allowed (empty stdout) or show "allowed"
    if (r.stdout.trim()) {
      const parsed = JSON.parse(r.stdout.trim());
      expect(parsed.decision).not.toBe('block');
    }
  });
});

// ── 4. No approval mechanism ──────────────────────────────────────────────────

describe('no approval mechanism', () => {
  let tmpHome: string;
  beforeEach(() => {
    // All approvers off, no cloud API key — any "review" verdict has nowhere to go
    tmpHome = makeTempHome({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 0,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
      policy: {
        dangerousWords: ['mkfs'],
      },
    });
  });
  afterEach(() => cleanupHome(tmpHome));

  it('risky tool with no mechanism → blocked JSON output', () => {
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'mkfs.ext4 /dev/sda' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.decision).toBe('block');
  });
});

// ── 5. Audit mode ─────────────────────────────────────────────────────────────

describe('audit mode', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = makeTempHome({
      settings: {
        mode: 'audit',
        autoStartDaemon: false,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
      policy: { dangerousWords: ['mkfs'] },
    });
  });
  afterEach(() => cleanupHome(tmpHome));

  it('risky tool in audit mode → allowed with checkedBy:audit', () => {
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'mkfs.ext4 /dev/sda' } },
      { HOME: tmpHome, NODE9_DEBUG: '1' },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('[audit]');
    expect(r.stderr).toContain('allowed');
  });

  it('non-flagged tool in audit mode → approved silently', () => {
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'ls -la' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
  });
});

// ── 6. Audit mode + cloud gating (auditLocalAllow) ────────────────────────────

describe('audit mode + cloud gating', () => {
  let tmpHome: string;
  let mockServer: http.Server;
  let auditCalls: object[];
  let serverPort: number;

  beforeEach(async () => {
    auditCalls = [];
    await new Promise<void>((resolve) => {
      mockServer = http.createServer((req, res) => {
        let body = '';
        req.on('data', (chunk) => (body += chunk));
        req.on('end', () => {
          if (req.url === '/audit' && req.method === 'POST') {
            try {
              auditCalls.push(JSON.parse(body));
            } catch {
              /* ignore */
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
          } else {
            res.writeHead(404);
            res.end();
          }
        });
      });
      mockServer.listen(0, '127.0.0.1', () => {
        serverPort = (mockServer.address() as { port: number }).port;
        resolve();
      });
    });

    tmpHome = makeTempHome({
      settings: {
        mode: 'audit',
        autoStartDaemon: false,
        approvers: { native: false, browser: false, cloud: true, terminal: false },
      },
      policy: { dangerousWords: ['mkfs'] },
    });

    // Write credentials pointing at our mock server
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'credentials.json'),
      JSON.stringify({ apiKey: 'test-key-123', apiUrl: `http://127.0.0.1:${serverPort}` })
    );
  });

  afterEach(async () => {
    cleanupHome(tmpHome);
    await new Promise<void>((resolve) => mockServer.close(() => resolve()));
  });

  it('audit mode + cloud:true + API key → POSTs to /audit endpoint', async () => {
    // auditLocalAllow is awaited in core.ts before process.exit(0), so by the
    // time runCheckAsync resolves (process closed) the POST is already complete.
    // No sleep needed — if it races here, it's a production bug too.
    const r = await runCheckAsync(
      { tool_name: 'bash', tool_input: { command: 'mkfs.ext4 /dev/sda' } },
      { HOME: tmpHome, NODE9_DEBUG: '1' },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toContain('[audit]');
    expect(auditCalls.length).toBeGreaterThan(0);
  });

  it('audit mode + cloud:false → does NOT POST to /audit', async () => {
    // Overwrite config with cloud:false
    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'audit',
          autoStartDaemon: false,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
        },
        policy: { dangerousWords: ['mkfs'] },
      })
    );

    const r = await runCheckAsync(
      { tool_name: 'bash', tool_input: { command: 'mkfs.ext4 /dev/sda' } },
      { HOME: tmpHome, NODE9_DEBUG: '1' },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toContain('[audit]');
    expect(auditCalls.length).toBe(0);
  });
});

// ── 7. Config validation — malformed JSON ─────────────────────────────────────

describe('config validation — malformed JSON', () => {
  let tmpHome: string;
  afterEach(() => cleanupHome(tmpHome));

  it('literal newline in JSON string → warning on stderr + falls back to defaults', () => {
    // Create a JSON file with a literal newline inside a string value (like the real bug)
    const badJson =
      '{"settings":{"mode":"standard"},"policy":{"smartRules":[{"name":"bad","tool":"bash","conditions":[{"field":"command","op":"matches","value":"^ls\n"}],"verdict":"allow"}]}}';
    tmpHome = makeTempHomeRaw(badJson);

    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'ls -la' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    // Should warn about parse failure
    expect(r.stderr).toMatch(/Failed to parse|Invalid config|Using default/i);
  });

  it('completely invalid JSON → warning on stderr + exits cleanly', () => {
    tmpHome = makeTempHomeRaw('not valid json at all {{{');

    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'ls -la' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toMatch(/Failed to parse|Using default/i);
  });
});

// ── 8. Config validation — Zod schema warnings ───────────────────────────────

describe('config validation — Zod schema warnings', () => {
  let tmpHome: string;
  afterEach(() => cleanupHome(tmpHome));

  it('unknown top-level key → Zod warning on stderr', () => {
    tmpHome = makeTempHome({
      settings: { mode: 'standard', autoStartDaemon: false },
      unknownKey: 'should-warn',
    });

    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'ls' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toMatch(/Invalid config|unknown/i);
  });

  it('invalid mode value → Zod warning on stderr', () => {
    tmpHome = makeTempHome({
      settings: { mode: 'bad-mode', autoStartDaemon: false },
    });

    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'ls' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toMatch(/Invalid config|mode/i);
  });

  it('invalid smart rule op → Zod warning', () => {
    tmpHome = makeTempHome({
      settings: { mode: 'standard', autoStartDaemon: false },
      policy: {
        smartRules: [
          {
            tool: 'bash',
            conditions: [{ field: 'command', op: 'invalid-op', value: 'ls' }],
            verdict: 'allow',
          },
        ],
      },
    });

    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'ls' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toMatch(/Invalid config|op/i);
  });

  it('valid config → no Zod warnings', () => {
    tmpHome = makeTempHome({
      version: '1.0',
      settings: { mode: 'standard', autoStartDaemon: false },
      policy: { dangerousWords: ['mkfs'] },
    });

    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'ls' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stderr).not.toMatch(/Invalid config|Failed to parse/i);
  });
});

// ── 9. Cloud race engine (mock SaaS) ─────────────────────────────────────────

describe('cloud race engine', () => {
  let tmpHome: string;
  let mockServer: http.Server;
  let serverPort: number;

  function startMockSaas(decision: 'allow' | 'deny'): Promise<void> {
    return new Promise((resolve) => {
      mockServer = http.createServer((req, res) => {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          if (req.url === '/' && req.method === 'POST') {
            // Initial check submission → signal pending, return a requestId for polling
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ pending: true, requestId: 'mock-request-id' }));
          } else if (req.url?.startsWith('/status/') && req.method === 'GET') {
            // Status poll → return final status in the format the poller expects
            const status = decision === 'allow' ? 'APPROVED' : 'DENIED';
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status, approvedBy: 'test@example.com' }));
          } else {
            res.writeHead(404);
            res.end();
          }
        });
      });
      mockServer.listen(0, '127.0.0.1', () => {
        serverPort = (mockServer.address() as { port: number }).port;
        resolve();
      });
    });
  }

  afterEach(async () => {
    cleanupHome(tmpHome);
    if (mockServer) await new Promise<void>((resolve) => mockServer.close(() => resolve()));
  });

  it('cloud approves → allowed with checkedBy:cloud', async () => {
    await startMockSaas('allow');

    tmpHome = makeTempHome({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvers: { native: false, browser: false, cloud: true, terminal: false },
        approvalTimeoutMs: 3000,
      },
      policy: { dangerousWords: ['mkfs'] },
    });

    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'credentials.json'),
      JSON.stringify({ apiKey: 'test-key', apiUrl: `http://127.0.0.1:${serverPort}` })
    );

    const r = await runCheckAsync(
      { tool_name: 'bash', tool_input: { command: 'mkfs.ext4 /dev/sda' } },
      { HOME: tmpHome, NODE9_DEBUG: '1' },
      tmpHome,
      10000
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).toMatch(/\[cloud\].*allowed/i);
  });

  it('cloud denies → blocked JSON output', async () => {
    await startMockSaas('deny');

    tmpHome = makeTempHome({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvers: { native: false, browser: false, cloud: true, terminal: false },
        approvalTimeoutMs: 3000,
      },
      policy: { dangerousWords: ['mkfs'] },
    });

    fs.writeFileSync(
      path.join(tmpHome, '.node9', 'credentials.json'),
      JSON.stringify({ apiKey: 'test-key', apiUrl: `http://127.0.0.1:${serverPort}` })
    );

    const r = await runCheckAsync(
      { tool_name: 'bash', tool_input: { command: 'mkfs.ext4 /dev/sda' } },
      { HOME: tmpHome },
      tmpHome,
      10000
    );
    expect(r.status).toBe(0);
    const denied = JSON.parse(r.stdout.trim());
    expect(denied.decision).toBe('block');
  });
});

// ── 10. Malformed payload to `node9 check` ───────────────────────────────────

describe('malformed JSON payload', () => {
  // The CLI argument is a trust boundary: any process can call `node9 check <arg>`.
  //
  // Design decision: malformed payloads "fail open" (exit 0, no block output).
  // Rationale: hooks run inline before every tool call; a transient JSON serialization
  // error (e.g. payload truncated mid-send) must NOT block the user's AI session.
  // The failure is logged to ~/.node9/hook-debug.log when NODE9_DEBUG=1.
  //
  // These tests verify the failure is graceful (no uncaught exception / stack trace).

  it('non-JSON string → fails open (exit 0, no crash)', () => {
    const r = runCheck('not-valid-json', {}, os.tmpdir());
    expect(r.status).toBe(0); // fail-open: allow rather than hard-block on parse error
    expect(r.stderr).not.toContain('TypeError');
    expect(r.stderr).not.toContain('at Object.<anonymous>');
  });

  it('empty string payload → fails open (exit 0, no crash)', () => {
    const r = runCheck('', {}, os.tmpdir());
    expect(r.status).toBe(0);
    expect(r.stderr).not.toContain('TypeError');
    expect(r.stderr).not.toContain('at Object.<anonymous>');
  });

  it('partial JSON object → fails open (exit 0, no crash)', () => {
    const r = runCheck('{"tool_name":"bash"', {}, os.tmpdir());
    expect(r.status).toBe(0);
    expect(r.stderr).not.toContain('TypeError');
  });
});

// ── removefrom command ────────────────────────────────────────────────────────

describe('removefrom command', () => {
  // Use a minimal env to avoid leaking CI secrets into subprocess invocations.
  // PATH is required so Node.js can resolve its own binary; everything else is
  // explicitly set to control test behaviour.
  const minimalEnv = { PATH: process.env.PATH ?? '', NODE9_TESTING: '1' };

  it('exits with code 1 and prints error for unknown target', () => {
    const result = spawnSync(process.execPath, [CLI, 'removefrom', 'vscode'], {
      encoding: 'utf-8',
      timeout: 5000,
      env: minimalEnv,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Unknown target');
    expect(result.stderr).toContain('vscode');
  });

  for (const target of ['claude', 'gemini', 'cursor'] as const) {
    it(`exits with code 0 for valid target "${target}" even when nothing to remove`, () => {
      const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-removefrom-'));
      try {
        const result = spawnSync(process.execPath, [CLI, 'removefrom', target], {
          encoding: 'utf-8',
          timeout: 5000,
          env: { ...minimalEnv, HOME: tmpHome },
        });
        expect(result.status).toBe(0);
      } finally {
        fs.rmSync(tmpHome, { recursive: true });
      }
    });
  }
});
