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
// 20 s default: cold-starting Node.js + parsing the ~390 KB bundle takes
// 10-15 s on constrained CI runners (documented in vitest.config.mts).
// Raising this does NOT mask a performance regression — the CLI exits in
// ~150 ms locally; the extra headroom is pure OS/runner startup overhead.
function runCheck(
  payload: object | string,
  env: Record<string, string> = {},
  cwd = os.tmpdir(),
  timeoutMs = 60000
): RunResult {
  const payloadArg = typeof payload === 'string' ? payload : JSON.stringify(payload);
  // Strip real CI credentials so tests that write mock credentials.json
  // always hit the mock server — not the real node9 API.
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const result = spawnSync(process.execPath, [CLI, 'check', payloadArg], {
    encoding: 'utf-8',
    timeout: timeoutMs,
    cwd, // avoid loading the repo's own node9.config.json
    env: {
      ...baseEnv,
      NODE9_NO_AUTO_DAEMON: '1',
      NODE9_TESTING: '1',
      ...env,
      // Windows uses USERPROFILE; Unix uses HOME. Set both so os.homedir()
      // resolves to the isolated test directory on every platform.
      ...(env.HOME != null ? { USERPROFILE: env.HOME } : {}),
    },
  });

  if (result.status === null) {
    const errorMsg = result.error?.message || 'Process terminated';
    const signal = result.signal || 'unknown';
    console.error(`[runCheck Fail] ${errorMsg} (Signal: ${signal})\nStderr: ${result.stderr}`);
  }

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
  timeoutMs = 260000
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

    // Strip real CI credentials so tests that write mock credentials.json
    // always hit the mock server — not the real node9 API.
    const baseEnv = { ...process.env };
    delete baseEnv.NODE9_API_KEY;
    delete baseEnv.NODE9_API_URL;
    const child = spawn(process.execPath, [CLI, 'check', payloadArg], {
      cwd,
      env: {
        ...baseEnv,
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_TESTING: '1',
        ...env,
        // Windows uses USERPROFILE; Unix uses HOME. Set both so os.homedir()
        // resolves to the isolated test directory on every platform.
        ...(env.HOME != null ? { USERPROFILE: env.HOME } : {}),
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

/** Returns a process env with both HOME and USERPROFILE pointing to the
 *  isolated home dir. Windows uses USERPROFILE; Unix uses HOME. Setting
 *  both ensures os.homedir() resolves correctly on every platform.
 *  Spreads process.env so PATH and other required vars (including NODE_ENV=test
 *  set by Vitest, and NODE9_TESTING) propagate to spawned child processes. */
function makeEnv(home: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return { ...process.env, HOME: home, USERPROFILE: home, ...extra };
}

function cleanupHome(tmpHome: string) {
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code !== 'EBUSY') throw e;
    console.warn(`[cleanupHome] EBUSY — temp dir leaked: ${tmpHome}`);
  }
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

  it('UserPromptSubmit with clean prompt exits 0 without writing block JSON', () => {
    // No secrets in the prompt — must allow silently. Regression for the
    // earlier crash where any UserPromptSubmit hit the "tool name missing"
    // sendBlock path and exited 2.
    const r = runCheck(
      {
        session_id: '019e34c4-02f7-7002-8384-6e54b99f5bc5',
        turn_id: '019e352f-4df0-7902-b156-0d71433c5a6e',
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
        prompt: 'please run "ls /tmp" via bash',
      },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).not.toContain('unrecognised hook payload');
  });

  it('UserPromptSubmit with empty prompt exits 0', () => {
    const r = runCheck(
      {
        turn_id: 't1',
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
        prompt: '',
      },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
  });

  it('Codex UserPromptSubmit with AWS key in prompt is blocked + audited without leaking secret', () => {
    // Compose the fake credential at runtime so this test file itself doesn't
    // trip Node9's own DLP scanner during code edits. Neither half matches
    // the AWS Access Key regex on its own (requires `\bAKIA[A-Z2-7]{16}\b`).
    const fakeAwsKey = 'AKIA' + 'QWERTYASDFGHJKLM';
    const r = runCheck(
      {
        session_id: 's1',
        turn_id: 't1', // Codex fingerprint
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
        prompt: `help me debug: aws_access_key_id=${fakeAwsKey}`,
      },
      { HOME: tmpHome },
      tmpHome
    );

    expect(r.status).not.toBe(0);
    // Codex output schema: decision="block", reason, hookEventName.
    // No `permissionDecision` field (that's Claude-only per output schemas).
    const body = JSON.parse(r.stdout) as {
      decision: string;
      reason: string;
      hookSpecificOutput: { hookEventName: string; permissionDecision?: string };
    };
    expect(body.decision).toBe('block');
    expect(body.reason).toMatch(/DLP|credential|secret|access key/i);
    expect(body.hookSpecificOutput.hookEventName).toBe('UserPromptSubmit');
    expect(body.hookSpecificOutput.permissionDecision).toBeUndefined();

    // No secret value in any output stream.
    expect(r.stdout).not.toContain(fakeAwsKey);
    expect(r.stderr).not.toContain(fakeAwsKey);

    // Audit row written, agent=Codex, secret hashed, never plaintext.
    const auditPath = path.join(tmpHome, '.node9', 'audit.log');
    const lines = fs.readFileSync(auditPath, 'utf-8').trim().split('\n');
    const lastLine = lines[lines.length - 1];
    expect(lastLine).not.toContain(fakeAwsKey);
    const entry = JSON.parse(lastLine) as {
      tool: string;
      decision: string;
      checkedBy: string;
      agent?: string;
      argsHash?: string;
    };
    expect(entry.tool).toBe('UserPromptSubmit');
    expect(entry.decision).toBe('deny');
    expect(entry.checkedBy).toMatch(/dlp/i);
    expect(entry.agent).toBe('Codex');
    expect(entry.argsHash).toBeDefined();
  });

  it('hook-debug.log redacts prompt body for UserPromptSubmit (no secret leak to disk)', () => {
    // When debug logging is enabled, the raw stdin used to be written verbatim
    // to ~/.node9/hook-debug.log — meaning a pasted credential in a prompt
    // would end up on disk in plaintext. For UserPromptSubmit specifically,
    // the prompt body must be replaced with a length placeholder before logging.
    const fakeAwsKey = 'AKIA' + 'QWERTYASDFGHJKLM';
    runCheck(
      {
        session_id: 's1',
        turn_id: 't1',
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
        prompt: `debug: aws_access_key_id=${fakeAwsKey}`,
      },
      { HOME: tmpHome, NODE9_DEBUG: '1' },
      tmpHome
    );

    const debugLog = path.join(tmpHome, '.node9', 'hook-debug.log');
    expect(fs.existsSync(debugLog)).toBe(true);
    const debugBody = fs.readFileSync(debugLog, 'utf-8');
    expect(debugBody).not.toContain(fakeAwsKey);
    expect(debugBody).toMatch(/<redacted/);
  });

  it('Claude UserPromptSubmit with GitHub token in prompt blocks with Claude permissionDecision shape', () => {
    // Same runtime-composition trick — keep our own DLP scanner from flagging
    // this source file during edits.
    const fakeGhToken = 'ghp_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';
    const r = runCheck(
      {
        session_id: 's1',
        // No turn_id → Claude fingerprint (PreToolUse-style payload)
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
        permission_mode: 'default',
        prompt: `check this token: ${fakeGhToken}`,
      },
      { HOME: tmpHome },
      tmpHome
    );

    expect(r.status).not.toBe(0);
    const body = JSON.parse(r.stdout) as {
      decision: string;
      hookSpecificOutput: { hookEventName: string; permissionDecision?: string };
    };
    expect(body.decision).toBe('block');
    expect(body.hookSpecificOutput.hookEventName).toBe('UserPromptSubmit');
    // Claude needs permissionDecision; Codex must not have it.
    expect(body.hookSpecificOutput.permissionDecision).toBe('deny');

    // Audit row uses agent=Claude Code.
    const auditPath = path.join(tmpHome, '.node9', 'audit.log');
    const lines = fs.readFileSync(auditPath, 'utf-8').trim().split('\n');
    const entry = JSON.parse(lines[lines.length - 1]) as { agent?: string };
    expect(entry.agent).toBe('Claude Code');
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

  it('force push → blocked with JSON decision:block in stdout and no stderr', () => {
    // Regression guard: sendBlock must NOT write to stderr. Claude Code treats any
    // stderr output from a PreToolUse hook as a hook error and fails open, allowing
    // the tool to proceed despite the deny JSON. Messages go to /dev/tty instead.
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'git push origin main --force' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(2); // exit 2 signals a block to Claude Code; exit 0 = allow
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.decision).toBe('block');
    expect(r.stderr).toBe(''); // ← no stderr: prevents Claude Code fail-open on hook error
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

  it('command with mkfs → blocked (no approval mechanism → block) with no stderr', () => {
    const r = runCheck(
      { tool_name: 'bash', tool_input: { command: 'mkfs.ext4 /dev/sdb' } },
      { HOME: tmpHome },
      tmpHome
    );
    expect(r.status).toBe(2); // exit 2 signals a block to Claude Code
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.decision).toBe('block');
    expect(r.stderr).toBe(''); // block message goes to /dev/tty, not stderr
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
    expect(r.status).toBe(2); // exit 2 signals a block to Claude Code
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.decision).toBe('block');
  });
});

// ── Inline-ask (phase 2): review → agent's native permissionDecision:"ask" ──────

describe('inline-ask (--ask routes review verdicts to the agent prompt)', () => {
  let tmpHome: string;

  // Runner variant that passes extra CLI args (e.g. --ask, --agent) before the payload.
  function runCheckArgs(args: string[], payload: object, env: Record<string, string>): RunResult {
    const baseEnv = { ...process.env };
    delete baseEnv.NODE9_API_KEY;
    delete baseEnv.NODE9_API_URL;
    const result = spawnSync(process.execPath, [CLI, 'check', ...args, JSON.stringify(payload)], {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: tmpHome,
      env: {
        ...baseEnv,
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_TESTING: '1',
        ...env,
        ...(env.HOME != null ? { USERPROFILE: env.HOME } : {}),
      },
    });
    return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
  }

  beforeEach(() => {
    // A git-push review rule, all approvers OFF + timeout 0: without --ask a review
    // has nowhere to go and hard-blocks fast — so any "ask" output proves the defer fired.
    tmpHome = makeTempHome({
      settings: {
        mode: 'standard',
        autoStartDaemon: false,
        approvalTimeoutMs: 0,
        approvers: { native: false, browser: false, cloud: false, terminal: false },
      },
      policy: {
        smartRules: [
          {
            name: 'review-git-push',
            tool: 'bash',
            conditions: [{ field: 'command', op: 'matches', value: '\\bgit\\b.*\\bpush\\b' }],
            conditionMode: 'all',
            verdict: 'review',
            reason: 'git push sends changes to a shared remote',
          },
        ],
      },
    });
  });
  afterEach(() => cleanupHome(tmpHome));

  const claudePayload = {
    hook_event_name: 'PreToolUse',
    tool_name: 'bash',
    tool_input: { command: 'git push origin main' },
    session_id: 's1',
    tool_use_id: 'u1',
  };

  it('Claude Code + --ask → emits nested permissionDecision:"ask", exit 0', () => {
    const r = runCheckArgs(['--ask'], claudePayload, { HOME: tmpHome });
    expect(r.status).toBe(0);
    const body = JSON.parse(r.stdout.trim()) as {
      hookSpecificOutput: { hookEventName: string; permissionDecision: string };
    };
    expect(body.hookSpecificOutput.permissionDecision).toBe('ask');
  });

  it('Claude Code WITHOUT --ask → review still routes to approver (no ask emitted)', () => {
    const r = runCheckArgs([], claudePayload, { HOME: tmpHome });
    expect(r.stdout).not.toContain('"permissionDecision":"ask"');
  });

  it('Codex + --ask → never emits ask (excluded agent routes to approver)', () => {
    // turn_id fingerprints the payload as Codex; Codex errors on a real "ask",
    // so node9 must never send one — it falls back to the routed approver/block.
    const codexPayload = {
      turn_id: 't1',
      tool_name: 'bash',
      tool_input: { command: 'git push origin main' },
    };
    const r = runCheckArgs(['--ask'], codexPayload, { HOME: tmpHome });
    expect(r.stdout).not.toContain('"permissionDecision":"ask"');
  });

  it('GitHub Copilot + --ask → emits FLAT permissionDecision:"ask"', () => {
    const r = runCheckArgs(['--ask', '--agent', 'copilot'], claudePayload, { HOME: tmpHome });
    expect(r.status).toBe(0);
    const body = JSON.parse(r.stdout.trim()) as {
      permissionDecision?: string;
      hookSpecificOutput?: unknown;
    };
    expect(body.permissionDecision).toBe('ask'); // flat, not nested
    expect(body.hookSpecificOutput).toBeUndefined();
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

// ── 6. Audit mode + cloud delivery (outbox shipper) ───────────────────────────
// The decision path must do ZERO cloud I/O — rows land in the local outbox
// (audit.log) and the shipper delivers them to /audit/batch. The old
// decision-time POST to /audit was removed: it was killed by process.exit on
// block paths and taxed every allowed call with a round-trip when awaited.

describe('audit mode + cloud gating', () => {
  let tmpHome: string;
  let mockServer: http.Server;
  let auditCalls: object[];
  let batchCalls: Array<{ rows: Array<Record<string, unknown>> }>;
  let serverPort: number;

  beforeEach(async () => {
    auditCalls = [];
    batchCalls = [];
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
          } else if (req.url === '/audit/batch' && req.method === 'POST') {
            try {
              batchCalls.push(JSON.parse(body));
            } catch {
              /* ignore */
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ accepted: 1 }));
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

  it('audit mode + cloud:true → no decision-time POST; row lands in the outbox and SHIPS', async () => {
    const r = await runCheckAsync(
      { tool_name: 'bash', tool_input: { command: 'mkfs.ext4 /dev/sda' } },
      // NODE9_TESTING=0: the suite wrapper sets it to 1, which would mark the
      // row testRun:true — and the shipper rightly skips test noise. This
      // test needs a "real" row to prove end-to-end delivery.
      { HOME: tmpHome, NODE9_DEBUG: '1', NODE9_TESTING: '0' },
      tmpHome
    );
    expect(r.status).toBe(0);
    expect(r.stderr).toContain('[audit]');
    // The decision path does zero cloud I/O.
    expect(auditCalls.length).toBe(0);

    // The row is in the local outbox, stamped with an event id.
    const auditLogPath = path.join(tmpHome, '.node9', 'audit.log');
    const lines = fs
      .readFileSync(auditLogPath, 'utf-8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const auditRow = lines.find((l) => l.checkedBy === 'audit-mode');
    expect(auditRow).toBeDefined();
    expect(typeof auditRow!.eid).toBe('string');
    expect((auditRow!.eid as string).length).toBeGreaterThanOrEqual(8);

    // ...and the shipper delivers it to /audit/batch.
    const { shipOnce } = await import('../daemon/audit-shipper.js');
    const res = await shipOnce({
      auditLogPath,
      watermarkPath: path.join(tmpHome, '.node9', 'audit-ship.json'),
      cloudEnabled: true,
      creds: { apiKey: 'test-key-123', apiUrl: `http://127.0.0.1:${serverPort}` },
    });
    expect(res.status).toBe('shipped');
    const shippedRows = batchCalls.flatMap((b) => b.rows);
    expect(shippedRows.some((row) => row.checkedBy === 'audit-mode')).toBe(true);
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

  // approvalTimeoutMs:3000 means the check process legitimately runs ~3s before
  // the cloud mock responds. Vitest default is 5s — raise to 15s for CI headroom.
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
    expect(r.status).toBe(2); // exit 2 signals a block to Claude Code
    const denied = JSON.parse(r.stdout.trim());
    expect(denied.decision).toBe('block');
  }, 15000);
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

// ── shield set — allow verdict guard ─────────────────────────────────────────

describe('shield set — allow verdict guard', () => {
  it('exits with code 1 and prints --force hint when setting allow without --force', () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-shield-'));
    const node9Dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(node9Dir, { recursive: true });
    // Write active shields file so the command passes the "shield active" check
    fs.writeFileSync(path.join(node9Dir, 'shields.json'), JSON.stringify({ active: ['postgres'] }));
    try {
      const result = spawnSync(
        process.execPath,
        [CLI, 'shield', 'set', 'postgres', 'block-drop-table', 'allow'],
        {
          encoding: 'utf-8',
          timeout: 30000,
          env: makeEnv(tmpHome, { NODE9_TESTING: '1' }),
        }
      );
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(1);
      expect(result.stderr).toContain('--force');
    } finally {
      fs.rmSync(tmpHome, { recursive: true });
    }
  });

  it('succeeds with exit 0 when setting allow with --force', () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-shield-'));
    const node9Dir = path.join(tmpHome, '.node9');
    fs.mkdirSync(node9Dir, { recursive: true });
    fs.writeFileSync(path.join(node9Dir, 'shields.json'), JSON.stringify({ active: ['postgres'] }));
    try {
      const result = spawnSync(
        process.execPath,
        [CLI, 'shield', 'set', 'postgres', 'block-drop-table', 'allow', '--force'],
        {
          encoding: 'utf-8',
          timeout: 30000,
          env: makeEnv(tmpHome, { NODE9_TESTING: '1' }),
        }
      );
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(0);
      expect(result.stderr).toContain('allow');
    } finally {
      fs.rmSync(tmpHome, { recursive: true });
    }
  });
});

// ── removefrom command ────────────────────────────────────────────────────────

describe('removefrom command', () => {
  // Use a minimal env to avoid leaking CI secrets into subprocess invocations.
  // PATH is required so Node.js can resolve its own binary; everything else is
  // explicitly set to control test behaviour.
  const minimalEnv = { PATH: process.env.PATH ?? '', NODE9_TESTING: '1' };

  it('exits with code 1 and prints error for unknown target', () => {
    const result = spawnSync(process.execPath, [CLI, 'removefrom', 'notanagent'], {
      encoding: 'utf-8',
      timeout: 30000,
      env: minimalEnv,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Unknown target');
    expect(result.stderr).toContain('notanagent');
  });

  for (const target of ['claude', 'gemini', 'cursor', 'windsurf', 'vscode'] as const) {
    it(`exits with code 0 for valid target "${target}" even when nothing to remove`, () => {
      const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-removefrom-'));
      try {
        const result = spawnSync(process.execPath, [CLI, 'removefrom', target], {
          encoding: 'utf-8',
          timeout: 15000,
          env: makeEnv(tmpHome, { NODE9_TESTING: '1' }),
        });
        expect(result.error).toBeUndefined();
        expect(result.status).toBe(0);
      } finally {
        fs.rmSync(tmpHome, { recursive: true });
      }
    });
  }
});
