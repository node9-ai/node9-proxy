/**
 * Integration tests for the GitHub Copilot CLI hook dialect.
 *
 * Spawns the real built CLI (`dist/cli.js`) with an isolated HOME, feeding
 * it PreToolUse payloads captured from Copilot CLI 1.0.60 via spy hook
 * (doc/roadmap/copilot-target.md §0.3). Copilot's PascalCase payload is
 * byte-identical to Claude Code's, so the only behavior that differs is
 * the deny response shape:
 *
 *   Copilot honours a FLAT `{permissionDecision:"deny",
 *   permissionDecisionReason}` (NOT Claude's nested hookSpecificOutput).
 *   Verified live: this shape with exit 0 blocks and surfaces the reason
 *   to the model. The `--agent copilot` flag selects it — without the
 *   flag the identical-to-Claude payload is (acceptably) attributed to
 *   Claude Code and gets the Claude block shape.
 *
 * Same harness rules as check.integration.test.ts: requires `npm run
 * build`, NODE9_NO_AUTO_DAEMON=1, NODE9_TESTING=1, per-test temp HOME.
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

/** Real PreToolUse payload captured from Copilot CLI 1.0.60 (PascalCase). */
function copilotPrePayload(command: string): object {
  return {
    hook_event_name: 'PreToolUse',
    session_id: '40a3be24-85b8-4b5a-ac50-9f71d7e1ec5a',
    timestamp: '2026-06-06T19:13:03.207Z',
    cwd: '/tmp/copilot-test',
    tool_name: 'bash',
    tool_input: { command, description: 'test command' },
  };
}

function run(
  subcommand: 'check' | 'log',
  extraArgs: string[],
  payload: object,
  home: string
): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  // A real CLAUDECODE in the test runner's env would override fingerprinting.
  delete baseEnv.CLAUDECODE;
  delete baseEnv.CLAUDE_CODE_SESSION_ID;
  const result = spawnSync(
    process.execPath,
    [CLI, subcommand, ...extraArgs, JSON.stringify(payload)],
    {
      encoding: 'utf-8',
      timeout: 60000,
      cwd: home,
      env: {
        ...baseEnv,
        NODE9_NO_AUTO_DAEMON: '1',
        NODE9_TESTING: '1',
        HOME: home,
        USERPROFILE: home,
      },
    }
  );
  expect(result.error).toBeUndefined();
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function makeTempHome(config: object): string {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-copilot-test-'));
  const node9Dir = path.join(tmpHome, '.node9');
  fs.mkdirSync(node9Dir, { recursive: true });
  fs.writeFileSync(path.join(node9Dir, 'config.json'), JSON.stringify(config));
  return tmpHome;
}

function cleanupHome(tmpHome: string) {
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code !== 'EBUSY') throw e;
    console.warn(`[cleanupHome] EBUSY — temp dir leaked: ${tmpHome}`);
  }
}

const BLOCK_FORCE_PUSH_CONFIG = {
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
    ],
  },
};

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found. Run "npm run build" first.\nExpected: ${CLI}`);
  }
});

describe('copilot check — deny response shape', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = makeTempHome(BLOCK_FORCE_PUSH_CONFIG);
  });
  afterEach(() => cleanupHome(tmpHome));

  it('--agent copilot → flat {permissionDecision:"deny"} on stdout, exit 0', () => {
    // The flat shape (no nested hookSpecificOutput) is what Copilot CLI
    // honours; verified live to block and surface the reason.
    const r = run(
      'check',
      ['--agent', 'copilot'],
      copilotPrePayload('git push origin main --force'),
      tmpHome
    );
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.permissionDecision).toBe('deny');
    expect(parsed.permissionDecisionReason).toContain('Smart Rule: block-force-push');
    // No Claude nesting in the Copilot shape.
    expect(parsed.hookSpecificOutput).toBeUndefined();
    expect(parsed.decision).toBeUndefined();
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
  });

  it('allowed bash command with --agent copilot → exit 0, no stdout', () => {
    const r = run('check', ['--agent', 'copilot'], copilotPrePayload('ls -la'), tmpHome);
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe('');
  });

  it('without the flag, the Claude-identical payload falls back to the Claude block shape', () => {
    // Documents the accepted fallback: Copilot's PascalCase payload is
    // indistinguishable from Claude Code, so a hand-written hook missing
    // --agent copilot gets attributed to Claude and the Claude shape.
    // Still blocks — only the SaaS label and response envelope differ.
    const r = run('check', [], copilotPrePayload('git push origin main --force'), tmpHome);
    const parsed = JSON.parse(r.stdout.trim());
    expect(parsed.decision).toBe('block');
    expect(parsed.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(r.status).toBe(2);
  });
});

describe('copilot log — audit attribution', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = makeTempHome({ settings: { mode: 'standard', autoStartDaemon: false } });
  });
  afterEach(() => cleanupHome(tmpHome));

  it('--agent copilot tags the audit row as GitHub Copilot', () => {
    const post = {
      ...(copilotPrePayload('echo hi') as Record<string, unknown>),
      hook_event_name: 'PostToolUse',
      tool_result: { result_type: 'success', text_result_for_llm: 'hi' },
    };
    const r = run('log', ['--agent', 'copilot'], post, tmpHome);
    expect(r.status).toBe(0);

    const auditPath = path.join(tmpHome, '.node9', 'audit.log');
    const entry = JSON.parse(fs.readFileSync(auditPath, 'utf-8').trim());
    expect(entry.agent).toBe('GitHub Copilot');
    expect(entry.tool).toBe('bash');
    // bash args are already canonical — no remapping, command preserved.
    expect(entry.args.command).toBe('echo hi');
    expect(entry.sessionId).toBe('40a3be24-85b8-4b5a-ac50-9f71d7e1ec5a');
  });
});
