/**
 * Integration tests: the block output Codex CLI enforces (node9Firewall#473).
 *
 * Codex reads a hook's exit code 2 as a block only when stderr carries the
 * reason; stdout is ignored on exit 2. With an empty stderr Codex marks the
 * hook failed and runs the tool (fail-open). Source: openai/codex rust-v0.154.0,
 * codex-rs/hooks/src/events/pre_tool_use.rs and user_prompt_submit.rs
 * (parse_completed). Same rule since at least rust-v0.120.0.
 *
 * Spawns the real built CLI (`dist/cli.js`); run `npm run build` first.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

interface RunResult {
  error: Error | undefined;
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCheck(payload: object, home: string, args: string[] = []): RunResult {
  const baseEnv = { ...process.env };
  delete baseEnv.NODE9_API_KEY;
  delete baseEnv.NODE9_API_URL;
  const r = spawnSync(process.execPath, [CLI, 'check', ...args, JSON.stringify(payload)], {
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
  });
  return { error: r.error, status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

// Known top-level and hookSpecificOutput keys of Codex's PreToolUse output
// (pre-tool-use.command.output schema, deny_unknown_fields on both levels).
const CODEX_PRE_TOOL_USE_KEYS = new Set([
  'continue',
  'decision',
  'hookSpecificOutput',
  'reason',
  'stopReason',
  'suppressOutput',
  'systemMessage',
]);
const CODEX_PRE_TOOL_USE_HSO_KEYS = new Set([
  'additionalContext',
  'hookEventName',
  'permissionDecision',
  'permissionDecisionReason',
  'updatedInput',
]);

/**
 * Codex 0.154's reading of a PreToolUse hook run, reduced to the block
 * decision: the reason Codex treats as a block, or null when Codex would let
 * the tool run (allow, or a hook run it marks failed).
 */
function codexPreToolUseBlockReason(r: RunResult): string | null {
  if (r.status === 2) return r.stderr.trim() || null;
  if (r.status !== 0 || !r.stdout.trim()) return null;
  let out: Record<string, unknown>;
  try {
    out = JSON.parse(r.stdout) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (Object.keys(out).some((k) => !CODEX_PRE_TOOL_USE_KEYS.has(k))) return null;
  const hso = out.hookSpecificOutput as Record<string, unknown> | undefined;
  if (hso && Object.keys(hso).some((k) => !CODEX_PRE_TOOL_USE_HSO_KEYS.has(k))) return null;
  if (hso && (hso.permissionDecision !== undefined || hso.permissionDecisionReason !== undefined)) {
    const reason =
      typeof hso.permissionDecisionReason === 'string' ? hso.permissionDecisionReason : '';
    return hso.permissionDecision === 'deny' && reason.trim() ? reason.trim() : null;
  }
  const reason = typeof out.reason === 'string' ? out.reason : '';
  return out.decision === 'block' && reason.trim() ? reason.trim() : null;
}

/** Codex 0.154's reading of a UserPromptSubmit hook run: the stop reason, or null. */
function codexPromptBlockReason(r: RunResult): string | null {
  if (r.status === 2) return r.stderr.trim() || null;
  if (r.status !== 0 || !r.stdout.trim()) return null;
  try {
    const out = JSON.parse(r.stdout) as { decision?: unknown; reason?: unknown };
    return out.decision === 'block' && typeof out.reason === 'string' && out.reason.trim()
      ? out.reason.trim()
      : null;
  } catch {
    return null;
  }
}

// A Codex 0.154 PreToolUse payload: every required field of
// pre-tool-use.command.input, turn_id included (node9's Codex fingerprint).
const codexPreToolUse = (command: string) => ({
  session_id: '019e34c4-02f7-7002-8384-6e54b99f5bc5',
  turn_id: '019e352f-4df0-7902-b156-0d71433c5a6e',
  transcript_path: null,
  cwd: os.tmpdir(),
  hook_event_name: 'PreToolUse',
  model: 'gpt-6-astra',
  permission_mode: 'default',
  tool_name: 'Bash',
  tool_input: { command },
  tool_use_id: 'call_codex_1',
});

// The same call as Claude Code sends it (no turn_id, no model).
const claudePreToolUse = (command: string) => ({
  session_id: 'claude-session-1',
  transcript_path: '/tmp/transcript.jsonl',
  cwd: os.tmpdir(),
  hook_event_name: 'PreToolUse',
  permission_mode: 'default',
  tool_name: 'Bash',
  tool_input: { command },
  tool_use_id: 'toolu_claude_1',
});

// eslint-disable-next-line no-control-regex -- matches an ANSI color escape
const ANSI = /\u001b\[/;
const BLOCKED_COMMAND = 'git push origin main --force';

beforeAll(() => {
  if (!fs.existsSync(CLI)) {
    throw new Error(`dist/cli.js not found. Run "npm run build" first. Expected: ${CLI}`);
  }
});

describe('Codex block output (node9Firewall#473)', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'node9-codex-block-'));
    fs.mkdirSync(path.join(home, '.node9'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({
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
              conditions: [{ field: 'command', op: 'matches', value: 'git push.*--force' }],
              conditionMode: 'all',
              verdict: 'block',
              reason: 'Force push blocked by policy',
            },
          ],
        },
      })
    );
  });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  it('Codex PreToolUse block: exit 2, the reason on stderr, nothing on stdout', () => {
    const claude = runCheck(claudePreToolUse(BLOCKED_COMMAND), home);
    expect(claude.error).toBeUndefined();
    expect(claude.status).toBe(2);
    const claudeReason = (JSON.parse(claude.stdout) as { reason: string }).reason;

    const r = runCheck(codexPreToolUse(BLOCKED_COMMAND), home);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    // The same negotiation message Claude Code gets, as plain text.
    expect(r.stderr).toBe(claudeReason + '\n');
    expect(r.stderr).toContain('Force push blocked by policy');
    expect(r.stderr).not.toMatch(ANSI);
    expect(codexPreToolUseBlockReason(r)).toBe(claudeReason.trim());
  });

  it('Codex block on an unrecognised payload (tool name missing) has the same shape', () => {
    const r = runCheck({ ...codexPreToolUse(BLOCKED_COMMAND), tool_name: '' }, home);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('tool name missing');
    expect(r.stderr).not.toMatch(ANSI);
    expect(codexPreToolUseBlockReason(r)).toBe(r.stderr.trim());
  });

  it('Codex UserPromptSubmit DLP block: exit 2, the reason on stderr, no secret anywhere', () => {
    const fakeAwsKey = 'AKIA' + 'QWERTYASDFGHJKLM'; // composed so this file never trips DLP
    const r = runCheck(
      {
        session_id: 's1',
        turn_id: 't1',
        transcript_path: null,
        cwd: os.tmpdir(),
        hook_event_name: 'UserPromptSubmit',
        model: 'gpt-6-astra',
        permission_mode: 'default',
        prompt: `help me debug: aws_access_key_id=${fakeAwsKey}`,
      },
      home
    );
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toMatch(
      /^🚨 Node9 DLP: .+ detected in prompt \(.+\)\. Prompt was not submitted/
    );
    expect(r.stderr.endsWith('\n')).toBe(true);
    expect(r.stderr.split('\n').length).toBe(2); // one line, then the newline
    expect(r.stderr).not.toContain(fakeAwsKey);
    expect(r.stderr).not.toMatch(ANSI);
    expect(codexPromptBlockReason(r)).toBe(r.stderr.trim());
  });

  it('Codex review with no approver ends in a block on stderr (approval timeout path)', () => {
    fs.writeFileSync(
      path.join(home, '.node9', 'config.json'),
      JSON.stringify({
        settings: {
          mode: 'standard',
          autoStartDaemon: false,
          approvalTimeoutMs: 0,
          approvers: { native: false, browser: false, cloud: false, terminal: false },
          reviewChannel: 'approver',
        },
        policy: { dangerousWords: ['mkfs'] },
      })
    );
    const r = runCheck(codexPreToolUse('mkfs.ext4 /dev/sda'), home);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr.trim()).not.toBe('');
    expect(r.stderr).not.toMatch(ANSI);
    expect(codexPreToolUseBlockReason(r)).toBe(r.stderr.trim());
  });

  it('Claude Code block is unchanged: exit 2, JSON on stdout, empty stderr', () => {
    const r = runCheck(claudePreToolUse(BLOCKED_COMMAND), home);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(2);
    expect(r.stderr).toBe('');
    const out = JSON.parse(r.stdout) as {
      decision: string;
      reason: string;
      hookSpecificOutput: Record<string, string>;
    };
    expect(out.decision).toBe('block');
    expect(out.reason).toContain('Force push blocked by policy');
    expect(out.hookSpecificOutput).toEqual({
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: out.reason,
    });
  });

  it('GitHub Copilot block is unchanged: exit 0, flat deny on stdout, empty stderr', () => {
    const r = runCheck(claudePreToolUse(BLOCKED_COMMAND), home, ['--agent', 'copilot']);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
    const out = JSON.parse(r.stdout) as Record<string, string>;
    expect(Object.keys(out).sort()).toEqual(['permissionDecision', 'permissionDecisionReason']);
    expect(out.permissionDecision).toBe('deny');
    expect(out.permissionDecisionReason).toContain('Force push blocked by policy');
  });

  it('Codex allowed call: exit 0, nothing on stdout or stderr', () => {
    const r = runCheck(codexPreToolUse('ls /tmp'), home);
    expect(r.error).toBeUndefined();
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
    expect(r.stderr).toBe('');
    expect(codexPreToolUseBlockReason(r)).toBeNull();
  });
});
