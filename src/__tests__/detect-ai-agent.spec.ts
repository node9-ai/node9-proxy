// Unit tests for detectAiAgent — pure function over (payload, process.env).
// Source of truth for the SaaS Report's "AI Agents" breakdown.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { detectAiAgent } from '../cli/commands/check';

const ENV_KEYS = [
  'CLAUDECODE',
  'CLAUDE_CODE_SESSION_ID',
  'GEMINI_API_KEY',
  'GEMINI_CLI_VERSION',
  'CURSOR_TRACE_ID',
  'CURSOR_SESSION_ID',
  'AIDER_VERSION',
] as const;

describe('detectAiAgent', () => {
  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    // Snapshot then clear all detection-related env vars so a stale local
    // shell doesn't leak into test results. Restored in afterEach.
    saved = {};
    for (const k of ENV_KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  // ── Layer 0: explicit meta.agent tag (set by node9-authored shims) ────
  // Plugins for Opencode / Pi / any future agent ship with the node9
  // CLI. They tag payloads with meta.agent so detectAiAgent doesn't
  // need a per-agent fingerprint branch. Layer-0 because it has to
  // take precedence over the Claude/Codex/Gemini payload fingerprints
  // (an Opencode hook still carries hook_event_name: "PreToolUse" and
  // would otherwise be misattributed to Claude Code).

  it('detects Opencode from meta.agent tag', () => {
    expect(detectAiAgent({ hook_event_name: 'PreToolUse', meta: { agent: 'Opencode' } })).toBe(
      'Opencode'
    );
  });

  it('meta.agent takes precedence over hook_event_name fingerprint', () => {
    // Without the Layer-0 branch, hook_event_name: "PreToolUse" would
    // route to "Claude Code" by Layer-1 — the most common
    // misattribution we want to prevent.
    expect(detectAiAgent({ hook_event_name: 'PreToolUse', meta: { agent: 'Pi' } })).toBe('Pi');
  });

  it('meta.agent takes precedence over env vars', () => {
    process.env.CLAUDECODE = '1';
    expect(detectAiAgent({ meta: { agent: 'Opencode' } })).toBe('Opencode');
  });

  it('ignores meta.agent if not a non-empty string', () => {
    // Defensive: a malformed payload with meta.agent: null or "" should
    // fall through to existing detection rather than return a bogus
    // empty-string agent name.
    expect(detectAiAgent({ hook_event_name: 'PreToolUse', meta: { agent: '' } })).toBe(
      'Claude Code'
    );
    expect(
      detectAiAgent({ hook_event_name: 'PreToolUse', meta: { agent: null as unknown as string } })
    ).toBe('Claude Code');
  });

  // ── Layer 1: payload fingerprint ────────────────────────────────────

  it('detects Claude Code from PreToolUse hook event', () => {
    expect(detectAiAgent({ hook_event_name: 'PreToolUse' })).toBe('Claude Code');
  });

  it('detects Claude Code from tool_use_id', () => {
    expect(detectAiAgent({ tool_use_id: 'toolu_abc123' })).toBe('Claude Code');
  });

  it('detects Claude Code from permission_mode', () => {
    expect(detectAiAgent({ permission_mode: 'default' })).toBe('Claude Code');
  });

  it('detects Codex from turn_id field (Codex-only payload extension)', () => {
    // turn_id is a Codex-specific schema extension per openai/codex
    // pre-tool-use.command.input.schema.json — described as "Codex extension:
    // expose the active turn id to internal turn-scoped hooks."
    expect(detectAiAgent({ turn_id: '019e352f-4df0-7902-b156-0d71433c5a6e' })).toBe('Codex');
  });

  it('detects Codex from a real captured PreToolUse payload', () => {
    // Captured during issue #178 verification from codex-cli 0.130.0 —
    // shape is Claude-compatible PLUS turn_id + model fields.
    expect(
      detectAiAgent({
        session_id: '019e34c4-02f7-7002-8384-6e54b99f5bc5',
        turn_id: '019e352f-4df0-7902-b156-0d71433c5a6e',
        transcript_path:
          '/home/nadav/.codex/sessions/2026/05/17/rollout-2026-05-17T10-08-41-019e34c4-02f7-7002-8384-6e54b99f5bc5.jsonl',
        cwd: '/home/nadav/node9',
        hook_event_name: 'PreToolUse',
        model: 'gpt-5.4',
        permission_mode: 'default',
        tool_name: 'Bash',
        tool_input: { command: 'ls /tmp' },
        tool_use_id: 'call_fEKINAMZxjMuJbczLPxtBwTF',
      })
    ).toBe('Codex');
  });

  it('Codex turn_id takes precedence over Claude-style PreToolUse fingerprint', () => {
    // Codex's payload always has hook_event_name === 'PreToolUse' (same as
    // Claude), so without turn_id check it would misattribute as Claude Code.
    expect(detectAiAgent({ hook_event_name: 'PreToolUse', turn_id: 't_xyz' })).toBe('Codex');
  });

  it('detects Gemini CLI from BeforeTool hook event', () => {
    expect(detectAiAgent({ hook_event_name: 'BeforeTool' })).toBe('Gemini CLI');
  });

  it('detects Gemini CLI from timestamp field', () => {
    expect(detectAiAgent({ timestamp: '2026-05-03T12:00:00Z' })).toBe('Gemini CLI');
  });

  it('payload fingerprint takes precedence over env vars', () => {
    process.env.CURSOR_TRACE_ID = 'cursor_xyz';
    // Payload says Claude Code; env says Cursor — fingerprint wins.
    expect(detectAiAgent({ hook_event_name: 'PreToolUse' })).toBe('Claude Code');
  });

  // ── Layer 2: env-var fallback ───────────────────────────────────────

  it('detects Claude Code via CLAUDECODE env var', () => {
    process.env.CLAUDECODE = '1';
    expect(detectAiAgent({})).toBe('Claude Code');
  });

  it('detects Claude Code via CLAUDE_CODE_SESSION_ID env var', () => {
    process.env.CLAUDE_CODE_SESSION_ID = 'sess_abc';
    expect(detectAiAgent({})).toBe('Claude Code');
  });

  it('detects Gemini CLI via GEMINI_CLI_VERSION env var', () => {
    process.env.GEMINI_CLI_VERSION = '1.0.0';
    expect(detectAiAgent({})).toBe('Gemini CLI');
  });

  it('detects Cursor via CURSOR_TRACE_ID env var', () => {
    process.env.CURSOR_TRACE_ID = 'cursor_xyz';
    expect(detectAiAgent({})).toBe('Cursor');
  });

  it('detects Aider via AIDER_VERSION env var', () => {
    process.env.AIDER_VERSION = '0.50.1';
    expect(detectAiAgent({})).toBe('Aider');
  });

  it('Claude Code env-vars take priority over Gemini env-vars (most-specific first)', () => {
    process.env.CLAUDECODE = '1';
    process.env.GEMINI_API_KEY = 'gem_abc';
    expect(detectAiAgent({})).toBe('Claude Code');
  });

  // ── Layer 3: fallback ───────────────────────────────────────────────

  it('returns Unknown Agent when payload has tool_name but no AI hint', () => {
    expect(detectAiAgent({ tool_name: 'Bash' })).toBe('Unknown Agent');
  });

  it('returns Unknown Agent when payload has name but no AI hint', () => {
    expect(detectAiAgent({ name: 'Bash' })).toBe('Unknown Agent');
  });

  it('returns Terminal for an empty payload with no env-var hints', () => {
    expect(detectAiAgent({})).toBe('Terminal');
  });
});
