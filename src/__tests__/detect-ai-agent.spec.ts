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
