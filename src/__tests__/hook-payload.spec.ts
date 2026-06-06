// src/__tests__/hook-payload.spec.ts
// Unit tests for utils/hook-payload.ts
import { describe, it, expect } from 'vitest';
import {
  extractToolName,
  extractToolInput,
  canonicalToolName,
  canonicalToolInput,
  agentLabelFromFlag,
} from '../utils/hook-payload.js';

// Real PreToolUse payload captured from agy 1.0.6 via spy hook
// (doc/roadmap/antigravity-target.md §0.3) — tool name/args nested
// under toolCall, shell arg as PascalCase CommandLine.
const AGY_PRE_PAYLOAD = {
  artifactDirectoryPath:
    '/home/nadav/.gemini/antigravity-cli/brain/6c322973-64a8-41da-b2e9-06c217bb69a1',
  conversationId: '6c322973-64a8-41da-b2e9-06c217bb69a1',
  stepIdx: 3,
  toolCall: {
    args: {
      CommandLine: 'echo hello-node9',
      Cwd: '/tmp/agy-hooktest',
      WaitMsBeforeAsync: 2000,
    },
    name: 'run_command',
  },
  transcriptPath:
    '/home/nadav/.gemini/antigravity-cli/brain/6c322973-64a8-41da-b2e9-06c217bb69a1/.system_generated/logs/transcript_full.jsonl',
  workspacePaths: ['/tmp/agy-hooktest'],
};

describe('extractToolName', () => {
  it('returns tool_name when present (Claude shape)', () => {
    expect(extractToolName({ tool_name: 'Bash' })).toBe('Bash');
  });

  it('returns name when only Gemini shape is present', () => {
    expect(extractToolName({ name: 'run_shell_command' })).toBe('run_shell_command');
  });

  it('prefers tool_name over name when both are present', () => {
    expect(extractToolName({ tool_name: 'Bash', name: 'should_not_win' })).toBe('Bash');
  });

  it('returns empty string by default when no field is present', () => {
    expect(extractToolName({})).toBe('');
  });

  it('returns supplied defaultValue when no field is present', () => {
    expect(extractToolName({}, 'unknown')).toBe('unknown');
  });

  it('treats explicit empty string as the value (not as missing)', () => {
    // tool_name is set, just empty — `??` only triggers on null/undefined,
    // so the empty string wins over the default. Matches the existing
    // inline pattern in check.ts and log.ts pre-refactor.
    expect(extractToolName({ tool_name: '' }, 'fallback')).toBe('');
  });

  it('falls back across null tool_name to name', () => {
    // Defensive: typed as undefined, but real-world payloads occasionally
    // serialise `null`. `??` handles both.
    const payload = { tool_name: null as unknown as undefined, name: 'gemini_tool' };
    expect(extractToolName(payload)).toBe('gemini_tool');
  });

  // ── Antigravity (agy) dialect ─────────────────────────────────────────
  it('returns toolCall.name for an Antigravity payload', () => {
    expect(extractToolName(AGY_PRE_PAYLOAD)).toBe('run_command');
  });

  it('returns defaultValue for Antigravity toolCall: null (non-tool PostToolUse step)', () => {
    expect(extractToolName({ toolCall: null }, 'unknown')).toBe('unknown');
  });

  it('prefers tool_name over toolCall.name when both are present', () => {
    expect(extractToolName({ tool_name: 'Bash', toolCall: { name: 'should_not_win' } })).toBe(
      'Bash'
    );
  });
});

describe('extractToolInput', () => {
  it('returns tool_input when present (Claude shape)', () => {
    expect(extractToolInput({ tool_input: { command: 'ls' } })).toEqual({ command: 'ls' });
  });

  it('returns args when only Gemini shape is present', () => {
    expect(extractToolInput({ args: { command: 'ls' } })).toEqual({ command: 'ls' });
  });

  it('prefers tool_input over args when both are present', () => {
    expect(extractToolInput({ tool_input: { winner: true }, args: { winner: false } })).toEqual({
      winner: true,
    });
  });

  it('returns empty object when no field is present', () => {
    expect(extractToolInput({})).toEqual({});
  });

  it('preserves non-object input values verbatim (no type coercion)', () => {
    // tool_input is `unknown` — callers handle non-object cases themselves.
    expect(extractToolInput({ tool_input: 'a string' })).toBe('a string');
    expect(extractToolInput({ tool_input: 42 })).toBe(42);
    expect(extractToolInput({ tool_input: null })).toEqual({});
  });

  // ── Antigravity (agy) dialect ─────────────────────────────────────────
  it('returns toolCall.args for an Antigravity payload', () => {
    expect(extractToolInput(AGY_PRE_PAYLOAD)).toEqual({
      CommandLine: 'echo hello-node9',
      Cwd: '/tmp/agy-hooktest',
      WaitMsBeforeAsync: 2000,
    });
  });

  it('returns empty object for Antigravity toolCall: null', () => {
    expect(extractToolInput({ toolCall: null })).toEqual({});
  });
});

describe('canonicalToolName', () => {
  // Hermes Agent tool names → Claude vocabulary.
  it('maps terminal → Bash (Hermes shell tool)', () => {
    expect(canonicalToolName('terminal')).toBe('Bash');
  });

  it('maps write_file → Write', () => {
    expect(canonicalToolName('write_file')).toBe('Write');
  });

  it('maps patch → Edit', () => {
    expect(canonicalToolName('patch')).toBe('Edit');
  });

  it('maps read_file → Read', () => {
    expect(canonicalToolName('read_file')).toBe('Read');
  });

  it('maps search_files → Grep', () => {
    expect(canonicalToolName('search_files')).toBe('Grep');
  });

  // Pass-through cases — anything not in the alias table stays as-is.
  it('passes Claude-canonical names through unchanged', () => {
    expect(canonicalToolName('Bash')).toBe('Bash');
    expect(canonicalToolName('Write')).toBe('Write');
    expect(canonicalToolName('Edit')).toBe('Edit');
    expect(canonicalToolName('Read')).toBe('Read');
  });

  it('passes MCP tool names through unchanged', () => {
    expect(canonicalToolName('mcp__filesystem__read')).toBe('mcp__filesystem__read');
  });

  it('passes Hermes-specific tools (no Claude equivalent) through unchanged', () => {
    // delegate_task, execute_code, vision_analyze etc. have no Claude
    // counterpart — they should stay grep-able under their original names.
    expect(canonicalToolName('delegate_task')).toBe('delegate_task');
    expect(canonicalToolName('execute_code')).toBe('execute_code');
    expect(canonicalToolName('vision_analyze')).toBe('vision_analyze');
  });

  it('passes browser_* tools through unchanged', () => {
    expect(canonicalToolName('browser_click')).toBe('browser_click');
    expect(canonicalToolName('browser_navigate')).toBe('browser_navigate');
  });

  it('passes empty string through unchanged', () => {
    expect(canonicalToolName('')).toBe('');
  });

  it('is case-sensitive — TERMINAL does not map to Bash', () => {
    // Hermes always emits lowercase per agent/shell_hooks.py; an
    // upper-case variant means a different (non-Hermes) source we
    // don't want to silently rewrite.
    expect(canonicalToolName('TERMINAL')).toBe('TERMINAL');
    expect(canonicalToolName('Terminal')).toBe('Terminal');
  });

  it('maps run_command → Bash (Antigravity shell tool)', () => {
    expect(canonicalToolName('run_command')).toBe('Bash');
  });

  it('does not map Gemini run_shell_command (kept on its legacy allowlist path)', () => {
    // run_shell_command predates canonicalToolName and is special-cased
    // at orchestrator.ts / daemon/state.ts / config toolInspection —
    // mapping it here would change the audit log's agentToolName rows
    // for existing Gemini users.
    expect(canonicalToolName('run_shell_command')).toBe('run_shell_command');
  });
});

describe('canonicalToolInput', () => {
  it('maps agy run_command CommandLine/Cwd → command/cwd', () => {
    expect(canonicalToolInput('run_command', AGY_PRE_PAYLOAD.toolCall.args)).toEqual({
      command: 'echo hello-node9',
      cwd: '/tmp/agy-hooktest',
      WaitMsBeforeAsync: 2000,
    });
  });

  it('omits cwd when Cwd is absent or empty', () => {
    expect(canonicalToolInput('run_command', { CommandLine: 'ls' })).toEqual({ command: 'ls' });
    expect(canonicalToolInput('run_command', { CommandLine: 'ls', Cwd: '' })).toEqual({
      command: 'ls',
    });
  });

  it('passes run_command input through unchanged when CommandLine is missing', () => {
    // Defensive: a future agy version could rename the field; better to
    // pass the original shape through than emit { command: undefined }.
    const input = { Script: 'ls' };
    expect(canonicalToolInput('run_command', input)).toBe(input);
  });

  it('passes non-run_command tools through unchanged', () => {
    const input = { CommandLine: 'should stay' };
    expect(canonicalToolInput('Bash', input)).toBe(input);
    expect(canonicalToolInput('write_file', input)).toBe(input);
  });

  it('passes non-object inputs through unchanged', () => {
    expect(canonicalToolInput('run_command', 'a string')).toBe('a string');
    expect(canonicalToolInput('run_command', null)).toBe(null);
    expect(canonicalToolInput('run_command', [1, 2])).toEqual([1, 2]);
  });
});

describe('agentLabelFromFlag', () => {
  it('maps antigravity (any case) and agy alias to Antigravity', () => {
    expect(agentLabelFromFlag('antigravity')).toBe('Antigravity');
    expect(agentLabelFromFlag('Antigravity')).toBe('Antigravity');
    expect(agentLabelFromFlag('agy')).toBe('Antigravity');
  });

  it('maps copilot (any case) to GitHub Copilot', () => {
    // Essential, not cosmetic: Copilot CLI's PascalCase payload is
    // byte-identical to Claude Code, so the flag is the only reliable
    // attribution signal.
    expect(agentLabelFromFlag('copilot')).toBe('GitHub Copilot');
    expect(agentLabelFromFlag('Copilot')).toBe('GitHub Copilot');
  });

  it('ignores unknown or non-string values (falls back to fingerprinting)', () => {
    // The label selects block-response shapes, so arbitrary strings must
    // not be trusted verbatim.
    expect(agentLabelFromFlag('claude')).toBeUndefined();
    expect(agentLabelFromFlag('')).toBeUndefined();
    expect(agentLabelFromFlag(undefined)).toBeUndefined();
    expect(agentLabelFromFlag(42)).toBeUndefined();
  });
});
