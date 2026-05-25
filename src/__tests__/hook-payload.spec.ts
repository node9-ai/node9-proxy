// src/__tests__/hook-payload.spec.ts
// Unit tests for utils/hook-payload.ts
import { describe, it, expect } from 'vitest';
import { extractToolName, extractToolInput, canonicalToolName } from '../utils/hook-payload.js';

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
});
